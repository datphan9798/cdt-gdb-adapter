import { SymbolReader } from '../types/session';
import { spawn } from 'node:child_process';
import * as readline from 'node:readline';
import * as path from 'node:path';

type ObjectFormat = 'elf' | 'coff';

interface GlobalVariableSymbol {
    address: bigint;
    name: string;
    section: string;
    sectionNumber?: number;
}

interface AddressLocation {
    file: string;
}

interface NmSymbol {
    address: bigint;
    name: string;
    file?: string;
}

interface CoffSectionContribution {
    file: string;
    sectionNumber: number;
    start: bigint;
    end: bigint;
}

interface ObjdumpResult {
    format: ObjectFormat;
    symbols: GlobalVariableSymbol[];
    contributions: CoffSectionContribution[];
}

export class GNUObjdumpSymbolReader implements SymbolReader {
    private static readonly COFF_SYMBOL_PATTERN =
        /^\[\s*\d+\]\s*\(sec\s+(-?\d+)\)\(fl\s+0x[0-9a-fA-F]+\)\(ty\s+(\d+)\)\(scl\s+(\d+)\)\s+\(nx\s+\d+\)\s+0x([0-9a-fA-F]+)\s+(.+)$/;

    private static readonly COFF_FILE_PATTERN =
        /^\[\s*\d+\]\s*\(sec\s+-2\)\(fl\s+0x[0-9a-fA-F]+\)\(ty\s+0\)\(scl\s+103\)\s+\(nx\s+\d+\)\s+0x[0-9a-fA-F]+\s+(.+)$/;

    private static readonly COFF_SECTION_PATTERN =
        /^\[\s*\d+\]\s*\(sec\s+(\d+)\)\(fl\s+0x[0-9a-fA-F]+\)\(ty\s+0\)\(scl\s+3\)\s+\(nx\s+1\)\s+0x([0-9a-fA-F]+)\s+(\.\S+)$/;

    private static readonly COFF_SECTION_LENGTH_PATTERN =
        /^AUX\s+scnlen\s+0x([0-9a-fA-F]+)/;

    protected objdumpPath: string;
    protected nmPath: string;

    constructor(objdumpPath: string) {
        this.objdumpPath = objdumpPath;
        this.nmPath = this.deriveNmPath(objdumpPath);
    }

    async readGlobalVariablesByFile(
        symbolFile: string
    ): Promise<Map<string, string[]>> {
        const [objdumpResult, nmSymbols] = await Promise.all([
            this.readGlobalObjectSymbols(symbolFile),
            this.readNmSymbols(symbolFile),
        ]);

        return objdumpResult.format === 'coff'
            ? this.groupCoffSymbolsByFile(
                  objdumpResult.symbols,
                  nmSymbols,
                  objdumpResult.contributions
              )
            : this.groupElfSymbolsByFile(objdumpResult.symbols, nmSymbols);
    }

    private deriveNmPath(objdumpPath: string): string {
        const dir = path.dirname(objdumpPath);
        const ext = path.extname(objdumpPath);
        const base = path.basename(objdumpPath, ext);
        const lower = base.toLowerCase();
        const index = lower.lastIndexOf('objdump');
        const replacedBase =
            index >= 0
                ? base.slice(0, index) +
                  'nm' +
                  base.slice(index + 'objdump'.length)
                : 'nm';
        return path.join(dir, `${replacedBase}${ext}`);
    }

    private async readGlobalObjectSymbols(
        symbolFile: string
    ): Promise<ObjdumpResult> {
        const lines: string[] = [];

        await this.streamToolLines(
            this.objdumpPath,
            ['-t', '-C', '--wide', symbolFile],
            'objdump',
            (line) => {
                lines.push(line);
            }
        );

        // Scan all objdump output first to determine ELF vs PE/COFF format.
        const format: ObjectFormat = lines.some((line) =>
            this.isCoffFormatLine(line)
        )
            ? 'coff'
            : 'elf';

        const symbols: GlobalVariableSymbol[] = [];
        for (const line of lines) {
            const symbol =
                format === 'coff'
                    ? this.parseCoffObjdumpSymbolLine(line)
                    : this.parseElfObjdumpSymbolLine(line);
            if (symbol && !this.isCompilerGeneratedSymbol(symbol.name)) {
                symbols.push(symbol);
            }
        }

        return {
            format,
            symbols,
            contributions:
                format === 'coff'
                    ? this.parseCoffSectionContributions(lines)
                    : [],
        };
    }

    private isCoffFormatLine(rawLine: string): boolean {
        return /\bfile format (?:pei?|pe)-/i.test(rawLine);
    }

    private parseElfObjdumpSymbolLine(
        rawLine: string
    ): GlobalVariableSymbol | undefined {
        /*
         * Examples:
         *   0000000000004038 g     O .bss   0000000000000004              global
         *   0000000000004010  w    O .data  0000000000000004              weak_global
         *   0000000000001129 g     F .text  0000000000000023              main
         */
        const addressMatch = rawLine.match(/^([0-9a-fA-F]+)\s/);
        if (!addressMatch) {
            return undefined;
        }

        const afterAddress = rawLine.slice(addressMatch[0].length);
        if (afterAddress.length < 7) {
            return undefined;
        }

        const flags = afterAddress.slice(0, 7);
        const remainder = afterAddress.slice(7).replace(/^\s+/, '');
        const columnsMatch = remainder.match(/^(\S+)\s+[0-9a-fA-F]+\s*(.*)$/);
        if (!columnsMatch) {
            return undefined;
        }

        const section = columnsMatch[1];
        const name = columnsMatch[2]
            .trim()
            .replace(/^\.(?:hidden|protected|internal)\s+/, '');
        if (!name) {
            return undefined;
        }

        const bind = flags[0];
        const type = flags[6];
        if (bind === 'l' || type !== 'O') {
            return undefined;
        }
        if (section === '*UND*' || section === '*ABS*') {
            return undefined;
        }

        const address = this.parseHexAddress(addressMatch[1]);
        return address === undefined ? undefined : { address, name, section };
    }

    private parseCoffObjdumpSymbolLine(
        rawLine: string
    ): GlobalVariableSymbol | undefined {
        /*
         * PE/COFF examples:
         *   [867](sec  2)(fl 0x00)(ty   0)(scl   2) (nx 0) 0x48 global_int
         *   [ 87](sec  1)(fl 0x00)(ty  20)(scl   2) (nx 1) 0x4d0 main
         *
         * Keep defined external data symbols. Functions use a non-zero type
         * (for example ty 20 in MinGW output) and are excluded.
         */
        const match = rawLine.match(GNUObjdumpSymbolReader.COFF_SYMBOL_PATTERN);
        if (!match) {
            return undefined;
        }

        const sectionNumber = Number.parseInt(match[1], 10);
        const type = Number.parseInt(match[2], 10);
        const storageClass = Number.parseInt(match[3], 10);
        const address = this.parseHexAddress(match[4]);
        const name = match[5].trim();

        if (
            sectionNumber <= 0 ||
            type !== 0 ||
            storageClass !== 2 ||
            address === undefined ||
            name.length === 0
        ) {
            return undefined;
        }

        return {
            address,
            name,
            section: `sec${sectionNumber}`,
            sectionNumber,
        };
    }

    private parseCoffSectionContributions(
        lines: readonly string[]
    ): CoffSectionContribution[] {
        const contributions: CoffSectionContribution[] = [];
        let currentFile: string | undefined;
        let pendingSection:
            | {
                  file: string;
                  sectionNumber: number;
                  start: bigint;
              }
            | undefined;

        for (const line of lines) {
            const fileMatch = line.match(
                GNUObjdumpSymbolReader.COFF_FILE_PATTERN
            );
            if (fileMatch) {
                currentFile = this.normalizePortablePath(fileMatch[1]);
                pendingSection = undefined;
                continue;
            }

            if (!currentFile) {
                continue;
            }

            const sectionMatch = line.match(
                GNUObjdumpSymbolReader.COFF_SECTION_PATTERN
            );
            if (sectionMatch) {
                const start = this.parseHexAddress(sectionMatch[2]);
                pendingSection =
                    start === undefined
                        ? undefined
                        : {
                              file: currentFile,
                              sectionNumber: Number.parseInt(
                                  sectionMatch[1],
                                  10
                              ),
                              start,
                          };
                continue;
            }

            if (!pendingSection) {
                continue;
            }

            const lengthMatch = line.match(
                GNUObjdumpSymbolReader.COFF_SECTION_LENGTH_PATTERN
            );
            if (!lengthMatch) {
                pendingSection = undefined;
                continue;
            }

            const length = this.parseHexAddress(lengthMatch[1]);
            if (length !== undefined && length > 0) {
                contributions.push({
                    file: pendingSection.file,
                    sectionNumber: pendingSection.sectionNumber,
                    start: pendingSection.start,
                    end: pendingSection.start + length,
                });
            }
            pendingSection = undefined;
        }

        return contributions;
    }

    private async readNmSymbols(symbolFile: string): Promise<NmSymbol[]> {
        const symbols: NmSymbol[] = [];
        await this.streamToolLines(
            this.nmPath,
            ['-l', '-C', '--defined-only', symbolFile],
            'nm',
            (line) => {
                const parsed = this.parseNmLine(line);
                if (parsed) {
                    symbols.push(parsed);
                }
            }
        );
        return symbols;
    }

    private parseNmLine(rawLine: string): NmSymbol | undefined {
        const tabIndex = rawLine.indexOf('\t');
        const symbolPart = tabIndex >= 0 ? rawLine.slice(0, tabIndex) : rawLine;
        const locationPart =
            tabIndex >= 0 ? rawLine.slice(tabIndex + 1).trim() : undefined;
        const symbolMatch = symbolPart.match(/^([0-9a-fA-F]+)\s+\S+\s+(.+)$/);
        if (!symbolMatch) {
            return undefined;
        }

        const address = this.parseHexAddress(symbolMatch[1]);
        const name = symbolMatch[2].trim();
        if (address === undefined || name.length === 0) {
            return undefined;
        }

        if (!locationPart) {
            return { address, name };
        }

        const fileLineMatch = locationPart.match(/^(.*):(\d+)$/);
        if (fileLineMatch) {
            return {
                address,
                name,
                file: this.normalizePortablePath(fileLineMatch[1]),
            };
        }

        return {
            address,
            name,
            file: this.normalizePortablePath(locationPart),
        };
    }

    private groupElfSymbolsByFile(
        symbols: GlobalVariableSymbol[],
        nmSymbols: readonly NmSymbol[]
    ): Map<string, string[]> {
        const locationsByAddress = new Map<bigint, AddressLocation>();
        for (const symbol of nmSymbols) {
            if (symbol.file) {
                locationsByAddress.set(symbol.address, {
                    file: symbol.file,
                });
            }
        }

        return this.groupSymbolsByFile(symbols, (symbol) =>
            locationsByAddress.get(symbol.address)
        );
    }

    private groupCoffSymbolsByFile(
        symbols: GlobalVariableSymbol[],
        nmSymbols: readonly NmSymbol[],
        contributions: readonly CoffSectionContribution[]
    ): Map<string, string[]> {
        const locationsByName = new Map<string, AddressLocation[]>();
        for (const symbol of nmSymbols) {
            if (!symbol.file) {
                continue;
            }
            const locations = locationsByName.get(symbol.name) ?? [];
            locations.push({ file: symbol.file });
            locationsByName.set(symbol.name, locations);
        }

        return this.groupSymbolsByFile(symbols, (symbol) => {
            const explicitLocations = locationsByName.get(symbol.name);
            if (explicitLocations?.length === 1) {
                return explicitLocations[0];
            }
            if (explicitLocations && explicitLocations.length > 1) {
                return undefined;
            }

            const contribution = this.findCoffContribution(
                symbol,
                contributions
            );
            if (!contribution) {
                return undefined;
            }

            return {
                file: this.resolveContributionFile(
                    contribution.file,
                    nmSymbols
                ),
            };
        });
    }

    private findCoffContribution(
        symbol: GlobalVariableSymbol,
        contributions: readonly CoffSectionContribution[]
    ): CoffSectionContribution | undefined {
        if (symbol.sectionNumber === undefined) {
            return undefined;
        }

        const matches = contributions.filter(
            (contribution) =>
                contribution.sectionNumber === symbol.sectionNumber &&
                symbol.address >= contribution.start &&
                symbol.address < contribution.end
        );

        return matches.length === 1 ? matches[0] : undefined;
    }

    private resolveContributionFile(
        contributionFile: string,
        nmSymbols: readonly NmSymbol[]
    ): string {
        const normalizedContribution =
            this.normalizePortablePath(contributionFile);
        const basename = path.posix.basename(normalizedContribution);
        const matchingFiles = new Set<string>();

        for (const symbol of nmSymbols) {
            if (symbol.file && path.posix.basename(symbol.file) === basename) {
                matchingFiles.add(symbol.file);
            }
        }

        return matchingFiles.size === 1
            ? [...matchingFiles][0]
            : normalizedContribution;
    }

    private groupSymbolsByFile(
        symbols: readonly GlobalVariableSymbol[],
        findLocation: (
            symbol: GlobalVariableSymbol
        ) => AddressLocation | undefined
    ): Map<string, string[]> {
        const namesByFile = new Map<string, Set<string>>();

        for (const symbol of symbols) {
            const location = findLocation(symbol);
            if (!location) {
                continue;
            }

            const names = namesByFile.get(location.file) ?? new Set<string>();
            names.add(symbol.name);
            namesByFile.set(location.file, names);
        }

        const sortedEntries = [...namesByFile.entries()].sort(([a], [b]) =>
            this.compareFilePaths(a, b)
        );
        return new Map(
            sortedEntries.map(([file, names]) => [file, [...names]])
        );
    }

    private async streamToolLines(
        toolPath: string,
        args: readonly string[],
        toolLabel: string,
        onLine: (line: string) => void
    ): Promise<void> {
        const child = spawn(toolPath, [...args], {
            windowsHide: true,
            shell: false,
            stdio: ['ignore', 'pipe', 'pipe'],
        });
        const stderrChunks: Buffer[] = [];
        child.stderr.on('data', (chunk: Buffer | string) => {
            stderrChunks.push(
                Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
            );
        });
        const closed = new Promise<{
            code: number | null;
            signal: NodeJS.Signals | null;
        }>((resolve, reject) => {
            child.once('error', (error) => {
                reject(
                    new Error(
                        `Failed to start ${toolLabel} '${toolPath}': ${error.message}`
                    )
                );
            });
            child.once('close', (code, signal) => {
                resolve({ code, signal });
            });
        });
        closed.catch(() => {
            // Handled below via `await closed`.
        });
        const rl = readline.createInterface({
            input: child.stdout,
            crlfDelay: Infinity,
        });
        try {
            for await (const line of rl) {
                onLine(line);
            }
        } finally {
            rl.close();
        }
        const { code, signal } = await closed;
        if (code !== 0) {
            const stderr = Buffer.concat(stderrChunks).toString('utf8').trim();
            const termination = signal
                ? `signal ${signal}`
                : `exit code ${String(code)}`;
            throw new Error(
                `${toolLabel} terminated with ${termination}.` +
                    (stderr ? `\n${stderr}` : '')
            );
        }
    }

    private parseHexAddress(value: string): bigint | undefined {
        try {
            return BigInt(`0x${value}`);
        } catch {
            return undefined;
        }
    }

    private normalizePortablePath(value: string): string {
        const normalized = this.removeSurroundingQuotes(value.trim()).replace(
            /\\/g,
            '/'
        );
        return path.posix.normalize(normalized);
    }

    private removeSurroundingQuotes(value: string): string {
        if (value.length < 2) {
            return value;
        }
        const first = value[0];
        const last = value[value.length - 1];
        if (
            (first === '"' && last === '"') ||
            (first === "'" && last === "'")
        ) {
            return value.slice(1, -1);
        }
        return value;
    }

    private isCompilerGeneratedSymbol(name: string): boolean {
        // Tuned to GNU objdump/nm output and may need extension for other compilers.
        return (
            name.includes('$$') ||
            /^__(?:preinit|init|fini)_array_(?:start|end)$/.test(name) ||
            name === '__Vectors' ||
            name === '__Vectors_End' ||
            name === '__Vectors_Size'
        );
    }

    private compareFilePaths(a: string, b: string): number {
        return a.toLowerCase().localeCompare(b.toLowerCase());
    }
}
