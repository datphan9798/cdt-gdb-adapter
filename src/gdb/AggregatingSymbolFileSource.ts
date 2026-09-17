import { logger } from '@vscode/debugadapter';
import { SymbolSource, SymbolReader } from '../types/session';

export class AggregatingSymbolFileSource implements SymbolSource {
    private readonly parsedByFile = new Map<
        string,
        Promise<Map<string, string[]>>
    >();
    private readonly loadedFilesByInferior = new Map<number, Set<string>>();
    private readonly inferiorsByFile = new Map<string, Set<number>>();

    constructor(private readonly symbolReader: SymbolReader) {}

    async notifySymbolFileLoaded(
        inferiorId: number,
        filePath: string
    ): Promise<void> {
        const loadedFiles =
            this.loadedFilesByInferior.get(inferiorId) ?? new Set<string>();
        this.loadedFilesByInferior.set(inferiorId, loadedFiles);
        const alreadyLoadedByThisInferior = loadedFiles.has(filePath);

        const needsParse =
            !this.parsedByFile.has(filePath) || alreadyLoadedByThisInferior;
        if (needsParse) {
            const parsePromise =
                this.symbolReader.readGlobalVariablesByFile(filePath);
            parsePromise.catch((error) => {
                logger.verbose(
                    `Failed to read global symbols from ${filePath}.`
                );
            });
            this.parsedByFile.set(filePath, parsePromise);
        }

        loadedFiles.add(filePath);
        this.loadedFilesByInferior.set(inferiorId, loadedFiles);

        const dependents =
            this.inferiorsByFile.get(filePath) ?? new Set<number>();
        dependents.add(inferiorId);
        this.inferiorsByFile.set(filePath, dependents);

        await this.parsedByFile.get(filePath);
    }

    private toDisplayPath(
        symbolFilePath: string,
        absolutePath: string
    ): string {
        const normalize = (value: string) => value.replace(/\\/g, '/');
        const symbolNorm = normalize(symbolFilePath);
        const targetNorm = normalize(absolutePath);

        const isWindowsStyle =
            /^[A-Za-z]:\//.test(symbolNorm) || /^[A-Za-z]:\//.test(targetNorm);

        const symbolParts = symbolNorm.split('/').filter(Boolean);
        const rootParts = symbolParts.slice(0, -1);
        const targetParts = targetNorm.split('/').filter(Boolean);

        const segmentsEqual = (a: string, b: string) =>
            isWindowsStyle ? a.toLowerCase() === b.toLowerCase() : a === b;

        let sharedLength = 0;
        while (
            sharedLength < rootParts.length &&
            sharedLength < targetParts.length &&
            segmentsEqual(rootParts[sharedLength], targetParts[sharedLength])
        ) {
            sharedLength++;
        }

        // No shared ancestor at all: fall back to the absolute path rather
        // than emitting a deeply-nested "../../.." chain.
        if (sharedLength === 0) {
            return targetNorm;
        }

        const upSegments = new Array(rootParts.length - sharedLength).fill(
            '..'
        );
        const downSegments = targetParts.slice(sharedLength);
        const relativePath = [...upSegments, ...downSegments].join('/');
        return upSegments.length === 0 ? `./${relativePath}` : relativePath;
    }

    async getGlobalVariablesByFile(
        inferiorId: number
    ): Promise<Map<string, string[]>> {
        const merged = new Map<string, string[]>();
        const loadedFiles = this.loadedFilesByInferior.get(inferiorId);
        for (const filePath of loadedFiles ?? []) {
            const parsePromise = this.parsedByFile.get(filePath);
            if (!parsePromise) {
                continue;
            }
            let parsed: Map<string, string[]>;
            try {
                parsed = await parsePromise;
            } catch {
                continue;
            }
            for (const [sourceFile, names] of parsed) {
                const displayFile = this.toDisplayPath(filePath, sourceFile);
                const existing = merged.get(displayFile) ?? [];
                merged.set(displayFile, [...new Set([...existing, ...names])]);
            }
        }
        const sortedEntries = [...merged.entries()].sort(([a], [b]) =>
            a.toLowerCase().localeCompare(b.toLowerCase())
        );
        return new Map(sortedEntries);
    }

    clear(inferiorId: number): void {
        const loadedFiles = this.loadedFilesByInferior.get(inferiorId);
        if (loadedFiles && loadedFiles.size > 0) {
            for (const filePath of loadedFiles) {
                const dependents = this.inferiorsByFile.get(filePath);
                if (!dependents) {
                    continue;
                }
                dependents.delete(inferiorId);
                if (dependents.size === 0) {
                    this.parsedByFile.delete(filePath);
                    this.inferiorsByFile.delete(filePath);
                } else {
                    this.inferiorsByFile.set(filePath, dependents);
                }
            }
        }
        this.loadedFilesByInferior.delete(inferiorId);
    }
}
