import { SymbolSource, SymbolProvider } from '../types/session';

export class GlobalSymbolProvider implements SymbolProvider {
    constructor(public readonly symbolSource: SymbolSource) {}

    async notifySymbolFileLoaded(
        inferiorId: number,
        filePath: string
    ): Promise<void> {
        return await this.symbolSource.notifySymbolFileLoaded(
            inferiorId,
            filePath
        );
    }

    async getSourceFiles(inferiorId: number): Promise<string[]> {
        return [
            ...(
                await this.symbolSource.getGlobalVariablesByFile(inferiorId)
            ).keys(),
        ];
    }

    async getSymbolNames(
        inferiorId: number,
        sourceFile: string
    ): Promise<string[] | undefined> {
        return (
            await this.symbolSource.getGlobalVariablesByFile(inferiorId)
        ).get(sourceFile);
    }

    clear(inferiorId: number): void {
        this.symbolSource.clear(inferiorId);
    }
}
