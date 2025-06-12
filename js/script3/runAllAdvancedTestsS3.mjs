// js/script3/runAllAdvancedTestsS3.mjs
// ATUALIZADO PARA EXECUTAR A TENTATIVA DE UAF ASSÍNCRONO

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3 } from '../dom_elements.mjs';

// --- IMPORTAÇÃO ATUALIZADA ---
import { runAdvancedUAF_Attempts } from './testAdvancedPP.mjs';

/**
 * Orquestrador principal do Script 3, focado na tentativa de UAF.
 */
export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = 'Async_UAF_Runner';
    const runBtn = getRunBtnAdvancedS3();
    
    if (runBtn) {
        runBtn.disabled = true;
    }

    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}) ====`, 'test', FNAME_ORCHESTRATOR);
    logS3('Foco: Tentativa de Use-After-Free (UAF) Assíncrono com Hijack de "call"', 'info', FNAME_ORCHESTRATOR);
    logS3('AVISO: Este teste é o mais propenso a causar um CRASH. Monitore o navegador.', 'critical', FNAME_ORCHESTRATOR);

    await PAUSE_S3(2000); // Pausa para o usuário ler os avisos

    try {
        await runAdvancedUAF_Attempts();

    } catch (error) {
        logS3(`ERRO CRÍTICO no orquestrador: ${error.message}`, 'critical', FNAME_ORCHESTRATOR);
        console.error("Erro capturado pelo orquestrador S3:", error);
    } finally {
        await PAUSE_S3(500);
        
        logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
        logS3(`Se não houve crash, o GC do navegador é muito eficiente ou o padrão de acesso não foi o ideal.`, 'info', FNAME_ORCHESTRATOR);
        
        if (runBtn) {
            runBtn.disabled = false;
        }
    }
}
