// js/script3/runAllAdvancedTestsS3.mjs
// ATUALIZADO PARA EXECUTAR O "CALDEIRÃO" DE UAF

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3 } from '../dom_elements.mjs';

// --- IMPORTAÇÃO ATUALIZADA ---
import { runChaoticUAFCauldron } from './testAdvancedPP.mjs';

/**
 * Orquestrador principal do Script 3, focado na tentativa de UAF via "Caldeirão".
 */
export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = 'UAF_Cauldron_Runner';
    const runBtn = getRunBtnAdvancedS3();
    
    if (runBtn) {
        runBtn.disabled = true;
    }

    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}) ====`, 'test', FNAME_ORCHESTRATOR);
    logS3('Foco: Tentativa de UAF no MODO CAOS. Espere instabilidade severa.', 'critical', FNAME_ORCHESTRATOR);
    logS3('O teste rodará por ~20 segundos e tentará ativamente travar o navegador.', 'warn', FNAME_ORCHESTRATOR);

    await PAUSE_S3(3000); // Pausa longa para o usuário ler os avisos

    try {
        await runChaoticUAFCauldron();

    } catch (error) {
        logS3(`ERRO CRÍTICO no orquestrador: ${error.message}`, 'critical', FNAME_ORCHESTRATOR);
        console.error("Erro capturado pelo orquestrador S3:", error);
    } finally {
        await PAUSE_S3(500);
        
        logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
        logS3(`Se o navegador sobreviveu, ele possui um GC e um motor JS extremamente resilientes.`, 'good', FNAME_ORCHESTRATOR);
        
        if (runBtn) {
            runBtn.disabled = false;
        }
    }
}
