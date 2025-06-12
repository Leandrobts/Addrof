// js/script3/runAllAdvancedTestsS3.mjs
// VERSÃO CORRIGIDA - Ajustado para importar o script de teste da mesma pasta.

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3 } from '../dom_elements.mjs';

// --- IMPORTAÇÃO CORRIGIDA ---
// Usa './' para importar da mesma pasta, pois agora 'testAdvancedPP.mjs'
// está localizado em 'js/script3/'.
import { testAdvancedPPS2 } from './testAdvancedPP.mjs';


/**
 * Orquestrador principal do Script 3, focado em executar o teste
 * de Prototype Pollution Avançado.
 */
export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = 'AdvancedPP_Runner_v2';
    const runBtn = getRunBtnAdvancedS3();
    
    if (runBtn) {
        runBtn.disabled = true;
    }

    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}) ====`, 'test', FNAME_ORCHESTRATOR);
    logS3(`Foco: Teste de Prototype Pollution Avançado ('./testAdvancedPP.mjs')`, 'info', FNAME_ORCHESTRATOR);

    await PAUSE_S3(250);

    try {
        // --- CHAMADA DA FUNÇÃO ---
        // A função importada do arquivo local será executada.
        logS3('Invocando testAdvancedPPS2...', 'info', FNAME_ORCHESTRATOR);
        await testAdvancedPPS2();
        logS3('Execução de testAdvancedPPS2 concluída.', 'good', FNAME_ORCHESTRATOR);

    } catch (error) {
        // Bloco de captura de erro para diagnosticar problemas na inicialização ou execução.
        logS3(`ERRO CRÍTICO no orquestrador ao executar o teste: ${error.message}`, 'critical', FNAME_ORCHESTRATOR);
        console.error("Erro capturado pelo orquestrador S3:", error);
    } finally {
        await PAUSE_S3(500);
        
        logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
        
        if (runBtn) {
            runBtn.disabled = false;
        }
    }
}
