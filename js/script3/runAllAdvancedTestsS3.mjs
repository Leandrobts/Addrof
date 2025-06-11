// js/script3/runAllAdvancedTestsS3.mjs

import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3, getOutputAdvancedS3 } from '../dom_elements.mjs';
import {
    executeSpeculativeAddrofTest,
    FNAME_MODULE
} from './testSpeculativeAddrof.mjs';

/**
 * Executa a nova estratégia de Addrof Especulativo.
 */
async function runSpeculativeAddrofStrategy() {
    const FNAME_RUNNER = `${FNAME_MODULE}_Runner`;
    logS3(`==== INICIANDO Estratégia de Teste (${FNAME_MODULE}) ====`, 'test', FNAME_RUNNER);
    document.title = `Iniciando ${FNAME_MODULE}...`;

    let result;
    try {
        result = await executeSpeculativeAddrofTest();
    } catch (e) {
        logS3(`ERRO CRÍTICO IRRECUPERÁVEL durante a execução do teste: ${e.name} - ${e.message}`, "critical", FNAME_RUNNER);
        console.error("Erro capturado em runSpeculativeAddrofStrategy:", e);
        result = { success: false, message: `Erro fatal no runner: ${e.message}` };
    }

    logS3(`==== RESULTADO FINAL (${FNAME_MODULE}): ${result.message}`, result.success ? "vuln" : "error", FNAME_RUNNER);
    document.title = result.success ? `${FNAME_MODULE}: SUCESSO!` : `${FNAME_MODULE}: Falha`;
    logS3(`==== Estratégia de Teste (${FNAME_MODULE}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

/**
 * Função principal que inicializa e executa os testes.
 */
export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE}_MainOrchestrator`;
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`, 'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script (${FNAME_ORCHESTRATOR}) / Teste (${FNAME_MODULE}) ====`, 'test', FNAME_ORCHESTRATOR);

    await runSpeculativeAddrofStrategy();
    
    logS3(`\n==== Script (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;
}
