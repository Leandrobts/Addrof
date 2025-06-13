// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para Revisão 60 - Chamador de Diagnóstico)
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3 } from '../dom_elements.mjs';

import {
    FNAME_MODULE,
    runDiagnosticExploitChain
} from './UltimateExploit.mjs';

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE}_MainOrchestrator`;
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = true;

    // Executa a nova cadeia de diagnóstico
    const result = await runDiagnosticExploitChain();

    if (result && result.success) {
        logS3(`  RUNNER: DIAGNÓSTICO BEM-SUCEDIDO!`, "vuln", FNAME_ORCHESTRATOR);
        logS3(`  RUNNER: Mensagem Final: ${result.message}`, "good", FNAME_ORCHESTRATOR);
    } else {
        const errorMsg = result ? result.message : "Resultado indefinido do exploit.";
        logS3(`  RUNNER: DIAGNÓSTICO FALHOU: ${errorMsg}`, "critical", FNAME_ORCHESTRATOR);
    }

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;
}
