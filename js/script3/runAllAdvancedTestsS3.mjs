// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para chamar a verificação da cadeia completa)
import { logS3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { runFullChainVerification, FNAME_MODULE_UPDATED } from './testArrayBufferVictimCrash.mjs';

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_UPDATED}_MainOrchestrator`;
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    const result = await runFullChainVerification();
    
    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    
    if(result.success) {
        document.title = `${FNAME_MODULE_UPDATED}: FULL CHAIN SUCCESS!`;
    } else {
        document.title = `${FNAME_MODULE_UPDATED}: Test Failed`;
    }
    
    logS3(`Resultado final: ${result.message}`, result.success ? "good" : "error", FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;
}
