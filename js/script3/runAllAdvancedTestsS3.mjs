// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para chamar o teste de robustez)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3 } from '../dom_elements.mjs';
// Importa a nova função de teste de robustez
import { runRobustnessVerificationTest, FNAME_MODULE_UPDATED } from './testArrayBufferVictimCrash.mjs';

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_UPDATED}_MainOrchestrator`;
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    // Chama diretamente a nova rotina de teste de robustez
    const result = await runRobustnessVerificationTest();
    
    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    
    if(result.success) {
        document.title = `${FNAME_MODULE_UPDATED}: ROBUST R/W SUCCESS!`;
    } else {
        document.title = `${FNAME_MODULE_UPDATED}: Test Failed`;
    }
    
    logS3(`Resultado final: ${result.message}`, result.success ? "good" : "error", FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;
}
