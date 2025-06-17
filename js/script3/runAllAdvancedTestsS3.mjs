// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para v111)
import { logS3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { 
    runFinalUnifiedTest, 
    FNAME_MODULE_FINAL
} from './testArrayBufferVictimCrash.mjs';

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_FINAL}_MainOrchestrator`;
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    const result = await runFinalUnifiedTest();
    
    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    
    if(result.success) {
        document.title = `${FNAME_MODULE_FINAL}: WebKit Base Leaked!`;
    } else {
        document.title = `${FNAME_MODULE_FINAL}: FAILED`;
    }
    
    logS3(`Resultado final: ${result.message}`, result.success ? "good" : "error", FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;
}
