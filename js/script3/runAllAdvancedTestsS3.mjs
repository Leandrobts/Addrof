// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para chamar o Teste de Força Total)
import { logS3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { runFullControlTest, FNAME_MODULE_FULL_CONTROL } from './testArrayBufferVictimCrash.mjs';

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_FULL_CONTROL}_MainOrchestrator`;
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    const result = await runFullControlTest();
    
    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    
    if(result.success) {
        document.title = `${FNAME_MODULE_FULL_CONTROL}: ABSOLUTE CONTROL!`;
    } else {
        document.title = `${FNAME_MODULE_FULL_CONTROL}: Control Failed`;
    }
    
    logS3(`Resultado final: ${result.message}`, result.success ? "good" : "error", FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;
}
