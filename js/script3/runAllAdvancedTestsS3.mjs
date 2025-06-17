// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para o Teste ROP)
import { logS3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { runROPChainTest } from './testArrayBufferVictimCrash.mjs';

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = "ROP_Test_MainOrchestrator";
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}) ... ====`, 'test');
    
    const result = await runROPChainTest();
    
    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test');
    
    if(result.success) {
        document.title = `ROP Chain Staged!`;
    } else {
        document.title = `ROP Test Failed`;
    }
    
    logS3(`Resultado final: ${result.message}`, result.success ? "good" : "error");
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;
}
