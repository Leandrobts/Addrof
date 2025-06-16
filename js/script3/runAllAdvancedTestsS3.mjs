// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para chamar o teste de criação de addrof corrigido)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3 } from '../dom_elements.mjs';
// Importa a nova função de teste de criação de addrof
import { runAddrofCreationTest, FNAME_MODULE_ADDROF_CREATION } from './testArrayBufferVictimCrash.mjs';

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_ADDROF_CREATION}_MainOrchestrator`;
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    // Chama diretamente a nova rotina de teste corrigida
    const result = await runAddrofCreationTest();
    
    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    
    if(result.success) {
        document.title = `${FNAME_MODULE_ADDROF_CREATION}: ADDROF SUCCESS!`;
    } else {
        document.title = `${FNAME_MODULE_ADDROF_CREATION}: Test Failed`;
    }
    
    logS3(`Resultado final: ${result.message}`, result.success ? "good" : "error", FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;
}
