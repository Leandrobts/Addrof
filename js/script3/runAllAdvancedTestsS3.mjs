// js/script3/runAllAdvancedTestsS3.mjs (v129 - Sincronizado com a Estratégia UAF)
import { logS3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { 
    executeTypedArrayVictimAddrofAndWebKitLeak_R43, 
    FNAME_MODULE_FINAL // #MODIFICADO: Importa o novo nome do módulo
} from './testArrayBufferVictimCrash.mjs';

// #NOVO: Runner simplificado para a estratégia UAF
async function runUAFStrategy() {
    const FNAME_RUNNER = "UAF_Strategy_Runner";
    logS3(`==== INICIANDO Estratégia de UAF em Array Uncaged (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    
    // Chama o exploit principal
    const result = await executeTypedArrayVictimAddrofAndWebKitLeak_R43();
    
    // Analisa o resultado simplificado
    if (result.errorOccurred) {
        logS3(`  RUNNER: Teste principal capturou ERRO: ${String(result.errorOccurred)}`, "critical", FNAME_RUNNER);
        document.title = `${FNAME_MODULE_FINAL}: FAIL!`;
    } else if (result.addrof_result?.success) {
        logS3(`  RUNNER: Teste principal bem-sucedido! Mensagem: ${result.addrof_result.message}`, "good", FNAME_RUNNER);
        document.title = `${FNAME_MODULE_FINAL}: SUCCESS!`;
    } else {
        logS3(`  RUNNER: Teste concluído com estado inesperado.`, "warn", FNAME_RUNNER);
        document.title = `${FNAME_MODULE_FINAL}: UNKNOWN STATE`;
    }
    
    logS3(`==== Estratégia de UAF (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
    return result.addrof_result;
}

// #MODIFICADO: Orquestrador principal agora chama o novo runner
export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_FINAL}_MainOrchestrator`;
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    const result = await runUAFStrategy();
    
    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    logS3(`Resultado final: ${result.message}`, result.success ? "good" : "error", FNAME_ORCHESTRATOR);
    
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;
}
