// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para R47-LeakySelfCorruption)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeLeakySelfCorruptionStrategy_R47,
    FNAME_MODULE_LEAKY_CORRUPTION_R47
} from './testArrayBufferVictimCrash.mjs';

async function runLeakySelfCorruptionStrategy_R47() {
    const FNAME_RUNNER = "runLeakySelfCorruption_R47_Runner";
    logS3(`==== INICIANDO Estratégia de Autocorrupção com Vazamento (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    
    const result = await executeLeakySelfCorruptionStrategy_R47();

    const module_name_for_title = FNAME_MODULE_LEAKY_CORRUPTION_R47;

    if (result.error) {
        logS3(`  RUNNER R47: Teste principal capturou ERRO: ${result.error}`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: MainTest ERR!`;
    } else {
        logS3(`  RUNNER R47: Teste completado.`, "good", FNAME_RUNNER);
        logS3(`    - Primitiva de Leitura/Escrita Arbitrária: ${result.rw_primitive_ok ? "SUCESSO (Potencial)" : "FALHA"}`, result.rw_primitive_ok ? "good" : "error", FNAME_RUNNER);
        logS3(`    - Vazamento da Base do WebKit: ${result.webkit_leak_ok ? "SUCESSO" : "NÃO IMPLEMENTADO"}`, result.webkit_leak_ok ? "vuln" : "warn", FNAME_RUNNER);
        
        if (result.webkit_base_candidate) {
            logS3(`    - Base do WebKit Candidata: ${result.webkit_base_candidate}`, "leak", FNAME_RUNNER);
        }

        if (result.success) {
            document.title = `${module_name_for_title}: SUCCESS!`;
        } else if (result.rw_primitive_ok) {
            document.title = `${module_name_for_title}: R/W OK, Leak NI`;
        } else {
            document.title = `${module_name_for_title}: R/W Primitive Fail`;
        }
    }
    
    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Autocorrupção com Vazamento (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_LEAKY_CORRUPTION_R47}_MainOrchestrator`;
    logS3(`==== INICIANDO Script 3 R47 (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    await runLeakySelfCorruptionStrategy_R47();
    
    logS3(`\n==== Script 3 R47 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;
    
    if (document.title.includes(FNAME_MODULE_LEAKY_CORruption_R47) && !document.title.includes("SUCCESS") && !document.title.includes("Fail") && !document.title.includes("OK")) {
        document.title = `${FNAME_MODULE_LEAKY_CORRUPTION_R47}_Done`;
    }
}
