// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para R45-Shotgun)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeShotgunCorruptionStrategy_R45,
    FNAME_MODULE_SHOTGUN_CORRUPTION_R45
} from './testArrayBufferVictimCrash.mjs';

async function runShotgunCorruptionStrategy_R45() {
    const FNAME_RUNNER = "runShotgunCorruptionStrategy_R45_Runner";
    logS3(`==== INICIANDO Estratégia de Corrupção Shotgun (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    
    const result = await executeShotgunCorruptionStrategy_R45();

    const module_name_for_title = FNAME_MODULE_SHOTGUN_CORRUPTION_R45;

    if (result.error) {
        logS3(`  RUNNER R45: Teste principal capturou ERRO: ${result.error}`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: MainTest ERR!`;
    } else {
        logS3(`  RUNNER R45: Teste completado.`, "good", FNAME_RUNNER);
        logS3(`    - Corrupção do Butterfly (TC): ${result.tc_confirmed ? "SUCESSO" : "FALHA"}`, result.tc_confirmed ? "good" : "error", FNAME_RUNNER);
        logS3(`    - Construção de Primitivas: ${result.primitives_built ? "SUCESSO" : "FALHA"}`, result.primitives_built ? "good" : "error", FNAME_RUNNER);
        logS3(`    - Auto-Teste das Primitivas: ${result.primitives_tested_ok ? "SUCESSO" : "FALHA"}`, result.primitives_tested_ok ? "good" : "error", FNAME_RUNNER);
        logS3(`    - Vazamento da Base do WebKit: ${result.webkit_leak_ok ? "SUCESSO" : "FALHA"}`, result.webkit_leak_ok ? "vuln" : "error", FNAME_RUNNER);
        
        if (result.webkit_base_candidate) {
            logS3(`    - Base do WebKit Candidata: ${result.webkit_base_candidate}`, "leak", FNAME_RUNNER);
        }

        if (result.success && result.webkit_leak_ok) {
            document.title = `${module_name_for_title}: WebKitLeak SUCCESS!`;
        } else if (result.primitives_tested_ok) {
            document.title = `${module_name_for_title}: Primitives OK, Leak Fail`;
        } else if (result.tc_confirmed) {
            document.title = `${module_name_for_title}: TC OK, Primitives Fail`;
        } else {
            document.title = `${module_name_for_title}: TC Fail`;
        }
    }
    
    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Corrupção Shotgun (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_SHOTGUN_CORRUPTION_R45}_MainOrchestrator`;
    logS3(`==== INICIANDO Script 3 R45 (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    await runShotgunCorruptionStrategy_R45();
    
    logS3(`\n==== Script 3 R45 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;
    
    if (document.title.includes(FNAME_MODULE_SHOTGUN_CORRUPTION_R45) && !document.title.includes("SUCCESS") && !document.title.includes("Fail") && !document.title.includes("OK")) {
        document.title = `${FNAME_MODULE_SHOTGUN_CORRUPTION_R45}_Done`;
    }
}
