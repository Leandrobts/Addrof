// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para Revisão 50.1 - Self-Leak Fuzzer)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeSelfLeakFuzzerAndCorrupt_R50_1,
    FNAME_MODULE_SELF_LEAK_FUZZER_R50_1
} from './testArrayBufferVictimCrash.mjs';

async function runSelfLeakFuzzer_R50_1() {
    const FNAME_RUNNER = "runSelfLeakFuzzer_R50_1";
    logS3(`==== INICIANDO Estratégia de Self-Leak Fuzzer (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    
    const result = await executeSelfLeakFuzzerAndCorrupt_R50_1();
    const module_name_for_title = FNAME_MODULE_SELF_LEAK_FUZZER_R50_1;

    if (!result) {
        logS3(`  RUNNER R50.1: Teste retornou resultado inválido.`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: Invalid Result!`;
        return;
    }

    if (result.errorOccurred) {
        logS3(`  RUNNER R50.1: Teste principal capturou ERRO: ${String(result.errorOccurred)}`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: MainTest ERR!`;
    } else if (result.success) {
        logS3(`  RUNNER R50.1: SUCESSO! Primitivas Addrof/FakeObj construídas.`, "vuln", FNAME_RUNNER);
        logS3(`  RUNNER R50.1: Addrof(leaked_obj) => ${result.leaked_addr}`, "leak", FNAME_RUNNER);
        logS3(`  RUNNER R50.1: FakeObj(test_addr) => ${result.fake_obj_test_result}`, "good", FNAME_RUNNER);
        document.title = `${module_name_for_title}: Addrof/FakeObj SUCCESS!`;
    } else {
        logS3(`  RUNNER R50.1: FALHA na construção das primitivas.`, "error", FNAME_RUNNER);
        logS3(`  RUNNER R50.1: Detalhes: ${result.msg}`, "warn", FNAME_RUNNER);
        document.title = `${module_name_for_title}: Primitive Fail!`;
    }
    
    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Self-Leak Fuzzer (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_SELF_LEAK_FUZZER_R50_1}_MainOrchestrator`;
    logS3(`==== INICIANDO Script 3 R50.1 (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    await runSelfLeakFuzzer_R50_1();

    logS3(`\n==== Script 3 R50.1 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;
}
