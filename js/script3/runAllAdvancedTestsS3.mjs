// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para Revisão 48 - Corrupção de Estrutura)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeStructureCorruption_R48,
    FNAME_MODULE_STRUCTURE_CORRUPTION_R48
} from './testArrayBufferVictimCrash.mjs';

async function runStructureCorruption_R48() {
    const FNAME_RUNNER = "runStructureCorruption_R48";
    logS3(`==== INICIANDO Estratégia de Corrupção de Estrutura (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    
    const result = await executeStructureCorruption_R48();
    const module_name_for_title = FNAME_MODULE_STRUCTURE_CORRUPTION_R48;

    if (!result) {
        logS3(`  RUNNER R48: Teste retornou resultado inválido.`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: Invalid Result!`;
        return;
    }

    if (result.errorOccurred) {
        logS3(`  RUNNER R48: Teste principal capturou ERRO: ${String(result.errorOccurred)}`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: MainTest ERR!`;
    } else if (result.success) {
        logS3(`  RUNNER R48: SUCESSO! Primitivas Addrof/FakeObj construídas.`, "vuln", FNAME_RUNNER);
        logS3(`  RUNNER R48: Addrof(leaked_obj) => ${result.leaked_addr}`, "leak", FNAME_RUNNER);
        logS3(`  RUNNER R48: FakeObj(test_addr) => ${result.fake_obj_test_result}`, "good", FNAME_RUNNER);
        document.title = `${module_name_for_title}: Addrof/FakeObj SUCCESS!`;
    } else {
        logS3(`  RUNNER R48: FALHA na construção das primitivas.`, "error", FNAME_RUNNER);
        logS3(`  RUNNER R48: Detalhes: ${result.msg}`, "warn", FNAME_RUNNER);
        document.title = `${module_name_for_title}: Primitive Fail!`;
    }
    
    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Corrupção de Estrutura (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_STRUCTURE_CORRUPTION_R48}_MainOrchestrator`;
    logS3(`==== INICIANDO Script 3 R48 (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    await runStructureCorruption_R48();

    logS3(`\n==== Script 3 R48 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;
}
