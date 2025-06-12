// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para Revisão 46 - Fuzzer de Offset)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeOffsetFuzzer_R46,
    FNAME_MODULE_OFFSET_FUZZER_R46
} from './testArrayBufferVictimCrash.mjs';

// NOVO: Runner focado em encontrar o offset correto para a corrupção.
async function runOffsetFuzzer_R46() {
    const FNAME_RUNNER = "runOffsetFuzzer_R46";
    logS3(`==== INICIANDO Estratégia de Fuzzing de Offset (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    
    const result = await executeOffsetFuzzer_R46();
    const module_name_for_title = FNAME_MODULE_OFFSET_FUZZER_R46;

    if (!result) {
        logS3(`  RUNNER R46: Teste retornou resultado inválido.`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: Invalid Result!`;
        return;
    }

    if (result.errorOccurred) {
        logS3(`  RUNNER R46: Teste principal capturou ERRO: ${String(result.errorOccurred)}`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: MainTest ERR!`;
    } else if (result.success) {
        logS3(`  RUNNER R46: SUCESSO! Offset funcional encontrado.`, "vuln", FNAME_RUNNER);
        logS3(`  RUNNER R46: Detalhes: ${result.msg}`, "good", FNAME_RUNNER);
        document.title = `${module_name_for_title}: Offset Found!`;
    } else {
        logS3(`  RUNNER R46: FALHA. Nenhum offset funcional encontrado na faixa testada.`, "error", FNAME_RUNNER);
        logS3(`  RUNNER R46: Detalhes: ${result.msg}`, "warn", FNAME_RUNNER);
        document.title = `${module_name_for_title}: Offset Not Found!`;
    }
    
    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Fuzzing de Offset (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_OFFSET_FUZZER_R46}_MainOrchestrator`;
    logS3(`==== INICIANDO Script 3 R46 (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    await runOffsetFuzzer_R46();

    logS3(`\n==== Script 3 R46 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;
}
