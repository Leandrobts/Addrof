// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para Revisão 51 - Ataque Wasm)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeWasmOverwrite_R51,
    FNAME_MODULE_WASM_ACE_R51
} from './testArrayBufferVictimCrash.mjs';

async function runWasmAttack_R51() {
    const FNAME_RUNNER = "runWasmAttack_R51";
    logS3(`==== INICIANDO Estratégia de Ataque Wasm (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    
    const result = await executeWasmOverwrite_R51();
    const module_name_for_title = FNAME_MODULE_WASM_ACE_R51;

    if (!result) {
        logS3(`  RUNNER R51: Teste retornou resultado inválido.`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: Invalid Result!`;
        return;
    }

    if (result.errorOccurred) {
        logS3(`  RUNNER R51: Teste principal capturou ERRO: ${String(result.errorOccurred)}`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: MainTest ERR!`;
    } else if (result.success) {
        logS3(`  RUNNER R51: SUCESSO! Execução de Código Arbitrário (ACE) obtida.`, "vuln", FNAME_RUNNER);
        logS3(`  RUNNER R51: Detalhes: ${result.msg}`, "good", FNAME_RUNNER);
        document.title = `${module_name_for_title}: ACE SUCCESS!`;
    } else {
        logS3(`  RUNNER R51: FALHA no ataque Wasm.`, "error", FNAME_RUNNER);
        logS3(`  RUNNER R51: Detalhes: ${result.msg}`, "warn", FNAME_RUNNER);
        document.title = `${module_name_for_title}: ACE Fail!`;
    }
    
    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Ataque Wasm (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_WASM_ACE_R51}_MainOrchestrator`;
    logS3(`==== INICIANDO Script 3 R51 (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    await runWasmAttack_R51();

    logS3(`\n==== Script 3 R51 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;
}
