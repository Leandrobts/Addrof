// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para Revisão 53 - Ataque JIT)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeJITOverwrite_R53,
    FNAME_MODULE_JIT_OVERWRITE_R53
} from './testArrayBufferVictimCrash.mjs';

async function runJITAttack_R53() {
    const FNAME_RUNNER = "runJITAttack_R53";
    logS3(`==== INICIANDO Estratégia de Ataque JIT (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    
    const result = await executeJITOverwrite_R53();
    const module_name_for_title = FNAME_MODULE_JIT_OVERWRITE_R53;

    if (!result) {
        logS3(`  RUNNER R53: Teste retornou resultado inválido.`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: Invalid Result!`;
        return;
    }

    if (result.errorOccurred) {
        logS3(`  RUNNER R53: Teste principal capturou ERRO: ${String(result.errorOccurred)}`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: MainTest ERR!`;
    } else if (result.success) {
        logS3(`  RUNNER R53: SUCESSO! Execução de Código Arbitrário (ACE) obtida.`, "vuln", FNAME_RUNNER);
        logS3(`  RUNNER R53: Detalhes: ${result.msg}`, "good", FNAME_RUNNER);
        document.title = `${module_name_for_title}: JIT ACE SUCCESS!`;
    } else {
        logS3(`  RUNNER R53: FALHA no ataque JIT.`, "error", FNAME_RUNNER);
        logS3(`  RUNNER R53: Detalhes: ${result.msg}`, "warn", FNAME_RUNNER);
        document.title = `${module_name_for_title}: JIT ACE Fail!`;
    }
    
    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Ataque JIT (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_JIT_OVERWRITE_R53}_MainOrchestrator`;
    logS3(`==== INICIANDO Script 3 R53 (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    await runJITAttack_R53();

    logS3(`\n==== Script 3 R53 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;
}
