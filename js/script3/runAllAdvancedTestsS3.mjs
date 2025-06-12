// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para Revisão 45 - Construtor de Primitiva R/W)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeArbReadWritePrimitiveBuilder_R45,
    FNAME_MODULE_ARB_RW_BUILDER_R45
} from './testArrayBufferVictimCrash.mjs';

// NOVO: Runner focado em construir a primitiva de R/W arbitrária.
async function runArbReadWriteBuilder_R45() {
    const FNAME_RUNNER = "runArbReadWriteBuilder_R45";
    logS3(`==== INICIANDO Estratégia de Construção de Primitiva R/W (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    
    const result = await executeArbReadWritePrimitiveBuilder_R45();
    const module_name_for_title = FNAME_MODULE_ARB_RW_BUILDER_R45;

    if (!result) {
        logS3(`  RUNNER R45: Teste retornou resultado inválido.`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: Invalid Result!`;
        return;
    }

    if (result.errorOccurred) {
        logS3(`  RUNNER R45: Teste principal capturou ERRO: ${String(result.errorOccurred)}`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: MainTest ERR!`;
    } else if (result.success) {
        logS3(`  RUNNER R45: SUCESSO! Primitiva de Leitura/Escrita Arbitrária construída.`, "vuln", FNAME_RUNNER);
        logS3(`  RUNNER R45: Detalhes: ${result.msg}`, "good", FNAME_RUNNER);
        document.title = `${module_name_for_title}: ArbR/W SUCCESS!`;
    } else {
        logS3(`  RUNNER R45: FALHA na construção da primitiva.`, "error", FNAME_RUNNER);
        logS3(`  RUNNER R45: Detalhes: ${result.msg}`, "warn", FNAME_RUNNER);
        document.title = `${module_name_for_title}: ArbR/W Fail!`;
    }
    
    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Construção de Primitiva R/W (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_ARB_RW_BUILDER_R45}_MainOrchestrator`;
    logS3(`==== INICIANDO Script 3 R45 (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    // ALTERADO: Chama a nova função runner.
    await runArbReadWriteBuilder_R45();

    logS3(`\n==== Script 3 R45 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;
}
