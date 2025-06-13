// js/script3/runAllAdvancedTestsS3.mjs (Revisão 47 - Adaptado para Novas Primitivas)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3 } from '../dom_elements.mjs';

// ATUALIZADO: Importando a função de teste correta e o nome do módulo.
import {
    executeArrayBufferVictimCrashTest as executeExploit,
    FNAME_MODULE_V28 as FNAME_MODULE
} from './testArrayBufferVictimCrash.mjs';

async function runFinalExploitStrategy() {
    const FNAME_RUNNER = "runFinalExploitStrategy";
    logS3(`==== INICIANDO Estratégia de Teste (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);

    // O teste agora retorna um objeto com uma estrutura diferente.
    const result_wrapper = await executeExploit();
    // O resultado real do teste está dentro da propriedade 'exploit_attempt_result'.
    const result = result_wrapper?.exploit_attempt_result;

    // ATUALIZADO: Lógica de verificação de sucesso adaptada para o novo formato de resultado.
    if (!result || result.success === false) {
        logS3(`  RUNNER: O teste das primitivas arb_read/write FALHOU.`, "critical", FNAME_RUNNER);
        logS3(`  > Mensagem: ${result?.message || 'Erro desconhecido.'}`, "critical", FNAME_RUNNER);
        document.title = `${FNAME_MODULE}: FAIL!`;
    } else {
        logS3(`  RUNNER: O teste das primitivas arb_read/write foi concluído com SUCESSO.`, "good", FNAME_RUNNER);
        // O teste atual não vaza a base do WebKit, ele apenas confirma o R/W.
        logS3(`  > Mensagem: ${result.message}`, "vuln", FNAME_RUNNER);
        document.title = `SUCESSO! ${FNAME_MODULE}`;
    }

    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Teste (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE}_MainOrchestrator`;
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = true;

    await runFinalExploitStrategy();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;
}
