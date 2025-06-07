// js/script3/runAllAdvancedTestsS3.mjs (Revisão 48 - Adaptado para Teste Direto de OOB)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3 } from '../dom_elements.mjs';

// ATUALIZADO: Importando a nova função de teste e o novo nome do módulo.
import {
    executeOutOfBoundsReadWriteTest as executeExploit,
    FNAME_MODULE
} from './testArrayBufferVictimCrash.mjs';

async function runFinalExploitStrategy() {
    const FNAME_RUNNER = "runFinalExploitStrategy";
    logS3(`==== INICIANDO Estratégia de Teste (${FNAME_RUNNER}) - ${FNAME_MODULE} ====`, 'test', FNAME_RUNNER);

    // A chamada da função de teste agora retorna um objeto com o resultado.
    const result_wrapper = await executeExploit();
    // O resultado real do teste está dentro da propriedade 'exploit_attempt_result'.
    const result = result_wrapper?.exploit_attempt_result;

    // A lógica de verificação de sucesso continua a mesma, pois o formato do objeto de resultado foi mantido.
    if (!result || result.success === false) {
        logS3(`  RUNNER: O teste de R/W fora dos limites FALHOU.`, "critical", FNAME_RUNNER);
        logS3(`  > Mensagem: ${result?.message || 'Erro desconhecido.'}`, "critical", FNAME_RUNNER);
        document.title = `${FNAME_MODULE}: FAIL!`;
    } else {
        logS3(`  RUNNER: O teste de R/W fora dos limites foi concluído com SUCESSO.`, "good", FNAME_RUNNER);
        logS3(`  > Mensagem: ${result.message}`, "vuln", FNAME_RUNNER);
        document.title = `SUCESSO! ${FNAME_MODULE}`;
    }

    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
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
