// js/script3/runAllAdvancedTestsS3.mjs

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3, getOutputAdvancedS3 } from '../dom_elements.mjs';
import {
    executeJsonRecursionCrashTest,
    FNAME_MODULE
} from './testJsonRecursionCrash.mjs';

async function runTestStrategy() {
    const FNAME_RUNNER = `${FNAME_MODULE}_Runner`;
    logS3(`==== INICIANDO Estratégia de Teste: ${FNAME_MODULE} ====`, 'test', FNAME_RUNNER);
    logS3("O objetivo é replicar o crash 'idx < size()' ou 'lento/sem memória'.", "info", FNAME_RUNNER);
    logS3("Abra o console do navegador (F12) com 'Preserve Log' ATIVADO para ver os logs da sonda.", "warn", FNAME_RUNNER);

    // Pausa para dar tempo de ler a mensagem
    await PAUSE_S3(1000);

    const result = await executeJsonRecursionCrashTest();

    logS3(`==== Estratégia de Teste ${FNAME_MODULE} CONCLUÍDA (do ponto de vista do runner) ====`, 'test', FNAME_RUNNER);

    if (result.error) {
        document.title = `${FNAME_MODULE}: ERRO CAPTURADO`;
        logS3(`Resultado: Teste finalizou com um erro explícito: ${result.error}`, "error", FNAME_RUNNER);
    } else if (result.completed) {
        document.title = `${FNAME_MODULE}: SUCESSO (Inesperado)`;
        logS3("Resultado: Teste completou sem travar. A condição para o crash não foi atingida com este objeto.", "good", FNAME_RUNNER);
    } else {
        // Se a função retornou, mas 'completed' é false, algo estranho ocorreu.
        // No entanto, o mais provável é que o script pare antes de chegar aqui.
        document.title = `${FNAME_MODULE}: TRAVAMENTO PROVÁVEL`;
        logS3("Resultado: O runner continuou, mas o teste não foi marcado como concluído. Verifique o console para os últimos logs antes do provável travamento.", "critical", FNAME_RUNNER);
    }
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE}_MainOrchestrator`;
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}) ====`, 'test', FNAME_ORCHESTRATOR);

    await runTestStrategy();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;
}
