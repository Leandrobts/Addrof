// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTypedArrayVictimAddrofTest_AdvancedGetterLeak,
    FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL
} from './testArrayBufferVictimCrash.mjs'; // Nomes já estavam corretos

async function runHeisenbugReproStrategy_TypedArrayVictim() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_AdvancedGetterLeak";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);

    // Chama a função de teste principal
    const result = await executeTypedArrayVictimAddrofTest_AdvancedGetterLeak();

    // Analisa o resultado consolidado
    if (result.errorOccurred) {
        logS3(`  RUNNER: Teste principal capturou ERRO: ${result.errorOccurred.name || 'Error'} - ${result.errorOccurred.message || String(result.errorOccurred)}.`, "critical", FNAME_RUNNER);
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}: MainTest ERR!`;
    } else if (result) { // result deve sempre ser um objeto agora
        logS3(`  RUNNER: Teste de Iteração de Valores OOB Concluído.`, "good", FNAME_RUNNER);
        logS3(`  RUNNER: OOB Value da Melhor/Última Iteração Reportada: ${result.oob_value_of_best_result || 'N/A'}`, "info", FNAME_RUNNER);
        logS3(`  RUNNER: Detalhes da sonda (toJSON_details) da melhor iteração: ${result.toJSON_details ? JSON.stringify(result.toJSON_details) : 'N/A'}`, "leak", FNAME_RUNNER);
        logS3(`  RUNNER: Stringify Output (stringifyResult) da melhor iteração: ${result.stringifyResult ? JSON.stringify(result.stringifyResult) : 'N/A'}`, "leak", FNAME_RUNNER);

        const heisenbugSuccessfullyDetected = result.heisenbug_on_M2_in_best_result;
        const addrofASuccess = result.addrof_A_result?.success;
        const addrofBSuccess = result.addrof_B_result?.success;

        if (addrofASuccess) {
            logS3(`  RUNNER: ADDROF M2.Getter (Melhor Iter): ${result.addrof_A_result.msg} (Valor: ${result.addrof_A_result.value})`, "vuln", FNAME_RUNNER);
        } else if (result.addrof_A_result) { // Log mesmo se falhou, para ter a msg
             logS3(`  RUNNER: ADDROF M2.Getter (Melhor Iter): ${result.addrof_A_result.msg} (Valor: ${result.addrof_A_result.value})`, "warn", FNAME_RUNNER);
        }


        if (addrofBSuccess) {
            logS3(`  RUNNER: ADDROF M2.Direct (Melhor Iter): ${result.addrof_B_result.msg} (Valor: ${JSON.stringify(result.addrof_B_result.value)})`, "vuln", FNAME_RUNNER);
        } else if (result.addrof_B_result) { // Log mesmo se falhou
            logS3(`  RUNNER: ADDROF M2.Direct (Melhor Iter): ${result.addrof_B_result.msg} (Valor: ${JSON.stringify(result.addrof_B_result.value)})`, "warn", FNAME_RUNNER);
        }


        if (addrofASuccess || addrofBSuccess) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}: AddrLeaked SUCCESS! (OOB: ${result.oob_value_of_best_result})`;
        } else if (heisenbugSuccessfullyDetected) {
            logS3(`  RUNNER: !!!! TYPE CONFUSION NO M2 OBSERVADA (na melhor iteração reportada, OOB: ${result.oob_value_of_best_result}) !!!!`, "vuln", FNAME_RUNNER);
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}: M2_TC OK, Addr Fail (OOB: ${result.oob_value_of_best_result})`;
        } else {
            logS3(`  RUNNER: Nenhuma Type Confusion em M2 confirmada na melhor iteração. Iterações testadas.`, "error", FNAME_RUNNER);
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}: No M2_TC Confirmed (OOB: ${result.oob_value_of_best_result})`;
        }
         // Log do sumário de todas as iterações, se disponível
        if(result.iteration_results_summary && result.iteration_results_summary.length > 0){
            logS3(`  RUNNER: Sumário completo das iterações:`, "info", FNAME_RUNNER);
            result.iteration_results_summary.forEach((iter_sum, index) => {
                logS3(`    Iter ${index + 1} (OOB ${iter_sum.oob_value}): TC_M2=${iter_sum.heisenbug_on_M2_this_iter}, AddrA_OK=${iter_sum.addrof_A_this_iter.success}, AddrB_OK=${iter_sum.addrof_B_this_iter.success}${iter_sum.error ? `, Err: ${iter_sum.error}` : ''}`, "info", FNAME_RUNNER);
            });
        }


    } else {
        logS3(`  RUNNER: Teste principal retornou resultado inválido ou nulo.`, "critical", FNAME_RUNNER);
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}: Invalid Result Obj`;
    }

    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_MainOrchestrator`;
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = ''; // Limpa o output anterior

    logS3(`==== User Agent: ${navigator.userAgent} ====`, 'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Heisenbug (${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}) ====`, 'test', FNAME_ORCHESTRATOR);

    await runHeisenbugReproStrategy_TypedArrayVictim();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    // A lógica de atualização do título já é tratada mais especificamente dentro de runHeisenbugReproStrategy_TypedArrayVictim
    // Podemos simplificar ou remover esta seção se a lógica acima for suficiente.
    // Por segurança, vamos manter um fallback genérico.
    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL)) {
        if (!document.title.includes("SUCCESS") && !document.title.includes("Fail") &&
            !document.title.includes("ERR") && !document.title.includes("Confirmed") &&
            !document.title.includes("Leaked")) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL} Run Finished`;
        }
    }
}
