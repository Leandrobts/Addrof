// js/script3/runAllAdvancedTestsS3.mjs (Adaptado para Leitura Cruzada Pós-TC)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTypedArrayVictimAddrofAndWebKitLeak_R43,
    FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim_R43() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_R43_CrossRead";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    const result = await executeTypedArrayVictimAddrofAndWebKitLeak_R43();

    const module_name_for_title = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;

    if (result.errorOccurred) {
        logS3(`  RUNNER R43(CrossRead): Teste principal capturou ERRO: ${String(result.errorOccurred)}`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: MainTest ERR!`;
    } else if (result) {
        let paramsUsedMsg = 'N/A';
        if (result.oob_params_detailed_best_result) { // Usar o campo detalhado se existir
            paramsUsedMsg = `Offset: ${result.oob_params_detailed_best_result.offset}, Valor: ${result.oob_params_detailed_best_result.value}`;
        } else if (result.oob_value_of_best_result) { // Fallback para o campo simplificado
             paramsUsedMsg = `OOB Value: ${result.oob_value_of_best_result}`;
        }
        logS3(`  RUNNER R43(CrossRead): Completou. Parâmetros OOB usados: ${paramsUsedMsg}`, "good", FNAME_RUNNER);
        logS3(`  RUNNER R43(CrossRead): Detalhes Sonda TC: ${result.tc_probe_details ? JSON.stringify(result.tc_probe_details) : 'N/A'}`, "leak_detail", FNAME_RUNNER);

        const heisenbugSuccessfullyDetected = result.heisenbug_on_M2_in_best_result;
        const crossReadAnalysis = result.cross_read_analysis_best_result; // Obter os detalhes da análise

        logS3(`  RUNNER R43(CrossRead): Heisenbug TC Sonda: ${heisenbugSuccessfullyDetected ? "CONFIRMADA" : "NÃO CONFIRMADA"}`, heisenbugSuccessfullyDetected ? "vuln_potential" : "warn", FNAME_RUNNER);

        if (crossReadAnalysis) {
            logS3(`  RUNNER R43(CrossRead): Análise de Leitura/Escrita Cruzada Pós-TC:`, "info_emphasis", FNAME_RUNNER);
            logS3(`    Notas: ${crossReadAnalysis.notes}`, crossReadAnalysis.write_test_successful === true ? "success_major" : (crossReadAnalysis.write_test_successful === false ? "warn" : "info"), FNAME_RUNNER);
            logS3(`    Conteúdo de victim_typed_array (na sonda TC): ${crossReadAnalysis.victim_content_in_tc}`, "leak_detail", FNAME_RUNNER);
            logS3(`    Conteúdo de marker_M2_TA (na sonda TC, antes da escrita): ${crossReadAnalysis.marker_m2_content_in_tc_before_write}`, "leak_detail", FNAME_RUNNER);
            if (crossReadAnalysis.write_test_successful !== null) { // Se o teste de escrita foi tentado
                logS3(`    Conteúdo de marker_M2_TA (na sonda TC, após escrita em victim): ${crossReadAnalysis.marker_m2_content_in_tc_after_write}`, "leak_detail", FNAME_RUNNER);
                logS3(`    Teste de Escrita Cruzada bem-sucedido: ${crossReadAnalysis.write_test_successful}`, crossReadAnalysis.write_test_successful === true ? "success_major" : "warn", FNAME_RUNNER);
            }
        } else {
            logS3(`  RUNNER R43(CrossRead): Detalhes da Análise de Leitura Cruzada não disponíveis.`, "warn", FNAME_RUNNER);
        }

        // Addrof e WebKitLeak não são o foco, mas exibir seus status se presentes
        if (result.addrof_result) {
            logS3(`  RUNNER R43(CrossRead): Teste Addrof: ${result.addrof_result.msg}`, result.addrof_result.success ? "vuln" : "info", FNAME_RUNNER);
        }
        if (result.webkit_leak_result) {
            logS3(`  RUNNER R43(CrossRead): Teste WebKit Base Leak: ${result.webkit_leak_result.msg}`, result.webkit_leak_result.success ? "vuln" : "info", FNAME_RUNNER);
        }

        let finalTitleSegment = "No Notable Result";
        if (crossReadAnalysis?.write_test_successful === true) {
            finalTitleSegment = "Cross-Write SUCCESS!";
        } else if (heisenbugSuccessfullyDetected) {
            finalTitleSegment = "TC Confirmed, Cross-Write Fail/Untested";
        }
        document.title = `${module_name_for_title}_R43_CrossRead: ${finalTitleSegment}`;

        // O iteration_results_summary terá apenas um elemento neste teste
        if (result.iteration_results_summary && result.iteration_results_summary.length > 0) {
            logS3(`  RUNNER R43(CrossRead): Sumário da Iteração:`, "info", FNAME_RUNNER);
            const iter_sum = result.iteration_results_summary[0]; // Apenas uma iteração
            const tcSuccess = iter_sum.heisenbug_on_M2_confirmed_by_tc_probe;
            const crossWriteSuccess = iter_sum.cross_read_analysis?.write_test_successful;
            let logMsg = `    Iter 1 (OOB ${iter_sum.oob_value}): TC=${tcSuccess}, CrossWriteSuccess=${crossWriteSuccess}`;
            if(iter_sum.error) logMsg += `, Err: ${iter_sum.error}`;
            logS3(logMsg, "info", FNAME_RUNNER);
        }

    } else {
        document.title = `${module_name_for_title}_R43_CrossRead: Invalid Result Obj`;
    }
    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT}_MainOrchestrator_CrossRead`;
    logS3(`==== INICIANDO Script 3 R43_CrossRead (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    await runHeisenbugReproStrategy_TypedArrayVictim_R43();
    logS3(`\n==== Script 3 R43_CrossRead (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;

    if (document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT) &&
        !document.title.includes("SUCCESS") &&
        !document.title.includes("Fail") &&
        !document.title.includes("OK") &&
        !document.title.includes("Confirmed") &&
        !document.title.includes("ERR") &&
        !document.title.includes("Invalid")) {
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT}_R43_CrossRead_Done`;
    }
}
