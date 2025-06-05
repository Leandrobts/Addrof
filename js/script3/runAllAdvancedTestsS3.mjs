// js/script3/runAllAdvancedTestsS3.mjs (Adaptado para TC com Propriedade Alvo em M2)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTypedArrayVictimAddrofAndWebKitLeak_R43,
    FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim_R43() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_R43_TCPropLeak";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    const result = await executeTypedArrayVictimAddrofAndWebKitLeak_R43();

    const module_name_for_title = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;

    if (result.errorOccurred) {
        logS3(`  RUNNER R43(TCPropLeak): Teste principal capturou ERRO: ${String(result.errorOccurred)}`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: MainTest ERR!`;
    } else if (result) {
        let paramsUsedMsg = 'N/A';
        if (result.oob_params_used) {
            paramsUsedMsg = `Offset: ${result.oob_params_used.offset}, Valor: ${result.oob_params_used.value}`;
        } else if (result.oob_value_of_best_result) {
             paramsUsedMsg = `OOB Value (fallback): ${result.oob_value_of_best_result}`;
        }

        logS3(`  RUNNER R43(TCPropLeak): Completou. Parâmetros OOB usados: ${paramsUsedMsg}`, "good", FNAME_RUNNER);
        logS3(`  RUNNER R43(TCPropLeak): Detalhes Sonda TC: ${result.tc_probe_details ? JSON.stringify(result.tc_probe_details) : 'N/A'}`, "leak_detail", FNAME_RUNNER);

        const heisenbugSuccessfullyDetected = result.heisenbug_on_M2_in_best_result;
        const stringifyAnalysis = result.stringify_output_analysis;

        logS3(`  RUNNER R43(TCPropLeak): Heisenbug TC Sonda: ${heisenbugSuccessfullyDetected ? "CONFIRMADA" : "NÃO CONFIRMADA"}`, heisenbugSuccessfullyDetected ? "vuln" : "warn", FNAME_RUNNER);

        if (stringifyAnalysis) {
            logS3(`  RUNNER R43(TCPropLeak): Análise do Output do JSON.stringify:`, "info_emphasis", FNAME_RUNNER);
            logS3(`    Notas: ${stringifyAnalysis.notes}`, "info", FNAME_RUNNER);
            logS3(`    Tipo do Output: ${stringifyAnalysis.output_type}`, "info", FNAME_RUNNER);
            if (stringifyAnalysis.potential_leak) {
                logS3(`    Potencial Leak Detectado: ${stringifyAnalysis.potential_leak}`, "vuln_potential", FNAME_RUNNER);
            }
            if (result.stringifyResult) { // Logar uma parte do raw output se for string
                const rawOutputStr = typeof result.stringifyResult === 'string' ? result.stringifyResult : JSON.stringify(result.stringifyResult);
                logS3(`    Raw Output (curto): ${rawOutputStr.substring(0, Math.min(200, rawOutputStr.length))}${rawOutputStr.length > 200 ? "..." : ""}`, "leak_detail");
            }
        } else {
            logS3(`  RUNNER R43(TCPropLeak): Detalhes da Análise do Stringify não disponíveis.`, "warn", FNAME_RUNNER);
        }
        
        // Addrof e WebKitLeak não são esperados aqui, mas exibir status
        if (result.addrof_result) { logS3(`  RUNNER R43(TCPropLeak): Teste Addrof: ${result.addrof_result.msg}`, "info", FNAME_RUNNER); }
        if (result.webkit_leak_result) { logS3(`  RUNNER R43(TCPropLeak): Teste WebKit Base Leak: ${result.webkit_leak_result.msg}`, "info", FNAME_RUNNER); }

        let finalTitleSegment = "No Notable Result";
        if (stringifyAnalysis?.potential_leak) {
            finalTitleSegment = `Potential Leak via Stringify!`;
        } else if (heisenbugSuccessfullyDetected) {
            finalTitleSegment = "TC Confirmed, No Obvious Stringify Leak";
        }
        document.title = `${module_name_for_title}_R43_TCPropLeak: ${finalTitleSegment}`;

        // iteration_results_summary terá apenas um elemento
        if (result.iteration_results_summary && result.iteration_results_summary.length > 0) {
            logS3(`  RUNNER R43(TCPropLeak): Sumário da Iteração:`, "info", FNAME_RUNNER);
            const iter_sum = result.iteration_results_summary[0];
            const tcSuccess = iter_sum.heisenbug_on_M2_confirmed_by_tc_probe;
            const leakNote = iter_sum.stringify_output_analysis?.potential_leak || "Nenhum";
            let logMsg = `    Iter 1 (OOB ${iter_sum.oob_value}): TC=${tcSuccess}, StringifyLeakNote='${leakNote}'`;
            if(iter_sum.error) logMsg += `, Err: ${iter_sum.error}`;
            logS3(logMsg, "info", FNAME_RUNNER);
        }

    } else {
        document.title = `${module_name_for_title}_R43_TCPropLeak: Invalid Result Obj`;
    }
    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT}_MainOrchestrator_TCPropLeak`;
    logS3(`==== INICIANDO Script 3 R43_TCPropLeak (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    await runHeisenbugReproStrategy_TypedArrayVictim_R43();
    logS3(`\n==== Script 3 R43_TCPropLeak (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;

    if (document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT) &&
        !document.title.includes("Leak") && // Se houver leak, o título já será específico
        !document.title.includes("SUCCESS") &&
        !document.title.includes("Fail") &&
        !document.title.includes("OK") &&
        !document.title.includes("Confirmed") &&
        !document.title.includes("ERR") &&
        !document.title.includes("Invalid")) {
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT}_R43_TCPropLeak_Done`;
    }
}
