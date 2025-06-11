// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para R44 - Corrupted Array Leak)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';

// --- CORREÇÃO: Importar os novos nomes da função e da constante do script R44 ---
import {
    executeTypedArrayVictimAddrofAndWebKitLeak_R44,
    FNAME_MODULE_TYPEDARRAY_ADDROF_V83_CAL_R44_WEBKIT
} from './testArrayBufferVictimCrash.mjs';

// --- CORREÇÃO: Renomeado para refletir a nova estratégia R44 ---
async function runCorruptedArrayLeakStrategy_R44() {
    const FNAME_RUNNER = "runCorruptedArrayLeakStrategy_R44";
    logS3(`==== INICIANDO Estratégia Corrupted Array Leak (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);

    // --- CORREÇÃO: Chamar a nova função exportada ---
    const result = await executeTypedArrayVictimAddrofAndWebKitLeak_R44();

    // --- CORREÇÃO: Usar a nova constante para o título ---
    const module_name_for_title = FNAME_MODULE_TYPEDARRAY_ADDROF_V83_CAL_R44_WEBKIT;

    if (result.errorOccurred) {
        logS3(`  RUNNER R44: Teste principal capturou ERRO: ${String(result.errorOccurred)}`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: MainTest ERR!`;
    } else if (result) {
        const addrofSuccess = result.addrof_result?.success;
        const webkitLeakSuccess = result.webkit_leak_result?.success;

        logS3(`  RUNNER R44: Completou. OOB usado: ${result.oob_value_used || 'N/A'}`, "good", FNAME_RUNNER);
        logS3(`  RUNNER R44: Teste Addrof: ${result.addrof_result.msg}`, addrofSuccess ? "vuln" : "warn", FNAME_RUNNER);
        logS3(`  RUNNER R44: Teste WebKit Base Leak: ${result.webkit_leak_result.msg}`, webkitLeakSuccess ? "vuln" : "warn", FNAME_RUNNER);

        if (webkitLeakSuccess) {
            document.title = `${module_name_for_title}_R44: WebKitLeak SUCCESS!`;
        } else if (addrofSuccess) {
            document.title = `${module_name_for_title}_R44: Addrof OK, WebKitLeak Fail`;
        } else {
            document.title = `${module_name_for_title}_R44: TC OK, Addrof Fail`;
        }

        if (result.iteration_results_summary && result.iteration_results_summary.length > 0) {
            logS3(`  RUNNER R44: Sumário completo das iterações:`, "info", FNAME_RUNNER);
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
        document.title = `${module_name_for_title}_R44: Invalid Result Obj`;
    }
    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia Corrupted Array Leak (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    // --- CORREÇÃO: Usar a nova constante no nome do orquestrador ---
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V83_CAL_R44_WEBKIT}_MainOrchestrator`;
    logS3(`==== INICIANDO Script (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    // --- CORREÇÃO: Chamar a nova função runner ---
    await runCorruptedArrayLeakStrategy_R44();
    
    logS3(`\n==== Script (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;
}
