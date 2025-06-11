// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para R55 - Type Confusion no JSC Heap)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';

import {
    executeTypedArrayVictimAddrofAndWebKitLeak_R55,
    FNAME_MODULE_TYPEDARRAY_ADDROF_V94_TCF_R55_WEBKIT
} from './testArrayBufferVictimCrash.mjs';


async function runJSCHeapTCStrategy_R55() {
    const FNAME_RUNNER = "runJSCHeapTCStrategy_R55";
    logS3(`==== INICIANDO Estratégia de Type Confusion no JSC Heap (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);

    const result = await executeTypedArrayVictimAddrofAndWebKitLeak_R55();

    const module_name_for_title = FNAME_MODULE_TYPEDARRAY_ADDROF_V94_TCF_R55_WEBKIT;

    if (result.errorOccurred) {
        logS3(`  RUNNER R55: Teste principal capturou ERRO: ${String(result.errorOccurred)}`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: MainTest ERR!`;
    } else if (result) {
        const addrofSuccess = result.addrof_result?.success;
        const webkitLeakSuccess = result.webkit_leak_result?.success;

        logS3(`  RUNNER R55: Completou.`, "good", FNAME_RUNNER);
        logS3(`  RUNNER R55: Teste Addrof/RW: ${result.addrof_result.msg}`, addrofSuccess ? "vuln" : "warn", FNAME_RUNNER);
        logS3(`  RUNNER R55: Teste WebKit Base Leak: ${result.webkit_leak_result.msg}`, webkitLeakSuccess ? "vuln" : "warn", FNAME_RUNNER);

        if (webkitLeakSuccess) {
            document.title = `${module_name_for_title}_R55: WebKitLeak SUCCESS!`;
        } else if (addrofSuccess) {
            document.title = `${module_name_for_title}_R55: Addrof OK`;
        } else {
             document.title = `${module_name_for_title}_R55: Exploit Fail`;
        }
    } else {
        document.title = `${module_name_for_title}_R55: Invalid Result Obj`;
    }
    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Type Confusion no JSC Heap (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V94_TCF_R55_WEBKIT}_MainOrchestrator`;
    logS3(`==== INICIANDO Script (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    await runJSCHeapTCStrategy_R55();
    
    logS3(`\n==== Script (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;
}
