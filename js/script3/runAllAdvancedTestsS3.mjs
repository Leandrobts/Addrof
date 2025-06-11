// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para R57 - Busca de Par Sobreposto)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';

import {
    executeTypedArrayVictimAddrofAndWebKitLeak_R57,
    FNAME_MODULE_TYPEDARRAY_ADDROF_V96_TCPF_R57_WEBKIT
} from './testArrayBufferVictimCrash.mjs';


async function runJSCHeapTCPairFindingStrategy_R57() {
    const FNAME_RUNNER = "runJSCHeapTCPairFindingStrategy_R57";
    logS3(`==== INICIANDO Estratégia de Busca de Par Sobreposto (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);

    const result = await executeTypedArrayVictimAddrofAndWebKitLeak_R57();

    const module_name_for_title = FNAME_MODULE_TYPEDARRAY_ADDROF_V96_TCPF_R57_WEBKIT;

    if (result.errorOccurred) {
        logS3(`  RUNNER R57: Teste principal capturou ERRO: ${String(result.errorOccurred)}`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: MainTest ERR!`;
    } else if (result) {
        const addrofSuccess = result.addrof_result?.success;
        const webkitLeakSuccess = result.webkit_leak_result?.success;

        logS3(`  RUNNER R57: Completou.`, "good", FNAME_RUNNER);
        logS3(`  RUNNER R57: Teste Addrof/RW: ${result.addrof_result.msg}`, addrofSuccess ? "vuln" : "warn", FNAME_RUNNER);
        logS3(`  RUNNER R57: Teste WebKit Base Leak: ${result.webkit_leak_result.msg}`, webkitLeakSuccess ? "vuln" : "warn", FNAME_RUNNER);

        if (webkitLeakSuccess) {
            document.title = `${module_name_for_title}_R57: WebKitLeak SUCCESS!`;
        } else if (addrofSuccess) {
            document.title = `${module_name_for_title}_R57: Addrof OK`;
        } else {
             document.title = `${module_name_for_title}_R57: Exploit Fail`;
        }
    } else {
        document.title = `${module_name_for_title}_R57: Invalid Result Obj`;
    }
    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Busca de Par Sobreposto (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V96_TCPF_R57_WEBKIT}_MainOrchestrator`;
    logS3(`==== INICIANDO Script (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    await runJSCHeapTCPairFindingStrategy_R57();
    
    logS3(`\n==== Script (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;
}
