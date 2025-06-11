// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para R58 - Primitiva de Escrita Controlada)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';

import {
    executeTypedArrayVictimAddrofAndWebKitLeak_R58,
    FNAME_MODULE_TYPEDARRAY_ADDROF_V97_TCCW_R58_WEBKIT
} from './testArrayBufferVictimCrash.mjs';


async function runControlledWriteStrategy_R58() {
    const FNAME_RUNNER = "runControlledWriteStrategy_R58";
    logS3(`==== INICIANDO Estratégia de Escrita Controlada (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);

    const result = await executeTypedArrayVictimAddrofAndWebKitLeak_R58();

    const module_name_for_title = FNAME_MODULE_TYPEDARRAY_ADDROF_V97_TCCW_R58_WEBKIT;

    if (result.errorOccurred) {
        logS3(`  RUNNER R58: Teste principal capturou ERRO: ${String(result.errorOccurred)}`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: MainTest ERR!`;
    } else if (result) {
        const addrofSuccess = result.addrof_result?.success;
        
        logS3(`  RUNNER R58: Completou.`, "good", FNAME_RUNNER);
        logS3(`  RUNNER R58: Teste da Primitiva de Base: ${result.addrof_result.msg}`, addrofSuccess ? "vuln" : "warn", FNAME_RUNNER);

        if (addrofSuccess) {
            document.title = `${module_name_for_title}_R58: Primitives OK`;
        } else {
             document.title = `${module_name_for_title}_R58: Exploit Fail`;
        }
    } else {
        document.title = `${module_name_for_title}_R58: Invalid Result Obj`;
    }
    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Escrita Controlada (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V97_TCCW_R58_WEBKIT}_MainOrchestrator`;
    logS3(`==== INICIANDO Script (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    await runControlledWriteStrategy_R58();
    
    logS3(`\n==== Script (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;
}
