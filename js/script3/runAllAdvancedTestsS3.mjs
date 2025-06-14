// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para R45 - Estratégia Híbrida)
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTypedArrayVictimAddrofAndWebKitLeak_R43, 
    FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT
} from './testArrayBufferVictimCrash.mjs';

async function testJITBehavior() { /* ...código sem alterações... */ }

async function runHybridStrategy_R45() {
    const FNAME_RUNNER = "runHybridUAFMemScan_R45";
    logS3(`==== INICIANDO Estratégia Híbrida (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    
    const result = await executeTypedArrayVictimAddrofAndWebKitLeak_R43();
    const module_name_for_title = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;

    if (result && result.success) {
        logS3(`  RUNNER R45: SUCESSO!`, "vuln", FNAME_RUNNER);
        logS3(`  RUNNER R45: Mensagem: ${result.msg}`, "good", FNAME_RUNNER);
        document.title = `${module_name_for_title}: SUCCESS!`;
    } else {
        const errorMsg = result ? result.errorOccurred : "Resultado indefinido do exploit.";
        logS3(`  RUNNER R45: A cadeia de exploração falhou: ${errorMsg}`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: FAIL`;
    }

    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(1000);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `Hybrid_R45_MainOrchestrator`;
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    // await testJITBehavior(); // Pulando para acelerar o teste principal
    // await PAUSE_S3(200);
    
    await runHybridStrategy_R45();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;
}
