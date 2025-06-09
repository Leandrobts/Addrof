// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para Revisado 44 - Estratégia CallFrame)

import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    // A função original é mantida importada, mas não será a principal chamada.
    executeTypedArrayVictimAddrofAndWebKitLeak_R43, 
    FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT,

    // NOVO: Importa a nova função e seu nome de módulo
    executeCallFrameVictimAddrofAndWebKitLeak_R44,
    FNAME_MODULE_CALLFRAME_ADDROF_R44

} from './testArrayBufferVictimCrash.mjs';

// Runner para a nova estratégia R44 (CallFrame Victim)
async function runNewCallFrameStrategy_R44() {
    const FNAME_RUNNER = "runNewCallFrameStrategy_R44";
    logS3(`==== INICIANDO Estratégia de Addrof via CallFrame (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    
    const result = await executeCallFrameVictimAddrofAndWebKitLeak_R44();
    const module_name_for_title = FNAME_MODULE_CALLFRAME_ADDROF_R44;

    if (!result) {
        logS3(`  RUNNER R44: Teste principal retornou um objeto de resultado inválido.`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: ERR-InvalidResult`;
        return;
    }

    logS3(`  RUNNER R44: Teste principal concluído. Mensagem: ${result.msg}`, result.success ? "good" : "warn", FNAME_RUNNER);

    if (result.probe_details) {
        logS3(`  RUNNER R44: Detalhes da sonda AddrOf: ${JSON.stringify(result.probe_details)}`, "leak", FNAME_RUNNER);
    }
    
    const addrofSuccess = result.addrof_success;
    const webkitLeakSuccess = result.webkit_leak_success;
    
    logS3(`  RUNNER R44: Sucesso Addrof: ${addrofSuccess}`, addrofSuccess ? "vuln" : "warn", FNAME_RUNNER);
    logS3(`  RUNNER R44: Sucesso WebKit Leak: ${webkitLeakSuccess}`, webkitLeakSuccess ? "vuln" : "warn", FNAME_RUNNER);
    
    if (webkitLeakSuccess) {
        document.title = `${module_name_for_title}: WebKitLeak SUCCESS!`;
        logS3(`  RUNNER R44: ENDEREÇO BASE DO WEBKIT ENCONTRADO: ${result.webkit_base}`, "vuln_major", FNAME_RUNNER);
    } else if (addrofSuccess) {
        document.title = `${module_name_for_title}: Addrof OK, WebKitLeak Fail`;
    } else {
        document.title = `${module_name_for_title}: Addrof/WebKitLeak Fail`;
    }

    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    // ALTERADO: O orquestrador agora chama a nova estratégia R44 por padrão.
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_CALLFRAME_ADDROF_R44}_MainOrchestrator`;
    logS3(`==== INICIANDO Script 3 R44 (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    await runNewCallFrameStrategy_R44();
    
    logS3(`\n==== Script 3 R44 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); 
    if (runBtn) runBtn.disabled = false;
    
    if (document.title.includes(FNAME_MODULE_CALLFRAME_ADDROF_R44) && !document.title.includes("SUCCESS") && !document.title.includes("Fail") && !document.title.includes("OK")) {
        document.title = `${FNAME_MODULE_CALLFRAME_ADDROF_R44}_R44 Done`;
    }
}
