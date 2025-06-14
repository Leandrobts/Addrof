// js/script3/runAllAdvancedTestsS3.mjs (ORQUESTRADOR PARA O TESTE HÍBRIDO)

import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTypedArrayVictimAddrofAndWebKitLeak_R43, 
    FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT // Usa o nome exportado do outro arquivo
} from './testArrayBufferVictimCrash.mjs';

async function runHybridExploitStrategy() {
    const FNAME_RUNNER = "runHybridExploitStrategy"; 
    logS3(`==== INICIANDO Estratégia Híbrida (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    
    // Chama o módulo de teste híbrido
    const result = await executeTypedArrayVictimAddrofAndWebKitLeak_R43();
    const module_name_for_title = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;

    if (result.errorOccurred) {
        logS3(`  RUNNER Híbrido: Teste principal capturou um ERRO: ${String(result.errorOccurred)}`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: Test ERR!`;
    } else if (result) {
        logS3(`  RUNNER Híbrido: Teste completou.`, "good", FNAME_RUNNER);

        const addrofResult = result.addrof_result;
        const webkitLeakResult = result.webkit_leak_result;

        // Reporta o resultado da Fase 1 (Addrof)
        if (addrofResult) {
            logS3(`  RUNNER Híbrido (Fase 1 - Addrof): ${addrofResult.msg}`, addrofResult.success ? "vuln" : "warn", FNAME_RUNNER);
        } else {
            logS3(`  RUNNER Híbrido (Fase 1 - Addrof): Resultado não disponível.`, "warn", FNAME_RUNNER);
        }

        // Reporta o resultado da Fase 2 (WebKit Leak)
        if (webkitLeakResult) {
            logS3(`  RUNNER Híbrido (Fase 2 - WebKit Leak): ${webkitLeakResult.msg}`, webkitLeakResult.success ? "vuln" : "warn", FNAME_RUNNER);
             if(webkitLeakResult.webkit_base_candidate) {
                logS3(`    Base Candidata do WebKit: ${webkitLeakResult.webkit_base_candidate}`, "leak", FNAME_RUNNER);
            }
        } else {
            logS3(`  RUNNER Híbrido (Fase 2 - WebKit Leak): Resultado não disponível.`, "warn", FNAME_RUNNER);
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
        logS3(`  RUNNER Híbrido: Formato de resultado inválido recebido do módulo de teste.`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: Invalid Result Obj`;
    }

    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia Híbrida (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}


export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `Hybrid_MainOrchestrator`;
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    // Chama o novo runner da estratégia híbrida
    await runHybridExploitStrategy();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;
}
