// js/script3/runAllAdvancedTestsS3.mjs (ORQUESTRADOR FINAL E SINCRONIZADO)

import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTypedArrayVictimAddrofAndWebKitLeak_R43, 
    FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT
} from './testArrayBufferVictimCrash.mjs';

async function runFinalExploitStrategy() {
    const FNAME_RUNNER = "runFinalExploitStrategy"; 
    logS3(`==== INICIANDO ESTRATÉGIA DE EXPLORAÇÃO FINAL (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    
    // Chama o módulo de teste final e completo
    const result = await executeTypedArrayVictimAddrofAndWebKitLeak_R43();
    const module_name_for_title = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;

    if (!result) {
        logS3(`  RUNNER FINAL: O teste principal retornou um resultado nulo ou indefinido.`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: Test ERR! (Null Result)`;
        return;
    }

    // A lógica de relatório agora é muito mais simples, baseada no novo objeto de resultado.
    if (result.success) {
        logS3(`  RUNNER FINAL: A CADEIA DE EXPLORAÇÃO OBTEVE SUCESSO!`, "vuln", FNAME_RUNNER);
        logS3(`  MENSAGEM FINAL: ${result.message}`, "good", FNAME_RUNNER);
        document.title = `${module_name_for_title}: ROP SUCCESS!`;
    } else {
        logS3(`  RUNNER FINAL: A CADEIA DE EXPLORAÇÃO FALHOU.`, "critical", FNAME_RUNNER);
        logS3(`  MENSAGEM FINAL: ${result.message}`, "error", FNAME_RUNNER);
        document.title = `${module_name_for_title}: ROP FAIL!`;
    }

    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== ESTRATÉGIA DE EXPLORAÇÃO FINAL (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}


export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `Final_MainOrchestrator`;
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    // Chama o novo runner final
    await runFinalExploitStrategy();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;
}
