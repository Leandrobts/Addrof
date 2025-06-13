// js/script3/runAllAdvancedTestsS3.mjs (Final - Orquestrador para UltimateExploit.mjs)

import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3 } from '../dom_elements.mjs';

// Importa a fun��o principal e a constante de nome do nosso script de ataque final
import {
    executeTypedArrayVictimAddrofAndWebKitLeak_R43 as runUltimateExploit,
    FNAME_MODULE_ULTIMATE
} from './UltimateExploit.mjs';

async function runFinalBypassStrategy() {
    const FNAME_RUNNER = "runFinalBypassStrategy"; 
    logS3(`==== INICIANDO ESTRAT�GIA DE BYPASS DE ASLR ====`, 'test', FNAME_RUNNER);
    
    // Chama a fun��o que tentar� todas as estrat�gias
    const result = await runUltimateExploit();

    if (result && result.success) {
        logS3(`  RUNNER: SUCESSO! Uma das estrat�gias de bypass funcionou.`, "good", FNAME_RUNNER);
        logS3(`  > Mensagem de Sucesso: ${result.message}`, "vuln", FNAME_RUNNER);
        document.title = `SUCESSO! ${result.message}`;
    } else {
        logS3(`  RUNNER: FALHA. Todas as estrat�gias de bypass falharam.`, "critical", FNAME_RUNNER);
        logS3(`  > Mensagem Final: ${result?.error || 'Erro desconhecido.'}`, "critical", FNAME_RUNNER);
        document.title = `${FNAME_MODULE_ULTIMATE}: Bypass FAIL!`;
    }
    
    logS3(`  T�tulo da p�gina final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== ESTRAT�GIA DE BYPASS CONCLU�DA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_ULTIMATE}_MainOrchestrator`;
    logS3(`==== INICIANDO Script Final (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    await runFinalBypassStrategy();
    
    logS3(`\n==== Script Final (${FNAME_ORCHESTRATOR}) CONCLU�DO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;
}