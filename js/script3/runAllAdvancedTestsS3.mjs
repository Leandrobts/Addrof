// js/script3/runAllAdvancedTestsS3.mjs (Revisão 59.1 - Corrigido)

import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3 } from '../dom_elements.mjs';

// CORREÇÃO: Importa a função correta do nosso script de ataque final
import {
    executeChainedUAF_R59 as runUltimateExploit,
    FNAME_MODULE_ULTIMATE
} from './UltimateExploit.mjs';

async function runFinalBypassStrategy() {
    const FNAME_RUNNER = "runChainedUAF_R59";
    const moduleName = FNAME_MODULE_ULTIMATE;
    logS3(`==== INICIANDO ESTRATÉGIA DE ATAQUE ENCADEADO (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    
    let result;
    try {
        result = await runUltimateExploit();
    } catch (e) {
        logS3(`ERRO CRÍTICO IRRECUPERÁVEL: ${e.name} - ${e.message}`, "critical", FNAME_RUNNER);
        result = { success: false, error: { message: e.message } };
    }

    logS3(`  RUNNER R59: Teste concluído.`, "info", FNAME_RUNNER);
    
    if (result.success) {
        document.title = `${moduleName}: Partial Success!`;
        logS3(`  > SUCESSO PARCIAL: ${result.message}`, "vuln", FNAME_RUNNER);
    } else {
        document.title = `${moduleName}: No Crash Detected.`;
        logS3(`  > Resultado: ${result.message}`, "warn", FNAME_RUNNER);
    }
    logS3(`  RUNNER R59: O resultado ideal deste teste é um CRASH do navegador.`, "info_major", FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_ULTIMATE}_MainOrchestrator`;
    logS3(`==== INICIANDO Script Final (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    await runFinalBypassStrategy();
    
    logS3(`\n==== Script Final (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if(runBtn) runBtn.disabled = false;
}
