// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para Revisado 59)

import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeChainedUAF_R59 as runUltimateExploit,
    FNAME_MODULE_ULTIMATE
} from './UltimateExploit.mjs';

async function runFinalBypassStrategy() {
    const FNAME_RUNNER = "runChainedUAF_R59"; 
    logS3(`==== INICIANDO ESTRATÉGIA DE ATAQUE ENCADEADO (${FNAME_RUNNER}) ====`, 'test');
    
    const result = await runUltimateExploit();

    logS3(`  RUNNER R59: Teste concluído.`, "info", FNAME_RUNNER);
    
    if (result.success) {
        document.title = `${FNAME_MODULE_ULTIMATE}: Partial Success!`;
        logS3(`  > Resultado: ${result.message}`, "vuln");
    } else {
        document.title = `${FNAME_MODULE_ULTIMATE}: No Crash Detected.`;
        logS3(`  > Resultado: ${result.message}`, "warn");
    }
    logS3(`  RUNNER R59: O resultado ideal deste teste é um CRASH do navegador.`, "info_major");
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_ULTIMATE}_MainOrchestrator`;
    logS3(`==== INICIANDO Script Final (${FNAME_ORCHESTRATOR}) ... ====`, 'test');
    
    await runFinalBypassStrategy();
    
    logS3(`\n==== Script Final (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test');
}
