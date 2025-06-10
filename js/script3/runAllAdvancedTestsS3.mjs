// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para Revisão 57)

import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeMemoryOverlapTest_R57 as runUltimateExploit,
    FNAME_MODULE_ULTIMATE
} from './UltimateExploit.mjs';

async function runFinalBypassStrategy() {
    const FNAME_RUNNER = "runFinalBypassStrategy_R57"; 
    logS3(`==== INICIANDO ESTRATÉGIA DE DIAGNÓSTICO FINAL (${FNAME_RUNNER}) ====`, 'test');
    
    const result = await runUltimateExploit();

    logS3(`  RUNNER: Teste de sobreposição de memória concluído.`, "info", FNAME_RUNNER);
    logS3(`  > Resultado: ${result.message}`, result.success ? "good" : "critical", FNAME_RUNNER);
    logS3(`  > Bits Vazados: ${result.leaked_bits}`, "leak", FNAME_RUNNER);
    
    document.title = result.success ? `${FNAME_MODULE_ULTIMATE}: Overlap SUCCESS!` : `${FNAME_MODULE_ULTIMATE}: Overlap FAIL!`;

    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_ULTIMATE}_MainOrchestrator`;
    logS3(`==== INICIANDO Script Final (${FNAME_ORCHESTRATOR}) ... ====`, 'test');
    await runFinalBypassStrategy();
    logS3(`\n==== Script Final (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test');
}
