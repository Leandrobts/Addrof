// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para Revisado 58)

import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    execute_json_uaf_attack_R58 as runUltimateExploit,
    FNAME_MODULE_ULTIMATE
} from './UltimateExploit.mjs';

async function runFinalBypassStrategy() {
    const FNAME_RUNNER = "runUAFStrategy_R58"; 
    logS3(`==== INICIANDO ESTRATÉGIA DE ATAQUE UAF (${FNAME_RUNNER}) ====`, 'test');
    
    const result = await runUltimateExploit();

    // Para este teste, não há um resultado de "sucesso" no código, pois o sucesso é um crash.
    // O log apenas reflete que o teste foi executado.
    logS3(`  RUNNER R58: Teste concluído.`, "info", FNAME_RUNNER);
    logS3(`  > Mensagem Final: ${result.message}`, "warn", FNAME_RUNNER);
    document.title = `${FNAME_MODULE_ULTIMATE}: UAF Test Finished.`;

    logS3(`  RUNNER R58: O resultado esperado deste teste é um CRASH. Se o navegador não travou, a mitigação do GC é eficaz.`, "info_major");
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_ULTIMATE}_MainOrchestrator`;
    logS3(`==== INICIANDO Script Final (${FNAME_ORCHESTRATOR}) ... ====`, 'test');
    
    await runFinalBypassStrategy();
    
    logS3(`\n==== Script Final (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test');
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;
}
