// js/script3/runAllAdvancedTestsS3.mjs (Final - Orquestrador para o Ataque R60)

import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { 
    executeChainedUAFExploit as runUltimateExploit,
    FNAME_MODULE_ULTIMATE
} from './UltimateExploit.mjs';

/**
 * Executa a estratégia principal do teste, agora com tratamento de exceções.
 */
async function runFinalAttackStrategy() {
    const FNAME_RUNNER = "runFinalAttackStrategy";
    const moduleName = FNAME_MODULE_ULTIMATE || 'UltimateAttack';
    logS3(`==== INICIANDO Estratégia Final (${moduleName}) ====`, 'test', FNAME_RUNNER);
    document.title = `Iniciando ${moduleName}...`;

    let result;
    try {
        result = await runUltimateExploit();
    } catch (e) {
        logS3(`ERRO CRÍTICO IRRECUPERÁVEL durante a execução do teste: ${e.name} - ${e.message}`, "critical", FNAME_RUNNER);
        result = { success: false, error: e.message };
    }

    if (result && result.success) {
        logS3(`  RUNNER: SUCESSO PARCIAL DETECTADO! A corrupção causou um erro de script controlado.`, "good", FNAME_RUNNER);
        logS3(`  > Mensagem de Sucesso: ${result.message}`, "vuln", FNAME_RUNNER);
        document.title = `SUCCESS! ${moduleName}`;
    } else {
        logS3(`  RUNNER: FALHA. O ataque foi executado, mas o navegador não travou.`, "warn", FNAME_RUNNER);
        logS3(`  > Mensagem Final: ${result?.message || 'Nenhum erro de script capturado.'}`, "warn", FNAME_RUNNER);
        document.title = `${moduleName}: No Crash`;
    }
    
    logS3(`  RUNNER: O resultado ideal deste teste era um CRASH. Se o navegador não travou, a mitigação do GC foi eficaz.`, "info_major", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== ESTRATÉGIA FINAL CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}


export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_ULTIMATE}_MainOrchestrator`;
    logS3(`==== INICIANDO Script Final (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    await runFinalAttackStrategy();
    
    logS3(`\n==== Script Final (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3();
    if(runBtn) runBtn.disabled = false;
}
