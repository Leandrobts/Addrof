// js/script3/runAllAdvancedTestsS3.mjs (Sem alterações necessárias)

import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3 } from '../dom_elements.mjs';

// Importa a função principal e a constante de nome do nosso script de ataque final
import {
    executeDirectTypeConfusionAttack as runUltimateExploit,
    FNAME_MODULE_ULTIMATE
} from './UltimateExploit.mjs';

async function runFinalAttackStrategy() {
    const FNAME_RUNNER = "runFinalAttackStrategy";
    const moduleName = FNAME_MODULE_ULTIMATE || 'Final_Attack';
    logS3(`==== INICIANDO ESTRATÉGIA FINAL (${moduleName}) ====`, 'test', FNAME_RUNNER);
    
    const result = await runUltimateExploit();

    if (result && result.success) {
        logS3(`  RUNNER: SUCESSO!`, "good", FNAME_RUNNER);
        logS3(`  > Mensagem de Sucesso: ${result.message}`, "vuln_major", FNAME_RUNNER);
        document.title = `SUCESSO! ${moduleName}`;
    } else {
        logS3(`  RUNNER: FALHA.`, "critical", FNAME_RUNNER);
        logS3(`  > Mensagem Final: ${result?.message || 'Erro desconhecido.'}`, "critical", FNAME_RUNNER);
        document.title = `${moduleName}: Exploit FAILED`;
    }
    
    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
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
