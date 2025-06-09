// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para Revisado 47 - Ataque ao Gigacage)

import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    // NOVO: Importa a nova função de ataque R47
    executeGigacageConfusion_R47,
    FNAME_MODULE_GIGACAGE_CONFUSION_R47
} from './testArrayBufferVictimCrash.mjs';

// Runner para a nova estratégia R47
async function runGigacageConfusionStrategy_R47() {
    const FNAME_RUNNER = "runGigacageConfusionStrategy_R47";
    logS3(`==== INICIANDO Estratégia de Confusão de Tipo no Gigacage (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    
    const result = await executeGigacageConfusion_R47();
    const module_name_for_title = FNAME_MODULE_GIGACAGE_CONFUSION_R47;

    if (!result) {
        logS3(`  RUNNER R47: Teste principal retornou um objeto de resultado inválido.`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: ERR-InvalidResult`;
        return;
    }
    
    logS3(`  RUNNER R47: Teste concluído. Mensagem: ${result.msg}`, result.success ? "good" : "warn", FNAME_RUNNER);

    if (result.success) {
        document.title = `${module_name_for_title}: Corruption Attempted. Check for Crash.`;
        logS3(`  RUNNER R47: O exploit não causou um crash imediato. A corrupção do heap pode ser sutil e pode exigir uma segunda fase para ser explorada.`, "warn");
    } else {
        document.title = `${module_name_for_title}: Fail at Stage '${result.stage}'`;
    }

    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_GIGACAGE_CONFUSION_R47}_MainOrchestrator`;
    logS3(`==== INICIANDO Script 3 R47 (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    await runGigacageConfusionStrategy_R47();
    
    logS3(`\n==== Script 3 R47 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); 
    if (runBtn) runBtn.disabled = false;
}
