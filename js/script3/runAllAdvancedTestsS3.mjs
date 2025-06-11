// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3 } from '../dom_elements.mjs';

// Importa a nova função de teste UAF
import { testUafExploit } from './testMemoryLeakViaJsonTC.mjs';

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `MainOrchestrator_UafStrategy`;
    logS3(`==== INICIANDO ESTRATÉGIA DE EXPLORAÇÃO: USE-AFTER-FREE (${FNAME_ORCHESTRATOR}) ====`, 'test', FNAME_ORCHESTRATOR);

    const runBtn = getRunBtnAdvancedS3();
    if (runBtn) runBtn.disabled = true;

    await PAUSE_S3(MEDIUM_PAUSE_S3);

    // Chama a função principal do novo exploit
    await testUafExploit();

    logS3(`\n==== ESTRATÉGIA DE EXPLORAÇÃO CONCLUÍDA (${FNAME_ORCHESTRATOR}) ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;
    document.title = `UAFExploit: Done`;
}
