// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3 } from '../dom_elements.mjs';

// Importa a função focada em reproduzir o crash.
import { reproduceInitialCrash } from './testMemoryLeakViaJsonTC.mjs';

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `MainOrchestrator_CrashRepro`;
    logS3(`==== INICIANDO ESTRATÉGIA: REPRODUÇÃO DE CRASH (${FNAME_ORCHESTRATOR}) ====`, 'test', FNAME_ORCHESTRATOR);

    const runBtn = getRunBtnAdvancedS3();
    if (runBtn) runBtn.disabled = true;

    await PAUSE_S3(MEDIUM_PAUSE_S3);

    // Chama a função principal do novo teste
    await reproduceInitialCrash();

    logS3(`\n==== ESTRATÉGIA DE REPRODUÇÃO CONCLUÍDA (${FNAME_ORCHESTRATOR}) ====`, 'test', FNAME_ORCHESTRATOR);
    logS3("Se o navegador não travou, a tentativa de reprodução falhou.", "info", FNAME);
    if (runBtn) runBtn.disabled = false;
    document.title = `CrashRepro: Done`;
}
