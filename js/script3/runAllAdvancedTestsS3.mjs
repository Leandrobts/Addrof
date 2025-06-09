// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para Revisado 45 - Estratégia em Estágios)

import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    // NOVO: Importa a nova função de teste R45 e seu nome de módulo.
    executeStagedLeak_R45,
    FNAME_MODULE_STAGED_LEAK_R45
} from './testArrayBufferVictimCrash.mjs';

// Runner para a nova estratégia R45 (Exploit em Estágios)
async function runStagedExploitStrategy_R45() {
    const FNAME_RUNNER = "runStagedExploitStrategy_R45";
    logS3(`==== INICIANDO Estratégia de Exploit em Estágios (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    
    const result = await executeStagedLeak_R45();
    const module_name_for_title = FNAME_MODULE_STAGED_LEAK_R45;

    if (!result) {
        logS3(`  RUNNER R45: Teste principal retornou um objeto de resultado inválido.`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: ERR-InvalidResult`;
        return;
    }
    
    logS3(`  RUNNER R45: Teste principal concluído. Mensagem: ${result.msg}`, result.success ? "good" : "warn", FNAME_RUNNER);

    if (result.success) {
        document.title = `${module_name_for_title}: WebKitLeak SUCCESS!`;
        logS3(`  RUNNER R45: ENDEREÇO BASE DO WEBKIT ENCONTRADO: ${result.webkit_base}`, "vuln_major");
    } else {
        document.title = `${module_name_for_title}: Fail at Stage '${result.stage}'`;
    }

    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_STAGED_LEAK_R45}_MainOrchestrator`;
    logS3(`==== INICIANDO Script 3 R45 (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    await runStagedExploitStrategy_R45();
    
    logS3(`\n==== Script 3 R45 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); 
    if (runBtn) runBtn.disabled = false;
    
    if (document.title.includes(FNAME_MODULE_STAGED_LEAK_R45) && !document.title.includes("SUCCESS") && !document.title.includes("Fail")) {
        document.title = `${FNAME_MODULE_STAGED_LEAK_R45}_R45 Done`;
    }
}
