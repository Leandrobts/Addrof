// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para R49-DefinitiveChain)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeDefinitiveChain_R49,
    FNAME_MODULE_DEFINITIVE_CHAIN_R49
} from './testArrayBufferVictimCrash.mjs';

async function runDefinitiveChain_R49() {
    const FNAME_RUNNER = "runDefinitiveChain_R49_Runner";
    logS3(`==== INICIANDO A Cadeia Definitiva (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    
    const result = await executeDefinitiveChain_R49();
    const module_name_for_title = FNAME_MODULE_DEFINITIVE_CHAIN_R49;

    if (result.error) {
        logS3(`  RUNNER R49: Teste principal capturou ERRO: ${result.error}`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: MainTest ERR!`;
    } else {
        logS3(`  RUNNER R49: Teste completado.`, "good", FNAME_RUNNER);
        logS3(`    - Primitiva de R/W Userland: ${result.rw_ok ? "SUCESSO" : "FALHA"}`, result.rw_ok ? "vuln" : "error", FNAME_RUNNER);
        logS3(`    - Payload do Kernel Construído: ${result.kexploit_built ? "SUCESSO" : "FALHA"}`, result.kexploit_built ? "good" : "error", FNAME_RUNNER);

        if (result.success) {
            document.title = `${module_name_for_title}: SUCCESS!`;
        } else if (result.rw_ok) {
            document.title = `${module_name_for_title}: Userland OK, Kernel Fail`;
        } else {
            document.title = `${module_name_for_title}: Userland R/W Fail`;
        }
    }
    
    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== A Cadeia Definitiva (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_DEFINITIVE_CHAIN_R49}_MainOrchestrator`;
    logS3(`==== INICIANDO Script 3 R49 (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    try {
        await runDefinitiveChain_R49();
    } catch(e) {
        logS3(`ERRO CRÍTICO no orquestrador: ${e.message}`, "critical", FNAME_ORCHESTRATOR);
    }
    
    logS3(`\n==== Script 3 R49 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;
    
    const final_title_constant = FNAME_MODULE_DEFINITIVE_CHAIN_R49;
    if (document.title.includes(final_title_constant) && !document.title.includes("SUCCESS") && !document.title.includes("Fail")) {
        document.title = `${final_title_constant}_Done`;
    }
}
