// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para R48-AggressiveHunt)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeAggressiveHuntStrategy_R48,
    FNAME_MODULE_AGGRESSIVE_HUNT_R48
} from './testArrayBufferVictimCrash.mjs';

async function runAggressiveHuntStrategy_R48() {
    const FNAME_RUNNER = "runAggressiveHunt_R48_Runner";
    logS3(`==== INICIANDO Estratégia de Caça Agressiva (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    
    const result = await executeAggressiveHuntStrategy_R48();

    const module_name_for_title = FNAME_MODULE_AGGRESSIVE_HUNT_R48;

    if (result.error) {
        logS3(`  RUNNER R48: Teste principal capturou ERRO: ${result.error}`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: MainTest ERR!`;
    } else {
        logS3(`  RUNNER R48: Teste completado.`, "good", FNAME_RUNNER);
        logS3(`    - Vítima Encontrada na Caça: ${result.victim_found ? "SUCESSO" : "FALHA"}`, result.victim_found ? "good" : "error", FNAME_RUNNER);
        logS3(`    - Primitiva de R/W Validada: ${result.rw_primitive_ok ? "SUCESSO" : "FALHA"}`, result.rw_primitive_ok ? "good" : "error", FNAME_RUNNER);
        logS3(`    - Primitiva de Addrof Construída: ${result.addrof_ok ? "SIM (Placeholder)" : "NÃO"}`, result.addrof_ok ? "good" : "warn", FNAME_RUNNER);
        logS3(`    - Vazamento da Base do WebKit: ${result.webkit_leak_ok ? "SUCESSO" : "NÃO IMPLEMENTADO"}`, result.webkit_leak_ok ? "vuln" : "warn", FNAME_RUNNER);

        if (result.success) {
            document.title = `${module_name_for_title}: R/W SUCCESS!`;
        } else if (result.victim_found) {
            document.title = `${module_name_for_title}: Victim Found, R/W Fail`;
        } else {
            document.title = `${module_name_for_title}: Hunt Failed`;
        }
    }
    
    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Caça Agressiva (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_AGGRESSIVE_HUNT_R48}_MainOrchestrator`;
    logS3(`==== INICIANDO Script 3 R48 (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    // Corrigindo o typo do log anterior aqui
    try {
        await runAggressiveHuntStrategy_R48();
    } catch(e) {
        logS3(`ERRO CRÍTICO no orquestrador: ${e.message}`, "critical", FNAME_ORCHESTRATOR);
    }
    
    logS3(`\n==== Script 3 R48 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;
    
    const final_title_constant = FNAME_MODULE_AGGRESSIVE_HUNT_R48;
    if (document.title.includes(final_title_constant) && !document.title.includes("SUCCESS") && !document.title.includes("Fail")) {
        document.title = `${final_title_constant}_Done`;
    }
}
