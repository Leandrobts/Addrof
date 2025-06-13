// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para Revisão 52 - Confusão de Tipo Autocontida)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeSelfContainedTypeConfusion_R52,
    FNAME_MODULE_SELF_CONFUSION_R52
} from './testArrayBufferVictimCrash.mjs';

async function runSelfContainedConfusion_R52() {
    const FNAME_RUNNER = "runSelfContainedConfusion_R52";
    logS3(`==== INICIANDO Estratégia de Confusão de Tipo Autocontida (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    
    const result = await executeSelfContainedTypeConfusion_R52();
    const module_name_for_title = FNAME_MODULE_SELF_CONFUSION_R52;

    if (!result) {
        logS3(`  RUNNER R52: Teste retornou resultado inválido.`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: Invalid Result!`;
        return;
    }

    if (result.errorOccurred) {
        logS3(`  RUNNER R52: Teste principal capturou ERRO: ${String(result.errorOccurred)}`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: MainTest ERR!`;
    } else if (result.success) {
        logS3(`  RUNNER R52: SUCESSO! Endereço base do WebKit vazado.`, "vuln", FNAME_RUNNER);
        logS3(`  RUNNER R52: Primitiva Addrof => ${result.addrof_leaked_addr}`, "leak", FNAME_RUNNER);
        logS3(`  RUNNER R52: Endereço Base WebKit (Candidato) => ${result.webkit_base_addr}`, "leak", FNAME_RUNNER);
        document.title = `${module_name_for_title}: WebKit Leak SUCCESS!`;
    } else {
        logS3(`  RUNNER R52: FALHA no ataque.`, "error", FNAME_RUNNER);
        logS3(`  RUNNER R52: Detalhes: ${result.msg}`, "warn", FNAME_RUNNER);
        document.title = `${module_name_for_title}: Fail!`;
    }
    
    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Confusão de Tipo Autocontida (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_SELF_CONFUSION_R52}_MainOrchestrator`;
    logS3(`==== INICIANDO Script 3 R52 (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    await runSelfContainedConfusion_R52();

    logS3(`\n==== Script 3 R52 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;
}
