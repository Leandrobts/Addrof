// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para Revisado 48 - Primitivas Confiáveis)

import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeAdjacentCorruption_R48,
    FNAME_MODULE_PRIMITIVES_R48
} from './testArrayBufferVictimCrash.mjs';

// Runner para a nova estratégia R48
async function runPrimitivesStrategy_R48() {
    const FNAME_RUNNER = "runPrimitivesStrategy_R48";
    logS3(`==== INICIANDO Estratégia de Primitivas Confiáveis (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    
    const result = await executeAdjacentCorruption_R48();
    const module_name_for_title = FNAME_MODULE_PRIMITIVES_R48;

    if (!result) {
        logS3(`  RUNNER R48: Teste principal retornou um objeto de resultado inválido.`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: ERR-InvalidResult`;
        return;
    }
    
    logS3(`  RUNNER R48: Teste concluído. Mensagem: ${result.msg}`, result.success ? "good" : "warn", FNAME_RUNNER);

    if (result.success) {
        document.title = `${module_name_for_title}: WebKitLeak SUCCESS!`;
        logS3(`  RUNNER R48: ENDEREÇO BASE DO WEBKIT ENCONTRADO: ${result.webkit_base}`, "vuln_major");
    } else {
        document.title = `${module_name_for_title}: Fail at Stage '${result.stage}'`;
    }

    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_PRIMITIVES_R48}_MainOrchestrator`;
    logS3(`==== INICIANDO Script 3 R48 (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    await runPrimitivesStrategy_R48();
    
    logS3(`\n==== Script 3 R48 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); 
    if (runBtn) runBtn.disabled = false;
}
