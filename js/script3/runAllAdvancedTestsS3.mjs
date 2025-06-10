// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para Revisado 55)

import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeDestructorHijack_R55,
    FNAME_MODULE_DESTRUCTOR_HIJACK_R55
} from './testArrayBufferVictimCrash.mjs';

async function runDestructorHijack_R55() {
    const FNAME_RUNNER = "runDestructorHijack_R55";
    logS3(`==== INICIANDO Estratégia de Ataque ao Destruidor (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    
    const result = await executeDestructorHijack_R55();
    const module_name_for_title = FNAME_MODULE_DESTRUCTOR_HIJACK_R55;

    logS3(`  RUNNER R55: Teste concluído. Mensagem: ${result.msg}`, result.success ? "good" : "warn", FNAME_RUNNER);

    if (result.success) {
        document.title = `${module_name_for_title}: Corruption Attempted.`;
    } else {
        document.title = `${module_name_for_title}: Fail at Stage '${result.stage}'`;
    }

    logS3(`  RUNNER R55: Se o navegador travou, o ataque foi bem-sucedido em corromper o heap.`, "info_major");
    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_DESTRUCTOR_HIJACK_R55}_MainOrchestrator`;
    logS3(`==== INICIANDO Script 3 R55 (${FNAME_ORCHESTRATOR}) ... ====`, 'test');
    await runDestructorHijack_R55();
    logS3(`\n==== Script 3 R55 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test');
}
