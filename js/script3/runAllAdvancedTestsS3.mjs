// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para Revisado 54)

import { logS3 } from './s3_utils.mjs';
import {
    executeVtableHijack_R54,
    FNAME_MODULE_VTABLE_HIJACK_R54
} from './testArrayBufferVictimCrash.mjs';

async function runVtableHijack_R54() {
    const FNAME_RUNNER = "runVtableHijack_R54";
    logS3(`==== INICIANDO Estratégia de Sequestro de Vtable (${FNAME_RUNNER}) ====`, 'test');
    
    const result = await executeVtableHijack_R54();
    const module_name_for_title = FNAME_MODULE_VTABLE_HIJACK_R54;

    logS3(`  RUNNER R54: Teste concluído. Mensagem: ${result.msg}`, result.success ? "good" : "warn");
    document.title = `${module_name_for_title}: Fail at Stage '${result.stage}'`;
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_VTABLE_HIJACK_R54}_MainOrchestrator`;
    logS3(`==== INICIANDO Script 3 R54 (${FNAME_ORCHESTRATOR}) ... ====`, 'test');
    await runVtableHijack_R54();
    logS3(`\n==== Script 3 R54 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test');
}
