// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para Revisão 52)

import { logS3 } from './s3_utils.mjs';
import {
    executeTypedArrayCorruption_R52,
    FNAME_MODULE_TYPEDARRAY_CORRUPTION_R52
} from './testArrayBufferVictimCrash.mjs';

async function runTypedArrayCorruption_R52() {
    const FNAME_RUNNER = "runTypedArrayCorruption_R52";
    logS3(`==== INICIANDO Estratégia de Corrupção de TypedArray (${FNAME_RUNNER}) ====`, 'test');
    
    const result = await executeTypedArrayCorruption_R52();
    const module_name_for_title = FNAME_MODULE_TYPEDARRAY_CORRUPTION_R52;

    logS3(`  RUNNER R52: Teste concluído. Mensagem: ${result.msg}`, result.success ? "good" : "warn");

    if (result.success) {
        document.title = `${module_name_for_title}: SUCCESS!`;
        logS3(`  RUNNER R52: ENDEREÇO BASE DO WEBKIT: ${result.webkit_base}`, "vuln_major");
    } else {
        document.title = `${module_name_for_title}: Fail at Stage '${result.stage}'`;
    }
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_CORRUPTION_R52}_MainOrchestrator`;
    logS3(`==== INICIANDO Script 3 R52 (${FNAME_ORCHESTRATOR}) ... ====`, 'test');
    await runTypedArrayCorruption_R52();
    logS3(`\n==== Script 3 R52 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test');
}
