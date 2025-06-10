// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para Revisado 53)

import { logS3 } from './s3_utils.mjs';
import {
    executeBruteForceOffset_R53,
    FNAME_MODULE_BRUTEFORCE_R53
} from './testArrayBufferVictimCrash.mjs';

async function runBruteForceStrategy_R53() {
    const FNAME_RUNNER = "runBruteForceStrategy_R53";
    logS3(`==== INICIANDO Estratégia de Brute-Force de Offset (${FNAME_RUNNER}) ====`, 'test');
    
    const result = await executeBruteForceOffset_R53();
    const module_name_for_title = FNAME_MODULE_BRUTEFORCE_R53;

    logS3(`  RUNNER R53: Teste concluído. Mensagem: ${result.msg}`, result.success ? "good" : "warn");

    if (result.success) {
        document.title = `${module_name_for_title}: SUCCESS!`;
        logS3(`  RUNNER R53: ENDEREÇO BASE DO WEBKIT: ${result.webkit_base}`, "vuln_major");
    } else {
        document.title = `${module_name_for_title}: Fail at Stage '${result.stage}'`;
    }
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_BRUTEFORCE_R53}_MainOrchestrator`;
    logS3(`==== INICIANDO Script 3 R53 (${FNAME_ORCHESTRATOR}) ... ====`, 'test');
    await runBruteForceStrategy_R53();
    logS3(`\n==== Script 3 R53 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test');
}
