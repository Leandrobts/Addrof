// js/script3/runAllAdvancedTestsS3.mjs

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3, getOutputAdvancedS3 } from '../dom_elements.mjs';
import {
    executeHeisenbugAddrofTest,
    FNAME_MODULE
} from './testHeisenbugAddrof.mjs';

async function runTestStrategy() {
    const FNAME_RUNNER = `${FNAME_MODULE}_Runner`;
    logS3(`==== INICIANDO Estratégia de Teste: ${FNAME_MODULE} ====`, 'test', FNAME_RUNNER);

    const result = await executeHeisenbugAddrofTest();

    logS3(`==== Estratégia de Teste ${FNAME_MODULE} CONCLUÍDA ====`, 'test', FNAME_RUNNER);

    if (result.success) {
        document.title = `${FNAME_MODULE}: Addr OK!`;
        logS3(`Resultado Final: SUCESSO. Endereço vazado: ${result.leaked_address}`, "vuln", FNAME_RUNNER);
    } else if (result.tc_confirmed) {
        document.title = `${FNAME_MODULE}: TC OK, Addr Fail`;
        logS3(`Resultado Final: FALHA. ${result.message}`, "warn", FNAME_RUNNER);
    } else {
        document.title = `${FNAME_MODULE}: FALHA GERAL`;
        logS3(`Resultado Final: FALHA. ${result.message}`, "error", FNAME_RUNNER);
    }
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE}_MainOrchestrator`;
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}) - Foco no Heisenbug Addrof ====`, 'test', FNAME_ORCHESTRATOR);

    await runTestStrategy();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;
}
