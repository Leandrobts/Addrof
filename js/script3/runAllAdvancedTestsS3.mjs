// js/script3/runAllAdvancedTestsS3.mjs

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3, getOutputAdvancedS3 } from '../dom_elements.mjs';
import {
    executeFullExploitChain,
    FNAME_MODULE
} from './final_exploit_chain.mjs';

async function runTestStrategy() {
    const FNAME_RUNNER = `${FNAME_MODULE}_Runner`;
    logS3(`==== INICIANDO Estratégia de Teste: ${FNAME_MODULE} ====`, 'test', FNAME_RUNNER);
    document.title = `Iniciando ${FNAME_MODULE}...`;

    const result = await executeFullExploitChain();

    logS3(`==== Estratégia de Teste ${FNAME_MODULE} CONCLUÍDA ====`, 'test', FNAME_RUNNER);

    if (result.arb_read_success) {
        document.title = `${FNAME_MODULE}: SUCESSO TOTAL!`;
        logS3(`Resultado Final: ${result.message}`, "vuln", FNAME_RUNNER);
    } else if (result.addrof_success) {
        document.title = `${FNAME_MODULE}: Addrof OK, Read Fail`;
        logS3(`Resultado Final: SUCESSO PARCIAL. 'addrof' funcionou, mas a leitura arbitrária falhou.`, "warn", FNAME_RUNNER);
        logS3(`   Detalhe: ${result.message}`, "warn");
    } else {
        document.title = `${FNAME_MODULE}: FALHA`;
        logS3(`Resultado Final: FALHA. ${result.message}`, "error", FNAME_RUNNER);
    }
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE}_MainOrchestrator`;
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}) - Foco na Cadeia de Exploração Completa ====`, 'test', FNAME_ORCHESTRATOR);

    await runTestStrategy();
    
    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;
}
