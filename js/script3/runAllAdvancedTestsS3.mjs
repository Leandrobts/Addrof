// js/script3/runAllAdvancedTestsS3.mjs

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3, getOutputAdvancedS3 } from '../dom_elements.mjs';
import {
    testJsonTypeConfusionUAFSpeculative,
    FNAME_MODULE
} from './testJsonTypeConfusionUAFSpeculative.mjs';

async function runTestStrategy() {
    const FNAME_RUNNER = `${FNAME_MODULE}_Runner`;
    logS3(`==== INICIANDO Estratégia de Teste: ${FNAME_MODULE} ====`, 'test', FNAME_RUNNER);

    const result = await testJsonTypeConfusionUAFSpeculative();

    logS3(`==== Estratégia de Teste ${FNAME_MODULE} CONCLUÍDA ====`, 'test', FNAME_RUNNER);

    if (result.success) {
        document.title = `${FNAME_MODULE}: SUCESSO!`;
        logS3(`Resultado Final: SUCESSO! Combinação vulnerável encontrada.`, "vuln", FNAME_RUNNER);
        logS3(`   Offset: ${result.details.offset}`, "vuln", FNAME_RUNNER);
        logS3(`   Valor: ${result.details.value}`, "vuln", FNAME_RUNNER);
        logS3(`   Erro Desencadeado: ${result.details.error}`, "vuln", FNAME_RUNNER);
    } else {
        document.title = `${FNAME_MODULE}: FALHA`;
        logS3(`Resultado Final: FALHA. Nenhuma combinação vulnerável óbvia foi encontrada com os parâmetros atuais.`, "error", FNAME_RUNNER);
    }
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE}_MainOrchestrator`;
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}) - Caça Especulativa por Type Confusion ====`, 'test', FNAME_ORCHESTRATOR);

    await runTestStrategy();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;
}
