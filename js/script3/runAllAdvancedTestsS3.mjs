// js/script3/runAllAdvancedTestsS3.mjs

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3, getOutputAdvancedS3 } from '../dom_elements.mjs';
import {
    testJsonTypeConfusionUAFSpeculative,
    FNAME_MODULE
} from './testJsonTypeConfusionUAFSpeculative.mjs'; // <--- IMPORT CORRETO

/**
 * Executa a estratégia de teste especulativo.
 */
async function runSpeculativeUAFStrategy() {
    const FNAME_RUNNER = "runSpeculativeUAFStrategy";
    logS3(`==== INICIANDO Estratégia de Teste: ${FNAME_MODULE} ====`, 'test', FNAME_RUNNER);

    let result;
    try {
        result = await testJsonTypeConfusionUAFSpeculative();
    } catch (e) {
        logS3(`ERRO CRÍTICO IRRECUPERÁVEL no runner: ${e.name} - ${e.message}`, "critical", FNAME_RUNNER);
        console.error("Erro capturado em runSpeculativeUAFStrategy:", e);
        result = { success: false, details: { error: "Erro do Runner: " + e.message } };
    }

    logS3(`==== Estratégia de Teste ${FNAME_MODULE} CONCLUÍDA ====`, 'test', FNAME_RUNNER);

    if (result.success) {
        document.title = `${FNAME_MODULE}: SUCESSO!`;
        logS3(`[+] SUCESSO! Combinação vulnerável encontrada.`, "vuln", FNAME_RUNNER);
        logS3(`    Offset Vencedor: ${result.details.offset}`, "vuln", FNAME_RUNNER);
        logS3(`    Valor Vencedor: ${result.details.value}`, "vuln", FNAME_RUNNER);
        logS3(`    Erro Desencadeado: "${result.details.error}"`, "vuln", FNAME_RUNNER);
    } else {
        document.title = `${FNAME_MODULE}: FALHA`;
        logS3(`[-] FALHA. Nenhuma combinação vulnerável óbvia foi encontrada com os parâmetros atuais.`, "error", FNAME_RUNNER);
        logS3("    Tente ajustar os 'corruption_offsets' e 'values_to_write' em 'testJsonTypeConfusionUAFSpeculative.mjs' e tente novamente.", "info", FNAME_RUNNER);
    }
}

/**
 * Função principal que inicializa o listener do botão para executar os testes avançados.
 */
export function initializeAdvancedTestRunner() {
    const FNAME_ORCHESTRATOR = `AdvancedTestOrchestrator`;
    const runBtn = getRunBtnAdvancedS3();

    if (!runBtn) {
        console.warn("Botão 'runAdvancedBtnS3' não encontrado. O runner avançado não será inicializado.");
        return;
    }

    runBtn.addEventListener('click', async () => {
        if (runBtn.disabled) return;
        
        const outputDiv = getOutputAdvancedS3();
        runBtn.disabled = true;
        if (outputDiv) outputDiv.innerHTML = '';

        logS3(`==== User Agent: ${navigator.userAgent} ====`, 'info', FNAME_ORCHESTRATOR);
        logS3(`==== INICIANDO Script (${FNAME_ORCHESTRATOR}) / Teste (${FNAME_MODULE}) ====`, 'test', FNAME_ORCHESTRATOR);

        await runSpeculativeUAFStrategy();
        
        logS3(`\n==== Script (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
        if (runBtn) runBtn.disabled = false;
    });

    logS3("Runner de Testes Avançados (S3) inicializado e pronto.", "info", FNAME_ORCHESTRATOR);
}
