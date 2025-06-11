// js/script3/runAllAdvancedTestsS3.mjs

import { logS3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
// Importa o novo módulo de teste especulativo
import { testJsonTypeConfusionUAFSpeculative } from './testJsonTypeConfusionUAFSpeculative.mjs';

/**
 * Executa a nova estratégia de teste de Type Confusion/UAF especulativo.
 */
async function runSpeculativeUAFTestStrategy() {
    const FNAME_RUNNER = "runSpeculativeUAFTestStrategy";
    const moduleName = 'Teste Especulativo UAF/TC via JSON';
    logS3(`==== INICIANDO Estratégia de Teste (${moduleName}) ====`, 'test', FNAME_RUNNER);
    document.title = `Iniciando ${moduleName}...`;

    try {
        // A chamada agora é para o teste de Type Confusion especulativo
        await testJsonTypeConfusionUAFSpeculative();
        
        // Como o teste invocado já loga seus próprios resultados detalhados,
        // apenas informamos que a execução terminou.
        logS3(`==== RESULTADO FINAL (${moduleName}): Teste executado. Verifique os logs acima para detalhes.`, 'good', FNAME_RUNNER);
        document.title = `${moduleName} Concluído`;

    } catch (e) {
        // Captura de erro genérica para o caso de o teste falhar catastroficamente
        logS3(`ERRO CRÍTICO IRRECUPERÁVEL durante a execução do teste: ${e.name} - ${e.message}`, "critical", FNAME_RUNNER);
        logS3("   -> Isso pode indicar um erro de programação ou uma falha inesperada no motor JS.", "error", FNAME_RUNNER);
        console.error("Erro capturado em runSpeculativeUAFTestStrategy:", e);
        document.title = `${moduleName} - ERRO CRÍTICO`;
    }

    logS3(`==== Estratégia de Teste (${moduleName}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
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

        const moduleName = 'Teste Especulativo UAF/TC via JSON';
        logS3(`==== User Agent: ${navigator.userAgent} ====`, 'info', FNAME_ORCHESTRATOR);
        logS3(`==== INICIANDO Script (${FNAME_ORCHESTRATOR}) / Teste (${moduleName}) ====`, 'test', FNAME_ORCHESTRATOR);

        // Chama a função de estratégia de teste atualizada
        await runSpeculativeUAFTestStrategy();
        
        logS3(`\n==== Script (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
        if (runBtn) runBtn.disabled = false;

        if (document.title.startsWith("Iniciando")) {
            document.title = `${moduleName} Teste Finalizado`;
        }
    });

    logS3("Runner de Testes Avançados (S3) inicializado e pronto.", "info", FNAME_ORCHESTRATOR);
}
