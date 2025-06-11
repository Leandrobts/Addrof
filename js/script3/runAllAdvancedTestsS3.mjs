// js/script3/runAllAdvancedTestsS3.mjs

import { logS3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';

// Importa o novo módulo de teste de Type Confusion via JSON.
import { testJsonTypeConfusionUAFSpeculative } from './testJsonTypeConfusionUAFSpeculative.mjs';

// Define um nome para o novo módulo para ser usado nos logs e títulos.
const FNAME_MODULE_S3 = "JSON Type Confusion Speculative Test";

/**
 * Executa a estratégia de teste de Type Confusion via JSON.
 * Esta função chama o teste e processa o resultado booleano.
 */
async function runJsonUAFSpeculativeStrategy() {
    const FNAME_RUNNER = "runJsonUAFSpeculativeStrategy";
    const moduleName = FNAME_MODULE_S3;
    logS3(`==== INICIANDO Estratégia de Teste (${moduleName}) ====`, 'test', FNAME_RUNNER);
    document.title = `Iniciando ${moduleName}...`;

    let wasSuccessful;
    try {
        // Chama a função de teste.
        // É esperado que 'testJsonTypeConfusionUAFSpeculative' retorne 'true' se
        // um erro/vulnerabilidade foi detectado, e 'false' caso contrário.
        wasSuccessful = await testJsonTypeConfusionUAFSpeculative();

    } catch (e) {
        logS3(`ERRO CRÍTICO IRRECUPERÁVEL durante a execução do teste: ${e.name} - ${e.message}`, "critical", FNAME_RUNNER);
        logS3("   -> Isso pode indicar um erro de programação no módulo de teste ou um crash não capturado.", "error", FNAME_RUNNER);
        console.error("Erro capturado em runJsonUAFSpeculativeStrategy:", e);
        
        // Se um erro catastrófico que não foi pego internamente ocorrer,
        // consideramos a tentativa como "sucedida" em causar instabilidade.
        wasSuccessful = true;
    }

    // Lógica de resultado simplificada para lidar com o retorno booleano.
    let finalLogMessage;
    let finalLogType;
    let finalDocumentTitle;

    if (wasSuccessful) {
        finalLogMessage = `VULNERABILIDADE POTENCIAL DETECTADA! O teste especulativo encontrou uma condição de erro (UAF/Type Confusion). Verifique os logs acima para o offset e valor que causaram o problema.`;
        finalLogType = "vuln"; // 'vuln' é um tipo de log customizado para vulnerabilidades.
        finalDocumentTitle = `${moduleName} - SUCESSO!`;
    } else {
        finalLogMessage = "O teste foi concluído sem detectar erros explícitos de UAF/Type Confusion.";
        finalLogType = "info";
        finalDocumentTitle = `${moduleName} - Concluído (Sem Falhas)`;
    }

    logS3(`==== RESULTADO FINAL (${moduleName}): ${finalLogMessage}`, finalLogType, FNAME_RUNNER);
    document.title = finalDocumentTitle;
    logS3(`==== Estratégia de Teste (${moduleName}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

/**
 * Função principal que inicializa o listener do botão para executar os testes avançados.
 * Você pode chamar esta função a partir do seu script principal (main.mjs).
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

        const moduleName = FNAME_MODULE_S3;
        logS3(`==== User Agent: ${navigator.userAgent} ====`, 'info', FNAME_ORCHESTRATOR);
        logS3(`==== INICIANDO Script (${FNAME_ORCHESTRATOR}) / Teste (${moduleName}) ====`, 'test', FNAME_ORCHESTRATOR);

        // Chama a nova função runner que executa o teste de JSON.
        await runJsonUAFSpeculativeStrategy();
        
        logS3(`\n==== Script (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
        if (runBtn) runBtn.disabled = false;

        if (document.title.startsWith("Iniciando")) {
            document.title = `${moduleName} Teste Finalizado`;
        }
    });

    logS3("Runner de Testes Avançados (S3) inicializado e pronto.", "info", FNAME_ORCHESTRATOR);
}
