// js/script3/runAllAdvancedTestsS3.mjs

import { logS3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';

// --- ALTERADO: Importa o novo módulo de teste ---
// Removemos a importação de 'testArrayBufferVictimCrash.mjs'.
import { testJsonTypeConfusionUAFSpeculative } from './testJsonTypeConfusionUAFSpeculative.mjs';

// --- ALTERADO: Define um nome para o novo módulo para ser usado nos logs ---
const FNAME_MODULE_S3 = "JSON Type Confusion Speculative Test";

/**
 * // ALTERADO: Renomeado e adaptado para executar o novo teste.
 * Executa a estratégia de teste de Type Confusion via JSON.
 */
async function runJsonUAFSpeculativeStrategy() {
    const FNAME_RUNNER = "runJsonUAFSpeculativeStrategy";
    const moduleName = FNAME_MODULE_S3;
    logS3(`==== INICIANDO Estratégia de Teste (${moduleName}) ====`, 'test', FNAME_RUNNER);
    document.title = `Iniciando ${moduleName}...`;

    let wasSuccessful;
    try {
        // --- ALTERADO: Chama a nova função de teste ---
        // A função agora deve retornar um booleano indicando o sucesso geral.
        // É recomendado modificar 'testJsonTypeConfusionUAFSpeculative' para que ela retorne a variável 'overallTestSuccess'.
        wasSuccessful = await testJsonTypeConfusionUAFSpeculative();

    } catch (e) {
        logS3(`ERRO CRÍTICO IRRECUPERÁVEL durante a execução do teste: ${e.name} - ${e.message}`, "critical", FNAME_RUNNER);
        logS3("   -> Isso pode indicar um erro de programação no módulo de teste ou um crash não capturado.", "error", FNAME_RUNNER);
        console.error("Erro capturado em runJsonUAFSpeculativeStrategy:", e);
        
        // Se um erro catastrófico ocorrer, consideramos a tentativa de exploração como "sucedida" em causar instabilidade.
        wasSuccessful = true;
    }

    // --- ALTERADO: Lógica de resultado simplificada para lidar com um booleano ---
    let finalLogMessage;
    let finalLogType;
    let finalDocumentTitle;

    if (wasSuccessful) {
        finalLogMessage = `VULNERABILIDADE POTENCIAL DETECTADA! O teste especulativo encontrou uma condição de erro (UAF/Type Confusion). Verifique os logs acima para o offset e valor que causaram o problema.`;
        finalLogType = "vuln"; // 'vuln' é um tipo de log personalizado para vulnerabilidades
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

        const moduleName = FNAME_MODULE_S3; // ALTERADO: Usa a nova constante de nome de módulo
        logS3(`==== User Agent: ${navigator.userAgent} ====`, 'info', FNAME_ORCHESTRATOR);
        logS3(`==== INICIANDO Script (${FNAME_ORCHESTRATOR}) / Teste (${moduleName}) ====`, 'test', FNAME_ORCHESTRATOR);

        // --- ALTERADO: Chama a nova função runner ---
        await runJsonUAFSpeculativeStrategy();
        
        logS3(`\n==== Script (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
        if (runBtn) runBtn.disabled = false;

        if (document.title.startsWith("Iniciando")) {
            document.title = `${moduleName} Teste Finalizado`;
        }
    });

    logS3("Runner de Testes Avançados (S3) inicializado e pronto.", "info", FNAME_ORCHESTRATOR);
}
