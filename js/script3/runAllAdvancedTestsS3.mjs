// js/script3/runAllAdvancedTestsS3.mjs

import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { 
    executeArrayBufferVictimCrashTest,
    FNAME_MODULE_V28 
} from './testArrayBufferVictimCrash.mjs';

/**
 * Executa a estratégia principal do teste, agora com tratamento de exceções.
 */
async function runHeisenbugReproStrategy_ABVictim() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_ABVictim";
    const moduleName = FNAME_MODULE_V28 || 'Teste Avançado';
    logS3(`==== INICIANDO Estratégia de Teste (${moduleName}) ====`, 'test', FNAME_RUNNER);
    document.title = `Iniciando ${moduleName}...`;

    let result;
    try {
        // A chamada crítica que pode lançar uma exceção (como ReferenceError)
        result = await executeArrayBufferVictimCrashTest();
    } catch (e) {
        logS3(`ERRO CRÍTICO IRRECUPERÁVEL durante a execução do teste: ${e.name} - ${e.message}`, "critical", FNAME_RUNNER);
        logS3("   -> Isso geralmente indica um erro de programação (como uma variável não definida) dentro do módulo de teste importado.", "error", FNAME_RUNNER);
        console.error("Erro capturado em runHeisenbugReproStrategy_ABVictim:", e);
        
        // Simula um objeto de resultado de erro para que o resto da função possa lidar com ele
        result = {
            errorOccurred: { name: e.name, message: e.message },
            toJSON_details: null,
            addrof_attempt_result: null
        };
    }

    // O restante da lógica para processar o objeto 'result' permanece o mesmo.
    // Esta parte agora funcionará mesmo que a função de teste falhe catastroficamente.
    let finalLogMessage = "Resultado do teste não determinado.";
    let finalLogType = "info";
    let finalDocumentTitle = `${moduleName} Concluído`;

    if (result.errorOccurred) {
        finalLogMessage = `ERRO JS CAPTURADO: ${result.errorOccurred.name} - ${result.errorOccurred.message}.`;
        finalLogType = "error";
        finalDocumentTitle = `${moduleName} ERR JS: ${result.errorOccurred.name}`;
    } else if (result.addrof_attempt_result) {
        const addrofRes = result.addrof_attempt_result;
        finalLogMessage = `Resultado Addrof: ${addrofRes.message || "Mensagem não especificada."}`;
        if (addrofRes.success) {
            finalLogType = "good";
            finalDocumentTitle = `${moduleName} Addrof PARECE OK!`;
        } else {
            finalLogType = "warn";
            finalDocumentTitle = `${moduleName} Addrof FALHOU`;
        }
    } else {
        finalLogMessage = "Estrutura de resultado (addrof_attempt_result) não encontrada no retorno.";
        finalLogType = "error";
        finalDocumentTitle = `${moduleName} Concluído (Res. Ausente)`;
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

        const moduleName = FNAME_MODULE_V28 || 'Teste Avançado';
        logS3(`==== User Agent: ${navigator.userAgent} ====`, 'info', FNAME_ORCHESTRATOR);
        logS3(`==== INICIANDO Script (${FNAME_ORCHESTRATOR}) / Teste (${moduleName}) ====`, 'test', FNAME_ORCHESTRATOR);

        await runHeisenbugReproStrategy_ABVictim();
        
        logS3(`\n==== Script (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
        if (runBtn) runBtn.disabled = false;

        if (document.title.startsWith("Iniciando")) {
            document.title = `${moduleName} Teste Finalizado`;
        }
    });

    logS3("Runner de Testes Avançados (S3) inicializado e pronto.", "info", FNAME_ORCHESTRATOR);
}
