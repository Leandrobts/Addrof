// NOME DO ARQUIVO: runJsonRecursionTest.mjs

import { executeJsonRecursionTest, FNAME_MODULE_JSON_RECURSION } from './testJsonRecursionCrash.mjs';

// Função de log simples para a interface
const logToDiv = (message, type = 'info') => {
    const outputDiv = document.getElementById('output');
    if (outputDiv) {
        const timestamp = `[${new Date().toLocaleTimeString()}]`;
        const logClass = type;
        outputDiv.innerHTML += `<span class="log-${logClass}">${timestamp} ${String(message).replace(/</g, "&lt;")}\n</span>`;
        outputDiv.scrollTop = outputDiv.scrollHeight;
    }
};

/**
 * Runner que gerencia a execução do teste e a UI.
 */
export async function runJsonRecursionTestRunner() {
    const runBtn = document.getElementById('runBtn');
    if (runBtn) runBtn.disabled = true;

    // Limpa o log da tela
    const outputDiv = document.getElementById('output');
    if (outputDiv) outputDiv.innerHTML = '';

    logToDiv(`==== INICIANDO TESTE: ${FNAME_MODULE_JSON_RECURSION} ====`, 'test');
    logToDiv("O objetivo é replicar o crash/lentidão. Foco no console do navegador (F12)!", 'warn');

    try {
        const result = await executeJsonRecursionTest();

        // Análise do resultado
        if (result.errorCaptured) {
            logToDiv(`ERRO DE SCRIPT CAPTURADO: ${result.errorCaptured}`, 'critical');
            document.title = "JSON Bug: Erro Capturado!";
        } else if (result.didComplete) {
            logToDiv(`TESTE CONCLUÍDO INESPERADAMENTE. Profundidade final: ${result.finalCallCount}.`, 'warn');
            document.title = "JSON Bug: Não Crashou";
        } else {
             logToDiv(`TESTE FINALIZADO. Profundidade final: ${result.finalCallCount}. Verifique o console para crash/lentidão.`, 'good');
             document.title = "JSON Bug: Teste Finalizado";
        }

    } catch (e) {
        // Erro inesperado no próprio runner
        logToDiv(`ERRO CRÍTICO NO RUNNER: ${e.message}`, 'critical');
        console.error("ERRO CRÍTICO NO RUNNER:", e);
        document.title = "JSON Bug: Erro no Runner";
    } finally {
        logToDiv("Runner concluído.", 'test');
        if (runBtn) runBtn.disabled = false;
    }
}
