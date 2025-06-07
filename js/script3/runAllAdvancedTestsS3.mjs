// js/script3/runAllAdvancedTestsS3.mjs

import { logS3 } from './s3_utils.mjs';
import { testOOBBoundaryCondition } from './testArrayBufferVictimCrash.mjs';

/**
 * Função principal para executar os testes avançados de exploração.
 */
async function runTests() {
    logS3("=============================================", "title");
    logS3("🚀 INICIANDO SUÍTE DE TESTES AVANÇADOS (S3) 🚀", "title");
    logS3("=============================================", "title");

    let allTestsPassed = true;

    try {
        // Executa o novo teste de condição de limite
        const boundaryTestResult = await testOOBBoundaryCondition();
        if (!boundaryTestResult) {
            allTestsPassed = false;
        }

        // Você pode adicionar a chamada ao seu teste original aqui se desejar
        // logS3("--- Próximo teste: Varredura de Memória ---", "test");
        // await executeArrayBufferVictimCrashTest();

    } catch (e) {
        logS3(`🚨 ERRO INESPERADO NA SUÍTE DE TESTES: ${e.message}`, "critical", "runTests");
        allTestsPassed = false;
    } finally {
        logS3("=============================================", "title");
        if (allTestsPassed) {
            logS3("✅ Suíte de testes concluída com SUCESSO.", "good", "runTests");
        } else {
            logS3("❌ Suíte de testes concluída com FALHAS.", "critical", "runTests");
        }
        logS3("=============================================", "title");
    }
}

// Inicia a execução dos testes
runTests();
