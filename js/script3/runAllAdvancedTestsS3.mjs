// js/script3/runAllAdvancedTestsS3.mjs
// ATUALIZADO PARA EXECUTAR OS TESTES MASSIVOS DE STRESS

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3 } from '../dom_elements.mjs';

// --- IMPORTAÇÃO ATUALIZADA ---
// Importa a nova função que executa os testes massivos.
import { runMassiveStressTests } from './testAdvancedPP.mjs';


/**
 * Orquestrador principal do Script 3, agora focado em executar os testes massivos.
 */
export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = 'Massive_Stress_Test_Runner';
    const runBtn = getRunBtnAdvancedS3();
    
    if (runBtn) {
        runBtn.disabled = true;
    }

    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}) ====`, 'test', FNAME_ORCHESTRATOR);
    logS3('Foco: Testes Massivos de Stress (GC Churn & DOM APIs) com Hijack de "call"', 'info', FNAME_ORCHESTRATOR);
    logS3('AVISO: Estes testes são INTENSIVOS e podem congelar ou travar o navegador. Seja paciente.', 'critical', FNAME_ORCHESTRATOR);

    await PAUSE_S3(2000); // Pausa para o usuário ler os avisos

    try {
        // --- CHAMADA DA NOVA FUNÇÃO ---
        await runMassiveStressTests();

    } catch (error) {
        logS3(`ERRO CRÍTICO no orquestrador ao executar Stress Tests: ${error.message}`, 'critical', FNAME_ORCHESTRATOR);
        console.error("Erro capturado pelo orquestrador S3:", error);
    } finally {
        await PAUSE_S3(500);
        
        logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
        logS3(`Se o navegador não travou, tente aumentar o valor de STRESS_ITERATIONS no script de teste.`, 'info', FNAME_ORCHESTRATOR);
        
        if (runBtn) {
            runBtn.disabled = false;
        }
    }
}
