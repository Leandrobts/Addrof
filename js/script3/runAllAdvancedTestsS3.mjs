// js/script3/runAllAdvancedTestsS3.mjs
// MODIFICADO PARA ISOLAR E EXECUTAR APENAS O TESTE DE PROTOTYPE POLLUTION AVANÇADO.

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3 } from '../dom_elements.mjs';

// --- IMPORTAÇÃO CORRETA ---
// Importa diretamente a função de teste de PP Avançado do Script 2.
// A lógica anterior de Type Confusion foi removida.
import { testAdvancedPPS2 } from '../script2/testAdvancedPP.mjs';


/**
 * Orquestrador principal do Script 3, agora focado em executar o teste
 * isolado de Prototype Pollution Avançado.
 */
export async function runAllAdvancedTestsS3() {
    // Nome do orquestrador para os logs, refletindo a nova função
    const FNAME_ORCHESTRATOR = 'AdvancedPP_Isolated_Runner';
    const runBtn = getRunBtnAdvancedS3();
    if (runBtn) {
        runBtn.disabled = true;
    }

    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}) ====`, 'test', FNAME_ORCHESTRATOR);
    logS3('Foco: Teste de Prototype Pollution Avançado (testAdvancedPPS2)', 'info', FNAME_ORCHESTRATOR);

    // Pausa breve para o usuário ler o que está acontecendo
    await PAUSE_S3(250);

    try {
        // --- CHAMADA DA FUNÇÃO VERIFICADA ---
        // A função testAdvancedPPS2 é chamada diretamente aqui.
        // Ela usará suas próprias funções de log (logS2), que é o comportamento esperado.
        await testAdvancedPPS2();

    } catch (error) {
        logS3(`ERRO CRÍTICO no orquestrador ao chamar testAdvancedPPS2: ${error.message}`, 'critical', FNAME_ORCHESTRATOR);
        console.error("Erro capturado pelo orquestrador S3:", error);
    } finally {
        // Pausa breve no final antes de reativar o botão.
        await PAUSE_S3(500);
        
        logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
        
        if (runBtn) {
            runBtn.disabled = false;
        }
    }
}
