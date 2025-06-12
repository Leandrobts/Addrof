// js/script3/runAllAdvancedTestsS3.mjs
// ATUALIZADO PARA EXECUTAR AS PROVAS DE CONCEITO (PoC) DE EXPLORAÇÃO

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3 } from '../dom_elements.mjs';

// --- IMPORTAÇÃO ATUALIZADA ---
// Importa a nova função que executa as PoCs de exploração.
import { runExploitationPoCs } from './testAdvancedPP.mjs';


/**
 * Orquestrador principal do Script 3, agora focado em executar as PoCs de exploração.
 */
export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = 'Exploitation_PoC_Runner';
    const runBtn = getRunBtnAdvancedS3();
    
    if (runBtn) {
        runBtn.disabled = true;
    }

    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}) ====`, 'test', FNAME_ORCHESTRATOR);
    logS3('Foco: Provas de Conceito de Exploração (Confusão de Tipos & Sequestro de Fluxo)', 'info', FNAME_ORCHESTRATOR);
    logS3('AVISO: Estes testes podem causar instabilidade ou travar o navegador.', 'warn', FNAME_ORCHESTRATOR);

    await PAUSE_S3(1000); // Pausa para o usuário ler os avisos

    try {
        // --- CHAMADA DA NOVA FUNÇÃO ---
        await runExploitationPoCs();

    } catch (error) {
        logS3(`ERRO CRÍTICO no orquestrador ao executar PoCs: ${error.message}`, 'critical', FNAME_ORCHESTRATOR);
        console.error("Erro capturado pelo orquestrador S3:", error);
    } finally {
        await PAUSE_S3(500);
        
        logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
        
        if (runBtn) {
            runBtn.disabled = false;
        }
    }
}
