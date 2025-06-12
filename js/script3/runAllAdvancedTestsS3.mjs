// js/script3/runAdvancedPP_isolated.mjs
// Orquestrador dedicado para executar APENAS o teste de PP Avançado (testAdvancedPPS2).

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3 } from '../dom_elements.mjs';

// --- IMPORTAÇÃO CHAVE ---
// Importa a função de teste específica do diretório do script 2.
import { testAdvancedPPS2 } from '../script2/testAdvancedPP.mjs';

/**
 * Orquestrador isolado para rodar o teste de Prototype Pollution Avançado.
 */
export async function runIsolatedAdvancedPPTest() {
    const FNAME_ORCHESTRATOR = `AdvancedPP_Isolated_Orchestrator`;
    const runBtn = getRunBtnAdvancedS3();
    if (runBtn) runBtn.disabled = true;

    logS3(`==== INICIANDO Teste Isolado de PP Avançado (${FNAME_ORCHESTRATOR}) ====`, 'test', FNAME_ORCHESTRATOR);
    
    // --- EXECUÇÃO DO TESTE ---
    // Chama diretamente a função de teste importada.
    // Os logs específicos do teste (logS2) continuarão funcionando normalmente.
    await testAdvancedPPS2();
    
    await PAUSE_S3(500); // Uma pequena pausa antes de finalizar.
    logS3(`\n==== Teste Isolado de PP Avançado (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    
    if (runBtn) runBtn.disabled = false;
}
