// js/script3/runAllAdvancedTestsS3.mjs
// CORRIGIDO - Atualizado para importar e chamar a função correta.

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3 } from '../dom_elements.mjs';

// --- IMPORTAÇÃO CORRIGIDA ---
// O nome da função exportada de testBuildAddrof.mjs foi corrigido.
import { tryMemoryCorruptionCrash } from './testBuildAddrof.mjs';


/**
 * Orquestrador principal do Script 3, focado no ataque de corrupção para crash.
 */
export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = 'Memory_Corruption_Runner';
    const runBtn = getRunBtnAdvancedS3();
    
    if (runBtn) {
        runBtn.disabled = true;
    }

    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}) ====`, 'test', FNAME_ORCHESTRATOR);
    logS3('Foco: Crash por corrupção de memória (OOB Write).', 'info', FNAME_ORCHESTRATOR);
    logS3('Este teste tentará corromper o byteLength de um ArrayBuffer vizinho.', 'warn', FNAME_ORCHESTRATOR);

    await PAUSE_S3(2000); // Pausa para o usuário ler os avisos

    try {
        // --- CHAMADA DA FUNÇÃO CORRIGIDA ---
        await tryMemoryCorruptionCrash();

    } catch (error) {
        logS3(`ERRO CRÍTICO no orquestrador: ${error.message}`, 'critical', FNAME_ORCHESTRATOR);
        console.error("Erro capturado pelo orquestrador S3:", error);
    } finally {
        await PAUSE_S3(500);
        
        logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
        logS3(`Verifique se o navegador travou. Se não, o ataque foi mitigado.`, 'info', FNAME_ORCHESTRATOR);
        
        if (runBtn) {
            runBtn.disabled = false;
        }
    }
}
