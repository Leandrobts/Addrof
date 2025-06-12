// js/script3/runAllAdvancedTestsS3.mjs
// ATUALIZADO PARA TENTAR CONSTRUIR O PRIMITIVO 'addrof'

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3 } from '../dom_elements.mjs';

// --- IMPORTAÇÃO ATUALIZADA ---
import { tryBuildAddrofPrimitive } from './testBuildAddrof.mjs';


/**
 * Orquestrador principal do Script 3, focado na construção de 'addrof'.
 */
export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = 'Addrof_Builder_Runner';
    const runBtn = getRunBtnAdvancedS3();
    
    if (runBtn) {
        runBtn.disabled = true;
    }

    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}) ====`, 'test', FNAME_ORCHESTRATOR);
    logS3('Foco: Usar primitivo OOB R/W para construir uma função "addrof" (vazar endereço de objeto).', 'info', FNAME_ORCHESTRATOR);
    logS3('Este teste simula o próximo passo em uma exploração real.', 'warn', FNAME_ORCHESTRATOR);

    await PAUSE_S3(2000); // Pausa para o usuário ler os avisos

    try {
        await tryBuildAddrofPrimitive();

    } catch (error) {
        logS3(`ERRO CRÍTICO no orquestrador: ${error.message}`, 'critical', FNAME_ORCHESTRATOR);
        console.error("Erro capturado pelo orquestrador S3:", error);
    } finally {
        await PAUSE_S3(500);
        
        logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
        logS3(`O próximo passo seria usar o endereço vazado para criar um objeto falso (fakeobj).`, 'info', FNAME_ORCHESTRATOR);
        
        if (runBtn) {
            runBtn.disabled = false;
        }
    }
}
