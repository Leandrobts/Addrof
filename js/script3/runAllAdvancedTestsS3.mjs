// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para Revisado 50 - Dumper Interativo)

import { logS3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3 } from '../dom_elements.mjs'; // Botão antigo não é mais usado aqui
import {
    executeMemoryDump_R50,
    FNAME_MODULE_MEMORY_DUMPER_R50
} from './testArrayBufferVictimCrash.mjs';

function setupMemoryDumperListener() {
    const FNAME_SETUP = "setupMemoryDumperListener";
    const runBtn = document.getElementById('runDumperBtn');
    const startAddrEl = document.getElementById('startAddr');
    const dumpSizeEl = document.getElementById('dumpSize');
    const outputEl = document.getElementById('dumpOutput');

    if (!runBtn || !startAddrEl || !dumpSizeEl || !outputEl) {
        logS3(`[${FNAME_SETUP}] ERRO: Elementos da UI do dumper não encontrados.`, "critical");
        return;
    }

    runBtn.addEventListener('click', async () => {
        runBtn.disabled = true;
        outputEl.textContent = "Preparando...";
        try {
            await executeMemoryDump_R50(startAddrEl.value, dumpSizeEl.value, outputEl);
        } catch (e) {
            outputEl.textContent += `\n\nERRO INESPERADO: ${e.message}`;
        } finally {
            runBtn.disabled = false;
        }
    });

    logS3(`[${FNAME_SETUP}] Ouvinte de eventos para o dumper de memória configurado.`, "good");
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_MEMORY_DUMPER_R50}_MainOrchestrator`;
    logS3(`==== INICIANDO Script 3 R50 (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    // Em vez de executar um teste, agora configuramos a interface do usuário.
    setupMemoryDumperListener();
    
    logS3(`\n==== Script 3 R50 (${FNAME_ORCHESTRATOR}) CONCLUÍDO e PRONTO PARA USO ====`, 'test', FNAME_ORCHESTRATOR);
    // Habilita o botão antigo, caso ainda exista na página.
    const oldRunBtn = getRunBtnAdvancedS3();
    if (oldRunBtn) oldRunBtn.disabled = false;
}
