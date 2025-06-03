// js/script3/testArrayBufferVictimCrash.mjs (v75_VerifyConfigConstants)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
// Não importaremos o core_exploit para este teste simples de config
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V75_VCC = "OriginalHeisenbug_TypedArrayAddrof_v75_VerifyConfigConstants";

let probe_call_count_v75 = 0;
let all_probe_interaction_details_v75 = [];

functiontoJSON_TA_Probe_Placeholder_v75() {
    probe_call_count_v75++;
    const call_num = probe_call_count_v75;
    const this_obj_type = Object.prototype.toString.call(this);
    let current_call_details = { /* ... */ };
    all_probe_interaction_details_v75.push(current_call_details);
    return { call_num_processed: call_num, type: this_obj_type };
}

export async function executeTypedArrayVictimAddrofTest_VerifyConfigConstants() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V75_VCC}.triggerAndLog`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Verificando constantes de config.mjs ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V75_VCC} Init...`;

    probe_call_count_v75 = 0;
    all_probe_interaction_details_v75 = [];
    let collected_probe_details_for_return = [];

    let config_check_result = {
        success: false,
        struct_id_str_type: "N/A",
        struct_id_str_val: "N/A",
        butterfly_str_type: "N/A",
        butterfly_str_val: "N/A",
        adv64_struct_id: "N/A",
        adv64_butterfly: "N/A",
        message: "Verificação de Config: Default (v75)"
    };

    try {
        logS3(`  DEBUG: Verificando JSC_OFFSETS importado...`, "debug", FNAME_CURRENT_TEST);
        if (typeof JSC_OFFSETS !== 'object' || JSC_OFFSETS === null) {
            throw new Error("JSC_OFFSETS não é um objeto ou é null.");
        }
        logS3(`  DEBUG: JSC_OFFSETS.Structure existe? ${!!JSC_OFFSETS.Structure}`, "debug", FNAME_CURRENT_TEST);
        logS3(`  DEBUG: JSC_OFFSETS.ArrayBuffer existe? ${!!JSC_OFFSETS.ArrayBuffer}`, "debug", FNAME_CURRENT_TEST);

        const struct_id_str = JSC_OFFSETS.Structure?.GENERIC_OBJECT_FAKE_ID_VALUE_FOR_CONFUSION;
        const butterfly_str = JSC_OFFSETS.ArrayBuffer?.BUTTERFLY_OR_DATA_FAKE_VALUE_FOR_CONFUSION;

        config_check_result.struct_id_str_val = String(struct_id_str);
        config_check_result.struct_id_str_type = typeof struct_id_str;
        config_check_result.butterfly_str_val = String(butterfly_str);
        config_check_result.butterfly_str_type = typeof butterfly_str;

        logS3(`  CONFIG CHECK: FAKE_STRUCTURE_ID_VAL_STR = '${struct_id_str}' (type: ${typeof struct_id_str})`, "info", FNAME_CURRENT_TEST);
        logS3(`  CONFIG CHECK: FAKE_BUTTERFLY_DATA_VAL_STR = '${butterfly_str}' (type: ${typeof butterfly_str})`, "info", FNAME_CURRENT_TEST);

        if (typeof struct_id_str !== 'string' || typeof butterfly_str !== 'string') {
            config_check_result.message = "V75 FALHA: Constantes FAKE_* não são strings ou são undefined.";
            logS3(config_check_result.message, "error", FNAME_CURRENT_TEST);
            config_check_result.success = false;
        } else {
            logS3(`  CONFIG CHECK: Tentando instanciar AdvancedInt64 com as strings...`, "info", FNAME_CURRENT_TEST);
            try {
                let adv_struct = new AdvancedInt64(struct_id_str);
                config_check_result.adv64_struct_id = adv_struct.toString(true);
                logS3(`    AdvancedInt64 from Structure ID string: ${config_check_result.adv64_struct_id}`, "good", FNAME_CURRENT_TEST);

                let adv_butterfly = new AdvancedInt64(butterfly_str);
                config_check_result.adv64_butterfly = adv_butterfly.toString(true);
                logS3(`    AdvancedInt64 from Butterfly string: ${config_check_result.adv64_butterfly}`, "good", FNAME_CURRENT_TEST);

                config_check_result.message = "V75 SUCESSO: Constantes FAKE_* carregadas como string e parseadas por AdvancedInt64.";
                config_check_result.success = true;
                logS3(config_check_result.message, "good", FNAME_CURRENT_TEST);

            } catch (e_adv64) {
                config_check_result.message = `V75 FALHA: Erro ao instanciar AdvancedInt64: ${e_adv64.message}. Strings usadas: Struct='${struct_id_str}', Butterfly='${butterfly_str}'`;
                logS3(config_check_result.message, "error", FNAME_CURRENT_TEST);
                config_check_result.success = false;
                config_check_result.adv64_struct_id = `Error: ${e_adv64.message}`;
                config_check_result.adv64_butterfly = `Error: ${e_adv64.message}`;
            }
        }

        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V75_VCC}: ${config_check_result.success ? 'Config OK' : 'Config FAIL'}`;

    } catch (e_main) {
        config_check_result.message = `V75 ERRO CRÍTICO no teste: ${e_main.message}`;
        logS3(config_check_result.message, "critical", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V75_VCC}: Test CRIT_ERR`;
        config_check_result.success = false; // Garantir que está como falha
    } finally {
        // Copiar all_probe_interaction_details_v75 ANTES de limpar para o runner
        if (all_probe_interaction_details_v75 && Array.isArray(all_probe_interaction_details_v75)) {
            collected_probe_details_for_return = all_probe_interaction_details_v75.map(d => (d && typeof d === 'object' ? {...d} : d));
        } else {
            collected_probe_details_for_return = [];
        }
        logS3(`--- ${FNAME_CURRENT_TEST} Completed ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Config Check Result: Success=${config_check_result.success}, Msg='${config_check_result.message}'`, config_check_result.success ? "good" : "error", FNAME_CURRENT_TEST);
    }

    return {
        // Para manter a estrutura esperada pelo runner, mesmo que este teste seja diferente
        errorCapturedMain: !config_check_result.success ? new Error(config_check_result.message) : null,
        stringifyResult: config_check_result, // Retorna o objeto de resultado da verificação
        rawStringifyForAnalysis: null,
        all_probe_calls_for_analysis: collected_probe_details_for_return, // Sonda placeholder, será vazio ou com poucas chamadas
        total_probe_calls: probe_call_count_v75,
        // Simular resultados de addrof para o runner não quebrar
        addrof_A_result: { success: config_check_result.success, msg: config_check_result.message },
        addrof_B_result: { success: true, msg: "N/A for v75 config check" }
    };
};
