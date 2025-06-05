// js/script3/runAllAdvancedTestsS3.mjs (Adaptado para Busca de Offset ABV - CORRIGIDO)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTypedArrayVictimAddrofAndWebKitLeak_R43,
    FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT
} from './testArrayBufferVictimCrash.mjs';

// Definir a constante que estava faltando no escopo do runner
const VICTIM_ARRAY_SIZE_ELEMENTS_DEFAULT_RUNNER = 8; // Deve ser igual ao valor no script de teste

// Função safeToHex também no runner para consistência de logs, se necessário para formatar oob_value_of_best_result
function safeToHexRunner(value, length = 8) {
    if (typeof value === 'number') {
        return '0x' + (value >>> 0).toString(16).padStart(length, '0');
    }
    if (value === null || value === undefined) {
        return String(value);
    }
    // Tentar extrair de strings como "0xOFFSET_0xVALUE"
    if (typeof value === 'string' && value.includes('_')) {
        return value; // Já está formatado ou é um identificador especial
    }
    // Adicione mais lógica de parsing se o toHex do utils.mjs for complexo
    return String(value);
}


async function runHeisenbugReproStrategy_TypedArrayVictim_R43() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_R43_OffsetSearchABV_Cor"; // Nome atualizado
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    const result = await executeTypedArrayVictimAddrofAndWebKitLeak_R43();

    const module_name_for_title = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT; // Nome do módulo do teste

    if (result.errorOccurred) {
        logS3(`  RUNNER R43(OffsetSearchCor): Teste principal capturou ERRO: ${String(result.errorOccurred)}`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: MainTest ERR!`;
    } else if (result) {
        let bestParamsMsg = 'N/A';
        if (result.oob_params_of_best_result_detailed) {
            bestParamsMsg = `Offset: ${result.oob_params_of_best_result_detailed.offset}, Valor: ${result.oob_params_of_best_result_detailed.value}`;
        } else if (result.oob_value_of_best_result) { // Fallback
             bestParamsMsg = `Melhor OOB (formato antigo/simplificado): ${result.oob_value_of_best_result}`;
        }

        logS3(`  RUNNER R43(OffsetSearchCor): Completou. Melhores Parâmetros OOB: ${bestParamsMsg}`, "good", FNAME_RUNNER);
        logS3(`  RUNNER R43(OffsetSearchCor): Detalhes Sonda TC (Best): ${result.tc_probe_details ? JSON.stringify(result.tc_probe_details) : 'N/A'}`, "leak_detail", FNAME_RUNNER);

        const heisenbugSuccessfullyDetected = result.heisenbug_on_M2_in_best_result;
        const abvCorruptionAnalysis = result.abv_corruption_details_best_result;

        logS3(`  RUNNER R43(OffsetSearchCor): Heisenbug TC Sonda (Best): ${heisenbugSuccessfullyDetected ? "CONFIRMADA" : "NÃO CONFIRMADA"}`, heisenbugSuccessfullyDetected ? "vuln_potential" : "warn", FNAME_RUNNER);

        if (abvCorruptionAnalysis) {
            logS3(`  RUNNER R43(OffsetSearchCor): Análise de Corrupção ABV (Melhor Iteração - Offset ${abvCorruptionAnalysis.offset_tested}):`, "info_emphasis", FNAME_RUNNER);
            logS3(`    Comprimento Original: ${abvCorruptionAnalysis.original_length}`, "info", FNAME_RUNNER);
            const lengthCorrupted = abvCorruptionAnalysis.reported_length_after_oob !== abvCorruptionAnalysis.original_length; // Usar original_length de abvCorruptionAnalysis
            logS3(`    Comprimento Pós-OOB: ${abvCorruptionAnalysis.reported_length_after_oob}`,
                lengthCorrupted ? "success_major" : "info", FNAME_RUNNER);
            logS3(`    ByteLength Pós-OOB: ${abvCorruptionAnalysis.reported_byteLength_after_oob}`, "info", FNAME_RUNNER);
            if (lengthCorrupted) {
                logS3(`    Leitura em Índice Alto OK: ${abvCorruptionAnalysis.read_high_index_ok}`, abvCorruptionAnalysis.read_high_index_ok ? "vuln" : "warn", FNAME_RUNNER);
                if (abvCorruptionAnalysis.read_high_index_ok) {
                    logS3(`    Valor Lido em Índice Alto: ${abvCorruptionAnalysis.read_extreme_index_value}`, "leak", FNAME_RUNNER);
                }
            }
            logS3(`    Padrão de Preenchimento Intacto: ${abvCorruptionAnalysis.fill_pattern_intact}`, abvCorruptionAnalysis.fill_pattern_intact ? "good" : "vuln_potential", FNAME_RUNNER);
            logS3(`    Notas da Análise ABV: ${abvCorruptionAnalysis.notes}`, "info", FNAME_RUNNER);
        } else {
            logS3(`  RUNNER R43(OffsetSearchCor): Detalhes da Análise de Corrupção ABV não disponíveis.`, "warn", FNAME_RUNNER);
        }

        if (result.addrof_result) { logS3(`  RUNNER R43(OffsetSearchCor): Teste Addrof: ${result.addrof_result.msg}`, "info", FNAME_RUNNER); }
        if (result.webkit_leak_result) { logS3(`  RUNNER R43(OffsetSearchCor): Teste WebKit Base Leak: ${result.webkit_leak_result.msg}`, "info", FNAME_RUNNER); }

        let finalTitleSegment = "No Notable Result";
        if (result.oob_params_of_best_result_detailed) {
            const best_params = result.oob_params_of_best_result_detailed;
            const best_abv_corr = result.abv_corruption_details_best_result;
            let parts = [];
            if (best_abv_corr?.reported_length_after_oob !== best_abv_corr?.original_length) parts.push("LenCORRUPT!");
            if (heisenbugSuccessfullyDetected) parts.push("TC_OK");
            if (parts.length > 0) finalTitleSegment = `Off ${best_params.offset}: ${parts.join(" ")}`;
            else finalTitleSegment = `Off ${best_params.offset}: No TC/Corruption`;
        }
        document.title = `${module_name_for_title}_R43_OffSearchCor: ${finalTitleSegment}`;


        if (result.iteration_results_summary && result.iteration_results_summary.length > 0) {
            logS3(`  RUNNER R43(OffsetSearchCor): Sumário completo das iterações:`, "info", FNAME_RUNNER);
            result.iteration_results_summary.forEach((iter_sum, index) => {
                const tcSuccess = iter_sum.heisenbug_on_M2_confirmed_by_tc_probe;
                // Corrigir a verificação de lengthCorrupted aqui usando original_length do sumário da iteração
                const lengthCorrupted = iter_sum.abv_corruption_details?.reported_length_after_oob !== iter_sum.abv_corruption_details?.original_length;
                let logMsg = `    Iter ${index + 1} (Offset ${iter_sum.oob_offset}): TC=${tcSuccess}, LengthCorrupt=${lengthCorrupted}`;
                if(iter_sum.error) logMsg += `, Err: ${iter_sum.error}`;
                logS3(logMsg, "info", FNAME_RUNNER);
            });
        }
    } else {
        document.title = `${module_name_for_title}_R43_OffSearchCor: Invalid Result Obj`;
    }
    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT}_MainOrchestrator_OffSearchCor`;
    logS3(`==== INICIANDO Script 3 R43_OffSearchCor (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    await runHeisenbugReproStrategy_TypedArrayVictim_R43();
    logS3(`\n==== Script 3 R43_OffSearchCor (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;

    if (document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT) &&
        !document.title.toUpperCase().includes("CORRUPT") && // Verificação case-insensitive
        !document.title.includes("OK") &&
        !document.title.includes("ERR") &&
        !document.title.includes("Invalid")) {
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT}_R43_OffSearchCor_Done`;
    }
}
