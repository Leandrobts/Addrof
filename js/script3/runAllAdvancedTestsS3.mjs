// js/script3/runAllAdvancedTestsS3.mjs (Runner para Testes Massivos Finais CORRIGIDO)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTypedArrayVictimAddrofAndWebKitLeak_R43,
    FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT
} from './testArrayBufferVictimCrash.mjs';

function safeToHexRunner(value, length = 8) { /* ... (como na versão anterior) ... */
    if (typeof value === 'number') { return '0x' + (value >>> 0).toString(16).padStart(length, '0'); }
    if (value === null || value === undefined) { return String(value); }
    if (typeof value === 'string' && value.startsWith('0x')) { return value; }
    return String(value);
}

async function runHeisenbugReproStrategy_TypedArrayVictim_R43_MassiveFinalCor() { // Nome da função do runner atualizado
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArray_R43_MassiveFinalCor"; // Nome do runner atualizado
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    
    const result = await executeTypedArrayVictimAddrofAndWebKitLeak_R43();

    const module_name_for_title = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;

    if (result.errorOccurred && !result.oob_params_of_best_result) {
        logS3(`  RUNNER R43(MassiveFinalCor): Teste principal capturou ERRO: ${String(result.errorOccurred)}`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: MainTest ERR!`;
    } else if (result) {
        logS3(`  RUNNER R43(MassiveFinalCor): Teste principal completado. Analisando resultados...`, "good", FNAME_RUNNER);

        logS3(`  --- MELHOR RESULTADO GERAL ENCONTRADO ---`, "info_emphasis", FNAME_RUNNER);
        let bestParamsMsg = 'N/A';
        if (result.oob_params_of_best_result) {
            bestParamsMsg = `Offset: ${result.oob_params_of_best_result.offset}, Valor: ${result.oob_params_of_best_result.value} (RawOff: ${safeToHexRunner(result.oob_params_of_best_result.raw_offset)}, RawVal: ${safeToHexRunner(result.oob_params_of_best_result.raw_value)})`;
        }
        logS3(`    Melhores Parâmetros OOB: ${bestParamsMsg}`, "info", FNAME_RUNNER);
        
        // CORRIGIDO: Usar result.heisenbug_on_M2_confirmed_by_tc_probe que está no objeto 'result' principal
        const heisenbugInBest = result.heisenbug_on_M2_confirmed_by_tc_probe;
        logS3(`    TC Confirmada no Melhor Resultado: ${heisenbugInBest}`, heisenbugInBest ? "vuln" : "info", FNAME_RUNNER);
        if (result.tc_probe_details) {
            logS3(`    Detalhes Sonda TC (Melhor): ${JSON.stringify(result.tc_probe_details)}`, "leak_detail", FNAME_RUNNER);
        }

        if (result.best_victim_analysis) {
            const va = result.best_victim_analysis;
            logS3(`    Análise do Victim_TA (Melhor Iteração - Off ${va.offset_tested} Val ${va.value_written}):`, "info_emphasis", FNAME_RUNNER);
            logS3(`      Notas: ${va.notes}`, "info", FNAME_RUNNER);
            logS3(`      Addrof via Corrupção da Vítima: ${va.addrof_achieved_via_victim_corruption}`, va.addrof_achieved_via_victim_corruption ? "success_major" : "info", FNAME_RUNNER);
            if (va.found_pointers_in_victim_ta && va.found_pointers_in_victim_ta.length > 0) {
                logS3(`      Ponteiros Encontrados na Vítima:`, "leak", FNAME_RUNNER);
                va.found_pointers_in_victim_ta.slice(0, 5).forEach(p => {
                    logS3(`        Index ${p.index}: ${p.addr_str}`, "leak_detail");
                });
                if (va.found_pointers_in_victim_ta.length > 5) logS3("        ...", "leak_detail");
            }
        }

        if (result.addrof_result) {
             logS3(`    Resultado Addrof (Global): ${result.addrof_result.msg} (Endereço: ${result.addrof_result.leaked_object_addr || 'N/A'})`, result.addrof_result.success ? "success_major" : "warn", FNAME_RUNNER);
        }
        if (result.webkit_leak_result) {
            logS3(`    Resultado WebKitLeak (Global): ${result.webkit_leak_result.msg} (Base: ${result.webkit_leak_result.webkit_base_candidate || 'N/A'})`, result.webkit_leak_result.success ? "success_major" : "info", FNAME_RUNNER);
        }
        if (result.errorOccurred) {
             logS3(`    Erro no Melhor Resultado Reportado: ${result.errorOccurred}`, "error", FNAME_RUNNER);
        }


        if (result.iteration_results_summary && result.iteration_results_summary.length > 0) {
            logS3(`  --- SUMÁRIO DE TODAS AS ITERAÇÕES (${result.iteration_results_summary.length} testadas) ---`, "info_emphasis", FNAME_RUNNER);
            result.iteration_results_summary.forEach((iter_sum, index) => {
                let logMsg = `    Iter ${index + 1} (Off ${iter_sum.oob_offset} Val ${iter_sum.oob_value}): `;
                let highlights = [];
                if (iter_sum.heisenbug_on_M2_confirmed_by_tc_probe) highlights.push("TC_OK");
                if (iter_sum.victim_ta_analysis?.addrof_achieved_via_victim_corruption) highlights.push("ADDROF_VictimOK");
                // Adicionar mais flags de sucesso da iteração se necessário
                if (iter_sum.webkit_leak_success_this_iter) highlights.push("WKLeak_IterOK");
                                
                if (highlights.length > 0) { logMsg += highlights.join(", "); }
                else { logMsg += "Sem Efeitos Notáveis"; }
                if(iter_sum.error) logMsg += `, Err: ${iter_sum.error}`;
                
                let logLevel = "info";
                if (iter_sum.webkit_leak_success_this_iter || iter_sum.addrof_success_this_iter || iter_sum.victim_ta_analysis?.addrof_achieved_via_victim_corruption) logLevel = "success_major";
                else if (iter_sum.heisenbug_on_M2_confirmed_by_tc_probe) logLevel = "vuln";
                logS3(logMsg, logLevel, FNAME_RUNNER);
            });
        } else {
            logS3(`  Sumário de iterações não disponível ou vazio.`, "warn", FNAME_RUNNER);
        }
        
        // Título final da página (usando o título já definido pelo script de teste)
        document.title = document.title; // Apenas para garantir que não haja redefinição indesejada aqui

    } else {
        document.title = `${module_name_for_title}_R43_MassiveFinalCor: Invalid Result Obj`;
        logS3(`  RUNNER R43(MassiveFinalCor): Objeto de resultado inválido ou nulo recebido do teste.`, "critical", FNAME_RUNNER);
    }

    logS3(`  Título da página final (definido pelo teste): ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT}_MainOrchestrator_MassiveFinalCor`;
    logS3(`==== INICIANDO Script 3 R43_MassiveFinalCor (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    await runHeisenbugReproStrategy_TypedArrayVictim_R43_MassiveFinalCor();
    
    logS3(`\n==== Script 3 R43_MassiveFinalCor (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;

    if (document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT) &&
        !document.title.includes("Final:") && 
        !document.title.toUpperCase().includes("OK") &&
        !document.title.toUpperCase().includes("SUCCESS") &&
        !document.title.includes("ERR") && 
        !document.title.includes("Invalid")) {
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT}_R43_MassiveFinalCor_Done`;
    }
}
