// js/script3/runAllAdvancedTestsS3.mjs (Runner para Addrof via ArbRead Scan)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTypedArrayVictimAddrofAndWebKitLeak_R43,
    FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT
} from './testArrayBufferVictimCrash.mjs';

function safeToHexRunner(value, length = 8) { /* ... (como antes) ... */ }

async function runHeisenbugReproStrategy_TypedArrayVictim_R43_ArbReadScan() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_R43_ArbReadScan";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    
    const result = await executeTypedArrayVictimAddrofAndWebKitLeak_R43();
    const module_name_for_title = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;

    if (result.errorOccurred && !result.oob_params_of_best_result) { /* ... (log de erro) ... */ }
    else if (result) {
        logS3(`  RUNNER R43(ArbReadScan): Teste completado. Analisando...`, "good", FNAME_RUNNER);
        logS3(`  --- MELHOR RESULTADO GERAL ---`, "info_emphasis", FNAME_RUNNER);
        let bestParamsMsg = 'N/A';
        if (result.oob_params_of_best_result) { /* ... (logar params) ... */ }
        logS3(`    Melhores Parâmetros OOB: ${bestParamsMsg}`, "info", FNAME_RUNNER);
        
        const heisenbugInBest = result.heisenbug_on_M2_confirmed_by_tc_probe;
        logS3(`    TC Confirmada no Melhor Resultado: ${heisenbugInBest}`, heisenbugInBest ? "vuln" : "info", FNAME_RUNNER);
        
        if (result.best_iter_addrof_details) { // Detalhes do addrof da melhor iteração
            const ad = result.best_iter_addrof_details;
            logS3(`    Detalhes Addrof (Melhor Iteração com Tentativa):`, "info_emphasis", FNAME_RUNNER);
            logS3(`      Tentativa: ${ad.attempted}, Sucesso: ${ad.success}`, ad.success ? "success_major" : "info", FNAME_RUNNER);
            logS3(`      Notas: ${ad.notes}`, "info", FNAME_RUNNER);
            if (ad.scan_base_addr_str) logS3(`      Base do Scan: ${ad.scan_base_addr_str}`, "leak_detail");
            if (ad.pattern_found_at_addr_str) logS3(`      Padrão M2 Encontrado em: ${ad.pattern_found_at_addr_str}`, "leak");
            if (ad.leaked_address_str) logS3(`      Endereço Vazado (Função Alvo?): ${ad.leaked_address_str}`, "leak", FNAME_RUNNER);
        }

        if (result.addrof_result) { /* ... (logar resultado global addrof) ... */ }
        if (result.webkit_leak_result) { /* ... (logar resultado global webkitleak) ... */ }
        if (result.errorOccurred && result.oob_params_of_best_result) { /* ... */ }

        if (result.iteration_results_summary && result.iteration_results_summary.length > 0) {
            logS3(`  --- SUMÁRIO DE TODAS AS ITERAÇÕES (${result.iteration_results_summary.length} testadas) ---`, "info_emphasis", FNAME_RUNNER);
            result.iteration_results_summary.forEach((iter_sum, index) => {
                let logMsg = `    Iter ${index + 1} (Off ${iter_sum.oob_offset} Val ${iter_sum.oob_value}): `;
                let highlights = [];
                if (iter_sum.heisenbug_on_M2_confirmed_by_tc_probe) highlights.push("TC_OK");
                if (iter_sum.addrof_success_this_iter) highlights.push("ADDROF_OK");
                if (iter_sum.webkit_leak_success_this_iter) highlights.push("WKLeak_OK");
                if (highlights.length === 0) highlights.push("Sem Sucesso Notável");
                logMsg += highlights.join(", ");
                if(iter_sum.error) logMsg += `, Err: ${iter_sum.error}`;
                logS3(logMsg, (iter_sum.addrof_success_this_iter || iter_sum.webkit_leak_success_this_iter) ? "success_major" : "info", FNAME_RUNNER);
            });
        }
        document.title = result.final_title_page || `${module_name_for_title} Final: Ver Logs`;
    } else { /* ... (log de resultado inválido) ... */ }
    // ... (resto do runner)
}

export async function runAllAdvancedTestsS3() { /* ... (sem alteração significativa, apenas nomes) ... */
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT}_MainOrchestrator_ArbReadScan`;
    logS3(`==== INICIANDO Script 3 R43_ArbReadScan (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    await runHeisenbugReproStrategy_TypedArrayVictim_R43_ArbReadScan(); // Chamar a função correta
    logS3(`\n==== Script 3 R43_ArbReadScan (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;
    // ... (lógica de título final do orchestrator)
}
