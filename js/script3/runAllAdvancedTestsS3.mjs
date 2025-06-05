// js/script3/runAllAdvancedTestsS3.mjs (Adaptado para Iterar Offsets OOB)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTypedArrayVictimAddrofAndWebKitLeak_R43,
    FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT // Nome do módulo do arquivo de teste
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim_R43() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_R43_IterOffsets";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    const result = await executeTypedArrayVictimAddrofAndWebKitLeak_R43();

    const module_name_for_title = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;

    if (result.errorOccurred) {
        logS3(`  RUNNER R43(IterOffsets): Teste principal capturou ERRO: ${String(result.errorOccurred)}`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: MainTest ERR!`;
    } else if (result) {
        let bestParamsMsg = 'N/A';
        if (result.oob_params_of_best_result_detailed) { // Usar o campo detalhado
            bestParamsMsg = `Offset: ${result.oob_params_of_best_result_detailed.offset}, Valor: ${result.oob_params_of_best_result_detailed.value}`;
        } else if (result.oob_value_of_best_result) { // Fallback para o campo antigo se o detalhado não estiver lá
             bestParamsMsg = `Melhor OOB (formato antigo): ${result.oob_value_of_best_result}`;
        }

        logS3(`  RUNNER R43(IterOffsets): Completou. Melhores Parâmetros OOB: ${bestParamsMsg}`, "good", FNAME_RUNNER);
        logS3(`  RUNNER R43(IterOffsets): Detalhes Sonda TC (Best): ${result.tc_probe_details ? JSON.stringify(result.tc_probe_details) : 'N/A'}`, "leak_detail", FNAME_RUNNER);

        const heisenbugSuccessfullyDetected = result.heisenbug_on_M2_in_best_result;
        const addrofResult = result.addrof_result;
        const webkitLeakResult = result.webkit_leak_result;
        const postOOBAnalysis = result.post_oob_victim_buffer_analysis_best_result;


        logS3(`  RUNNER R43(IterOffsets): Heisenbug TC Sonda (Best): ${heisenbugSuccessfullyDetected ? "CONFIRMADA" : "NÃO CONFIRMADA"}`, heisenbugSuccessfullyDetected ? "vuln_potential" : "warn", FNAME_RUNNER);

        if (postOOBAnalysis) {
            logS3(`  RUNNER R43(IterOffsets): Análise Pós-OOB do Buffer Vítima (Melhor Iteração):`, "info_emphasis", FNAME_RUNNER);
            logS3(`    Padrão de preenchimento encontrado: ${postOOBAnalysis.buffer_fill_pattern_found}`, postOOBAnalysis.buffer_fill_pattern_found ? "good" : "vuln_potential", FNAME_RUNNER);
            logS3(`    Notas: ${postOOBAnalysis.notes}`, "info", FNAME_RUNNER);
            if (postOOBAnalysis.buffer_initial_head && postOOBAnalysis.buffer_initial_head.length > 0) {
                 logS3(`    Cabeçalho do Buffer (Melhor Iteração - primeiros 8 U32s): ${postOOBAnalysis.buffer_initial_head.slice(0,8).map(v => "0x"+v.toString(16)).join(", ")}...`, "leak_detail", FNAME_RUNNER);
            }
        } else {
            logS3(`  RUNNER R43(IterOffsets): Detalhes da Análise Pós-OOB do Buffer Vítima não disponíveis.`, "warn", FNAME_RUNNER);
        }

        if (addrofResult) {
            logS3(`  RUNNER R43(IterOffsets): Teste Addrof (Best): ${addrofResult.msg}`, addrofResult.success ? "vuln" : "warn", FNAME_RUNNER);
        }
        if (webkitLeakResult) {
            logS3(`  RUNNER R43(IterOffsets): Teste WebKit Base Leak (Best): ${webkitLeakResult.msg}`, webkitLeakResult.success ? "vuln" : "warn", FNAME_RUNNER);
        }

        // Atualizar título da página baseado no resultado
        let finalTitleSegment = "No Notable Result";
         if (result.oob_params_of_best_result_detailed) {
            const best_oob_offset = result.oob_params_of_best_result_detailed.offset;
            if (heisenbugSuccessfullyDetected && postOOBAnalysis && !postOOBAnalysis.buffer_fill_pattern_found) {
                finalTitleSegment = `Off ${best_oob_offset}: TC & Buffer Corrupt!`;
            } else if (heisenbugSuccessfullyDetected) {
                finalTitleSegment = `Off ${best_oob_offset}: TC OK`;
            } else if (postOOBAnalysis && !postOOBAnalysis.buffer_fill_pattern_found) {
                finalTitleSegment = `Off ${best_oob_offset}: Buffer Corrupt`;
            } else {
                 finalTitleSegment = `Off ${best_oob_offset}: No TC/Corruption`;
            }
        }
        document.title = `${module_name_for_title}_R43_IterOffsets: ${finalTitleSegment}`;


        if (result.iteration_results_summary && result.iteration_results_summary.length > 0) {
            logS3(`  RUNNER R43(IterOffsets): Sumário completo das iterações:`, "info", FNAME_RUNNER);
            result.iteration_results_summary.forEach((iter_sum, index) => {
                const tcSuccess = iter_sum.heisenbug_on_M2_confirmed_by_tc_probe;
                const bufferCorrupted = iter_sum.post_oob_victim_buffer_analysis && !iter_sum.post_oob_victim_buffer_analysis.buffer_fill_pattern_found;
                // Usar iter_sum.oob_offset que agora está no sumário da iteração
                let logMsg = `    Iter ${index + 1} (Offset ${iter_sum.oob_offset}, OOB ${iter_sum.oob_value}): TC=${tcSuccess}, BufferCorrupt=${bufferCorrupted}`;
                if(iter_sum.error) logMsg += `, Err: ${iter_sum.error}`;
                logS3(logMsg, "info", FNAME_RUNNER);
            });
        }
    } else {
        document.title = `${module_name_for_title}_R43_IterOffsets: Invalid Result Obj`;
    }
    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT}_MainOrchestrator_IterOffsets`;
    logS3(`==== INICIANDO Script 3 R43_IterOffsets (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    await runHeisenbugReproStrategy_TypedArrayVictim_R43();
    logS3(`\n==== Script 3 R43_IterOffsets (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;

    if (document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT) &&
        !document.title.includes("Corrupt") &&
        !document.title.includes("OK") &&
        !document.title.includes("ERR") &&
        !document.title.includes("Invalid")) {
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT}_R43_IterOffsets_Done`;
    }
}
