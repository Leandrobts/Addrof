// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { 
    executeTypedArrayVictimAddrofTest_FixFinallyError,   // NOME DA FUNÇÃO ATUALIZADO
    FNAME_MODULE_TYPEDARRAY_ADDROF_V86A_FRFAM2    // NOME DO MÓDULO ATUALIZADO (era FFE, agora FRFAM2)
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_FixRefAndFocusM2"; // Atualizado
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);

    const result = await executeTypedArrayVictimAddrofTest_FixFinallyError(); // Atualizado

    logS3(`   (Runner) Total de chamadas da sonda (da última/melhor iteração): ${result.total_probe_calls || 0}`, "info", FNAME_RUNNER); 
    if (result.iteration_results_summary && result.iteration_results_summary.length > 0) {
        logS3(`   (Runner) Sumário das Iterações: ${JSON.stringify(result.iteration_results_summary)}`, "dev_verbose");
    }
    
    if (result.errorOccurred) { 
        logS3(`   RUNNER: Teste principal capturou ERRO: ${result.errorOccurred.name} - ${result.errorOccurred.message}.`, "critical", FNAME_RUNNER);
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V86A_FRFAM2}: MainTest ERR!`; 
    } else {
        logS3(`   RUNNER: Teste Completou. Detalhes da interação M2 (última/melhor iteração): ${result.toJSON_details ? JSON.stringify(result.toJSON_details) : 'N/A'}`, "good", FNAME_RUNNER);
        logS3(`   RUNNER: Stringify Output (última/melhor iteração): ${result.stringifyResult ? JSON.stringify(result.stringifyResult) : 'N/A'}`, "info", FNAME_RUNNER);

        let heisenbugOnM2InReportedIter = false;
        if (result.toJSON_details && result.toJSON_details.this_is_M2 && result.toJSON_details.this_type === '[object Object]') {
            heisenbugOnM2InReportedIter = true;
        }
        let anyAddrofSuccessInReportedIter = false;
        if ((result.addrof_A_result && result.addrof_A_result.success) || (result.addrof_B_result && result.addrof_B_result.success)) {
            anyAddrofSuccessInReportedIter = true;
        }

        if (result.addrof_A_result) logS3(`    ADDROF M2.Getter (Reportado): ${result.addrof_A_result.msg}`, result.addrof_A_result.success ? "vuln" : "warn", FNAME_RUNNER);
        if (result.addrof_B_result) logS3(`    ADDROF M2.Direct (Reportado): ${result.addrof_B_result.msg}`, result.addrof_B_result.success ? "vuln" : "warn", FNAME_RUNNER);
        
        if (anyAddrofSuccessInReportedIter) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V86A_FRFAM2}: AddrInM2 SUCCESS!`;
        } else if (heisenbugOnM2InReportedIter) {
            logS3(`     !!!! TYPE CONFUSION NO M2 OBSERVADA na iteração reportada (Call #${result.toJSON_details.call_number}) !!!!`, "critical", FNAME_RUNNER);
            if(result.toJSON_details.m2_interaction_summary) { // Checa se m2_interaction_summary existe
                 if(result.toJSON_details.m2_interaction_summary.getter_defined) logS3(`       Getter definido em M2.`, "info");
                 if(result.toJSON_details.m2_interaction_summary.direct_prop_set) logS3(`       Propriedade direta definida em M2.`, "info");
            }
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V86A_FRFAM2}: M2_TC OK, Addr Fail`;
        } else {
            let anyM2TCInAllIterations = false;
            if(result.iteration_results_summary) {
                anyM2TCInAllIterations = result.iteration_results_summary.some(iter_res => iter_res.m2_tc);
            }
            if(anyM2TCInAllIterations) {
                 document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V86A_FRFAM2}: M2_TC in some iter, Addr Fail`;
            } else {
                 document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V86A_FRFAM2}: All Iter Tested, No M2_TC?`;
            }
        }
    }

    logS3(`   Título da página: ${document.title}`, "info");
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V86A_FRFAM2}_MainOrchestrator`; 
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Heisenbug (${FNAME_MODULE_TYPEDARRAY_ADDROF_V86A_FRFAM2}) ====`, 'test', FNAME_ORCHESTRATOR);

    await runHeisenbugReproStrategy_TypedArrayVictim();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    // Lógica de título final
    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V86A_FRFAM2)) {
        if (!document.title.includes("CRASH") && !document.title.includes("RangeError") && 
            !document.title.includes("SUCCESS") && !document.title.includes("Addr Fail") && 
            !document.title.includes("ERR") && !document.title.includes("Tested") && !document.title.includes("M2_TC OK")) { 
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V86A_FRFAM2} Iterations Done`;
        }
    }
}
