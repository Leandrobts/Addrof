// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { 
    executeTypedArrayVictimAddrofTest_LeakAddressViaGetterOnM2,   // NOME DA FUNÇÃO ATUALIZADO
    FNAME_MODULE_TYPEDARRAY_ADDROF_V80_LAGM    // NOME DO MÓDULO ATUALIZADO
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_LeakAddrGetterM2";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);

    const result = await executeTypedArrayVictimAddrofTest_LeakAddressViaGetterOnM2(); 

    if (result.errorOccurred) { 
        logS3(`   RUNNER: Teste principal capturou ERRO: ${result.errorOccurred.name} - ${result.errorOccurred.message}.`, "critical", FNAME_RUNNER);
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V80_LAGM}: MainTest ERR!`; 
    } else {
        logS3(`   RUNNER: Teste de Iteração de Valores OOB Concluído.`, "good", FNAME_RUNNER);
        logS3(`   RUNNER: Detalhes da sonda M2 (última/1a-sucesso): ${result.toJSON_details ? JSON.stringify(result.toJSON_details) : 'N/A'}`, "info", FNAME_RUNNER);
        logS3(`   RUNNER: Stringify Output da iteração relevante: ${result.stringifyResult ? JSON.stringify(result.stringifyResult) : 'N/A'}`, "info", FNAME_RUNNER);

        let heisenbugOnM2InRelevantIter = false;
        if (result.toJSON_details && result.toJSON_details.this_is_M2 && result.toJSON_details.this_type === '[object Object]') {
            heisenbugOnM2InRelevantIter = true;
        }
        let anyAddrofSuccess = false;
        if ((result.addrof_A_result && result.addrof_A_result.success) || (result.addrof_B_result && result.addrof_B_result.success)) {
            anyAddrofSuccess = true;
        }

        if (result.addrof_A_result) logS3(`    ADDROF M2.Getter: ${result.addrof_A_result.msg}`, result.addrof_A_result.success ? "vuln" : "warn", FNAME_RUNNER);
        if (result.addrof_B_result) logS3(`    ADDROF M2.Direct: ${result.addrof_B_result.msg}`, result.addrof_B_result.success ? "vuln" : "warn", FNAME_RUNNER);
        
        if (anyAddrofSuccess) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V80_LAGM}: AddrInM2 SUCCESS!`;
        } else if (heisenbugOnM2InRelevantIter) {
            logS3(`     !!!! TYPE CONFUSION NO M2 OBSERVADA na iteração relevante (Call #${result.toJSON_details.call_number}) !!!!`, "critical", FNAME_RUNNER);
            if(result.toJSON_details.m2_interaction && result.toJSON_details.m2_interaction.getter_defined) logS3(`       Getter definido em M2.`, "info");
            if(result.toJSON_details.m2_interaction && result.toJSON_details.m2_interaction.direct_prop_set) logS3(`       Propriedade direta definida em M2.`, "info");
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V80_LAGM}: M2_TC OK, Addr Fail`;
        } else {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V80_LAGM}: All Iter Tested, No M2_TC?`;
        }
    }

    logS3(`   Título da página: ${document.title}`, "info");
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V80_LAGM}_MainOrchestrator`; 
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Heisenbug (${FNAME_MODULE_TYPEDARRAY_ADDROF_V80_LAGM}) ====`, 'test', FNAME_ORCHESTRATOR);

    await runHeisenbugReproStrategy_TypedArrayVictim();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V80_LAGM)) {
        if (!document.title.includes("CRASH") && !document.title.includes("RangeError") && 
            !document.title.includes("SUCCESS") && !document.title.includes("Addr Fail") && 
            !document.title.includes("ERR") && !document.title.includes("Tested") && !document.title.includes("M2_TC OK")) { 
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V80_LAGM} Iterations Done`;
        }
    }
}
