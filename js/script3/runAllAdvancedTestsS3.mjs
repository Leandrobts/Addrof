// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para Revisado 19)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTypedArrayVictimAddrofTest_AdvancedGetterLeak_R19, // <<<< NOME DA FUNÇÃO ATUALIZADO
    FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_R19"; 
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    const result = await executeTypedArrayVictimAddrofTest_AdvancedGetterLeak_R19(); 

    if (result.errorOccurred) {
        logS3(`  RUNNER R19: Teste principal capturou ERRO: ${result.errorOccurred}.`, "critical", FNAME_RUNNER);
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_R19: MainTest ERR!`;
    } else if (result) {
        logS3(`  RUNNER R19: Completou. Melhor OOB: ${result.oob_value_of_best_result||'N/A'}`,"good",FNAME_RUNNER);
        logS3(`  RUNNER R19: Detalhes Sonda TC (Best): ${result.tc_probe_details?JSON.stringify(result.tc_probe_details):'N/A'}`,"leak",FNAME_RUNNER); // Campo renomeado em R19
        
        const heisenbugSuccessfullyDetected = result.heisenbug_on_M2_in_best_result; // Nome da propriedade no objeto result
        const addrofCoreSuccess = result.addrof_A_result?.success;
        const addrofDirectSuccess = result.addrof_B_result?.success; 
        const addrofGetterInfo = result.addrof_A_getter_details; 

        logS3(`  RUNNER R19: Heisenbug TC Sonda (Best): ${heisenbugSuccessfullyDetected ? "CONFIRMADA" : "NÃO CONFIRMADA"}`, heisenbugSuccessfullyDetected ? "vuln" : "warn", FNAME_RUNNER);

        if (result.addrof_A_result) {
            logS3(`  RUNNER R19: Addrof via CoreExploit Func: ${result.addrof_A_result.msg} (Valor: ${result.addrof_A_result.value}, Double: ${result.addrof_A_result.raw_double})`, addrofCoreSuccess ? "vuln" : "warn", FNAME_RUNNER);
        }
        if (addrofGetterInfo) {
            logS3(`  RUNNER R19: Addrof via Getter na Sonda TC: ${addrofGetterInfo.msg} (Valor: ${addrofGetterInfo.value})`, addrofGetterInfo.success ? "vuln" : "warn", FNAME_RUNNER);
        }
        if (result.addrof_B_result) {
            logS3(`  RUNNER R19: Addrof Direct Prop (ObjB ID): ${result.addrof_B_result.msg} (Valor: ${JSON.stringify(result.addrof_B_result.value)})`, addrofDirectSuccess ? "vuln" : "warn", FNAME_RUNNER);
        }

        if (addrofCoreSuccess) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_R19: AddrofCore SUCCESS! (OOB: ${result.oob_value_of_best_result})`;
        } else if (heisenbugSuccessfullyDetected) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_R19: TC OK, Addrof Fail (OOB: ${result.oob_value_of_best_result})`;
        } else {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_R19: No TC Confirmed (OOB: ${result.oob_value_of_best_result})`;
        }
        
        if(result.iteration_results_summary && result.iteration_results_summary.length > 0){
            logS3(`  RUNNER R19: Sumário completo das iterações:`, "info", FNAME_RUNNER);
            result.iteration_results_summary.forEach((iter_sum, index) => { 
                logS3(`    Iter ${index + 1} (OOB ${iter_sum.oob_value}): TC_Probe=${iter_sum.heisenbug_on_M2_this_iter}, AddrCore_OK=${iter_sum.addrof_A_core_this_iter?.success ?? 'N/A'}, AddrGetter_OK=${iter_sum.addrof_A_getter_this_iter?.success ?? 'N/A'}${iter_sum.error ? `, Err: ${iter_sum.error}` : ''}`, "info", FNAME_RUNNER);
            });
        }
    } else {
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_R19: Invalid Result Obj`;
    }
    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_MainOrchestrator_R19`; 
    // ... (resto como na R18, atualizando nomes/logs para R19) ...
    logS3(`==== INICIANDO Script 3 R19 (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    await runHeisenbugReproStrategy_TypedArrayVictim();
    logS3(`\n==== Script 3 R19 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if(runBtn) runBtn.disabled = false;
    if (document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL)&&!document.title.includes("SUCCESS")&&!document.title.includes("Fail")&&!document.title.includes("OK")&&!document.title.includes("Confirmed")){document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_R19 Done`;}
}
