// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para Revisado 39)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTypedArrayVictimAddrofTest_AdvancedGetterLeak_R39, // <<<< NOME DA FUNÇÃO ATUALIZADO
    FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_R39"; 
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    const result = await executeTypedArrayVictimAddrofTest_AdvancedGetterLeak_R39(); 

    if (result.errorOccurred) {
        logS3(`  RUNNER R39: Teste principal capturou ERRO: ${String(result.errorOccurred)}`, "critical", FNAME_RUNNER);
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_R39: MainTest ERR!`;
    } else if (result) {
        logS3(`  RUNNER R39: Completou. Melhor OOB: ${result.oob_value_of_best_result||'N/A'}`,"good",FNAME_RUNNER);
        logS3(`  RUNNER R39: Detalhes Sonda TC (Best): ${result.tc_probe_details?JSON.stringify(result.tc_probe_details):'N/A'}`,"leak",FNAME_RUNNER);
        
        const heisenbugSuccessfullyDetected = result.heisenbug_on_M2_in_best_result; 
        const memScanResult = result.memory_scan_result;

        logS3(`  RUNNER R39: Heisenbug TC Sonda (Best): ${heisenbugSuccessfullyDetected ? "CONFIRMADA" : "NÃO CONFIRMADA"}`, heisenbugSuccessfullyDetected ? "vuln" : "warn", FNAME_RUNNER);

        if (memScanResult) {
            logS3(`  RUNNER R39: Teste Memory Scan: ${memScanResult.msg} (Encontrado em: ${memScanResult.found_at_address || 'N/A'}, Base OOB: ${memScanResult.oob_buffer_base_addr || 'N/A'})`, memScanResult.success ? "vuln" : "warn", FNAME_RUNNER);
        } else {
            logS3(`  RUNNER R39: Teste Memory Scan não produziu resultado ou não foi executado.`, "warn", FNAME_RUNNER);
        }
        
        if (memScanResult?.success) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_R39: MemScan SUCCESS!`;
        } else if (heisenbugSuccessfullyDetected) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_R39: TC OK, Scan Fail`;
        } else {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_R39: No TC Confirmed`;
        }
        
        if(result.iteration_results_summary && result.iteration_results_summary.length > 0){
            logS3(`  RUNNER R39: Sumário completo das iterações:`, "info", FNAME_RUNNER);
            result.iteration_results_summary.forEach((iter_sum, index) => { 
                logS3(`    Iter ${index + 1} (OOB ${iter_sum.oob_value}): TC_Probe=${iter_sum.heisenbug_on_M2_confirmed_by_tc_probe}, MemScanOK=${iter_sum.memory_scan_result_this_iter?.success ?? 'N/A'}${iter_sum.error ? `, Err: ${iter_sum.error}` : ''}`, "info", FNAME_RUNNER);
            });
        }
    } else {
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_R39: Invalid Result Obj`;
    }
    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_MainOrchestrator_R39`; 
    logS3(`==== INICIANDO Script 3 R39 (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    await runHeisenbugReproStrategy_TypedArrayVictim();
    logS3(`\n==== Script 3 R39 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if(runBtn) runBtn.disabled = false;
    if (document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL)&&!document.title.includes("SUCCESS")&&!document.title.includes("Fail")&&!document.title.includes("OK")&&!document.title.includes("Confirmed")){document.title=`${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL}_R39 Done`;}
}
