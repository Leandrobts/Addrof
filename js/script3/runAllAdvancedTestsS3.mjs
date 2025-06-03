// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { 
    executeTypedArrayVictimAddrofTest_OffsetValueFuzz,   // NOME DA FUNÇÃO ATUALIZADO
    FNAME_MODULE_TYPEDARRAY_ADDROF_V29_OVF    // NOME DO MÓDULO ATUALIZADO
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_OffsetValueFuzz";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug com TypedArray Vítima (OffsetValueFuzzing) ====`, 'test', FNAME_RUNNER);

    const result = await executeTypedArrayVictimAddrofTest_OffsetValueFuzz(); 

    if (result.errorOccurred) { // Erro principal no teste, fora do loop de iteração
        logS3(`   RESULTADO: ERRO JS PRINCIPAL CAPTURADO: ${result.errorOccurred.name} - ${result.errorOccurred.message}.`, "critical", FNAME_RUNNER);
        document.title = `Heisenbug (TypedArray-OVF) MAIN ERR!`; 
    } else if (result.overall_results && result.overall_results.length > 0) {
        logS3(`   RESULTADO: Teste de Fuzzing de Offset/Valor Concluído. Verificando resultados...`, "good", FNAME_RUNNER);
        let anyIterationSuccess = false;
        let firstSuccessfulParams = null;

        result.overall_results.forEach(iter_res => {
            logS3(`--- Iteration Offset: ${iter_res.offset}, Value: ${iter_res.value} ---`, 'info', FNAME_RUNNER);
            logS3(`    Stringify Output (Parseado): ${iter_res.stringify_output ? JSON.stringify(iter_res.stringify_output) : 'N/A'}`, 'info', FNAME_RUNNER);
            logS3(`    Detalhes da última sonda: ${iter_res.probe_details ? JSON.stringify(iter_res.probe_details) : 'N/A'}`, 'info', FNAME_RUNNER);
            logS3(`    Addrof na Vítima (A): ${iter_res.addrof_victim_A.msg}`, 'info', FNAME_RUNNER);
            logS3(`    Addrof no Output (LeakyA): Success=${iter_res.addrof_output_leaky_A.success}, Msg='${iter_res.addrof_output_leaky_A.msg}'`, iter_res.addrof_output_leaky_A.success ? "vuln" : "warn", FNAME_RUNNER);
            if (iter_res.error) {
                 logS3(`    ERRO nesta iteração: ${iter_res.error}`, "error", FNAME_RUNNER);
            }
            if (iter_res.addrof_output_leaky_A.success) {
                anyIterationSuccess = true;
                if (!firstSuccessfulParams) firstSuccessfulParams = `Off:${iter_res.offset},Val:${iter_res.value}`;
            }
        });

        if (anyIterationSuccess) {
            document.title = `Heisenbug (TypedArray-OVF) Addr SUCCESS @ ${firstSuccessfulParams}!`;
        } else {
            document.title = `Heisenbug (TypedArray-OVF) Fuzzing Done, No Addr`;
        }
    } else {
        logS3(`   RESULTADO: Nenhuma iteração de resultado encontrada.`, "warn", FNAME_RUNNER);
        document.title = `Heisenbug (TypedArray-OVF) No Results`;
    }

    logS3(`   Título da página: ${document.title}`, "info");
    await PAUSE_S3(MEDIUM_PAUSE_S3);

    logS3(`==== Estratégia de Reprodução do Heisenbug (OffsetValueFuzzing) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V29_OVF}_MainOrchestrator`; 
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Reproduzindo Heisenbug com TypedArray Vítima (OffsetValueFuzzing) ====`, 'test', FNAME_ORCHESTRATOR);

    await runHeisenbugReproStrategy_TypedArrayVictim();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V29_OVF)) {
        if (!document.title.includes("CRASH") && !document.title.includes("RangeError") && 
            !document.title.includes("SUCCESS") && !document.title.includes("No Addr") && 
            !document.title.includes("ERR")) { 
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V29_OVF} Concluído`;
        }
    }
}
