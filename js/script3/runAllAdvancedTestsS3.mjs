// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { 
    executeTypedArrayVictimAddrofTest_RevertV20WithGetterAndValueIteration,   // NOME DA FUNÇÃO ATUALIZADO
    FNAME_MODULE_TYPEDARRAY_ADDROF_V76_RV20GWV    // NOME DO MÓDULO ATUALIZADO
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_RevertV20GetterAndValueIteration";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);

    const result = await executeTypedArrayVictimAddrofTest_RevertV20WithGetterAndValueIteration(); 

    // result.overall_results contém os dados de cada iteração de OOB_WRITE_VALUE
    // O log principal e o título já são definidos dentro de execute...
    // Aqui podemos apenas logar um resumo se necessário, mas execute... já faz isso.
    if (result.errorOccurred) { // Erro principal no teste, se houver
        logS3(`   RESULTADO: ERRO JS PRINCIPAL CAPTURADO: ${result.errorOccurred.name} - ${result.errorOccurred.message}.`, "critical", FNAME_RUNNER);
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V76_RV20GWV}: Main ERR!`; 
    } else if (result.overall_results && result.overall_results.length > 0) {
        logS3(`   RESULTADO: Teste de Iteração de Valores OOB Concluído.`, "good", FNAME_RUNNER);
        // O título da página já deve ter sido definido pela lógica em execute...
    } else {
        logS3(`   RESULTADO: Nenhuma iteração de resultado encontrada.`, "warn", FNAME_RUNNER);
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V76_RV20GWV}: No Iter Results`;
    }

    logS3(`   Título final da página: ${document.title}`, "info");
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V76_RV20GWV}_MainOrchestrator`; 
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Heisenbug (RevertV20GetterAndValueIteration) ====`, 'test', FNAME_ORCHESTRATOR);

    await runHeisenbugReproStrategy_TypedArrayVictim();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    // A lógica de título final mais detalhada está agora dentro de execute...
    // Podemos simplificar aqui ou remover se o título já estiver bom.
    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V76_RV20GWV)) {
        if (!document.title.includes("CRASH") && !document.title.includes("RangeError") && 
            !document.title.includes("SUCCESS") && !document.title.includes("Addr Fail") && 
            !document.title.includes("ERR") && !document.title.includes("Tested")) { 
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V76_RV20GWV} Iterations Done`;
        }
    }
}
