// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { 
    executeTypedArrayVictimAddrofTest_AggressiveVictimInteraction,   // NOME DA FUNÇÃO ATUALIZADO
    FNAME_MODULE_TYPEDARRAY_ADDROF_V16_AVI    // NOME DO MÓDULO ATUALIZADO
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_AggressiveVictimInteraction";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug com TypedArray Vítima (AggressiveVictimInteraction) ====`, 'test', FNAME_RUNNER);

    const result = await executeTypedArrayVictimAddrofTest_AggressiveVictimInteraction(); 

    logS3(`   Total de chamadas da sonda toJSON durante o teste: ${result.total_probe_calls || 0}`, "info", FNAME_RUNNER); 

    if (result.errorOccurred) {
        logS3(`   RESULTADO: ERRO JS CAPTURADO: ${result.errorOccurred.name} - ${result.errorOccurred.message}.`, "error", FNAME_RUNNER);
        // ... (tratamento de erro similar)
        document.title = `Heisenbug (TypedArray-AVI) ERR: ${result.errorOccurred.name}`;
    } else if (result.potentiallyCrashed) { 
         logS3(`   RESULTADO: POTENCIAL ESTOURO DE PILHA. Detalhes da última sonda: ${result.toJSON_details ? JSON.stringify(result.toJSON_details) : 'N/A'}`, "critical", FNAME_RUNNER);
         document.title = `Heisenbug (TypedArray-AVI) StackOverflow?`;
    } else {
        logS3(`   RESULTADO: Completou. Detalhes da ÚLTIMA chamada da sonda (capturados): ${result.toJSON_details ? JSON.stringify(result.toJSON_details) : 'N/A'}`, "good", FNAME_RUNNER);
        
        let heisenbugObservedOnThisInProbe = false;
        if (result.toJSON_details && result.toJSON_details.probe_called && 
            result.toJSON_details.this_type_in_toJSON === "[object Object]") {
            heisenbugObservedOnThisInProbe = true;
        }

        const addrof_results = [
            result.addrof_A_attempt_result, result.addrof_B_attempt_result,
            result.addrof_C_attempt_result, result.addrof_D_attempt_result
        ];
        let anyAddrofSuccess = false;

        addrof_results.forEach((res, i) => {
            if (res && res.success) {
                logS3(`     ADDROF [${i}] SUCESSO! ${res.message}`, "vuln", FNAME_RUNNER);
                anyAddrofSuccess = true;
            } else if (res) {
                logS3(`     ADDROF [${i}] FALHOU: ${res.message}`, heisenbugObservedOnThisInProbe ? "warn" : "error", FNAME_RUNNER);
            }
        });

        if (result.toJSON_details && result.toJSON_details.error_in_toJSON) {
            logS3(`     ERRO INTERNO NA ÚLTIMA SONDA: ${result.toJSON_details.error_in_toJSON}`, "warn", FNAME_RUNNER);
            document.title = `Heisenbug (TypedArray-AVI) toJSON_ERR`;
        } else if (heisenbugObservedOnThisInProbe) {
            logS3(`     !!!! TYPE CONFUSION NO 'this' DA SONDA OBSERVADA !!!! Call #${result.toJSON_details.call_number}, Tipo: ${result.toJSON_details.this_type_in_toJSON}`, "critical", FNAME_RUNNER);
            if(result.toJSON_details.victim_interaction_attempted) {
                logS3(`       Interação agressiva com a VÍTIMA ORIGINAL tentada. Erro: ${result.toJSON_details.victim_interaction_error || 'Nenhum'}`, "info");
            }
            if (!anyAddrofSuccess) {
                 document.title = `Heisenbug (TypedArray-AVI) Sonda TC, Addr Fail`;
            } else {
                 document.title = `Heisenbug (TypedArray-AVI) Addr SUCCESS!`;
            }
        } else if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V16_AVI) || document.title.includes("Probing")) {
            if (!anyAddrofSuccess) {
                 document.title = `Heisenbug (TypedArray-AVI) Test OK`;
            }
        }
    }
    logS3(`   Título da página: ${document.title}`, "info");
    await PAUSE_S3(MEDIUM_PAUSE_S3);

    logS3(`==== Estratégia de Reprodução do Heisenbug (AggressiveVictimInteraction) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V16_AVI}_MainOrchestrator`; 
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Reproduzindo Heisenbug com TypedArray Vítima (AggressiveVictimInteraction) ====`, 'test', FNAME_ORCHESTRATOR);

    await runHeisenbugReproStrategy_TypedArrayVictim();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V16_AVI)) {
        if (!document.title.includes("CRASH") && !document.title.includes("RangeError") && 
            !document.title.includes("SUCESSO") && !document.title.includes("Addr Fail") && 
            !document.title.includes("ERR") && !document.title.includes("Sonda TC")) { 
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V16_AVI} Concluído`;
        }
    }
}
