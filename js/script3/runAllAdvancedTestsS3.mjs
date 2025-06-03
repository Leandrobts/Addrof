// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { 
    executeTypedArrayVictimAddrofTest_TargetConfusedMarkerForLeak,   // NOME DA FUNÇÃO ATUALIZADO
    FNAME_MODULE_TYPEDARRAY_ADDROF_V27_TCML    // NOME DO MÓDULO ATUALIZADO
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_TargetConfusedMarkerForLeak";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug com TypedArray Vítima (TargetConfusedMarkerForLeak) ====`, 'test', FNAME_RUNNER);

    const result = await executeTypedArrayVictimAddrofTest_TargetConfusedMarkerForLeak(); 

    logS3(`   Total de chamadas da sonda toJSON durante o teste: ${result.total_probe_calls || 0}`, "info", FNAME_RUNNER); 
    
    if (result.errorOccurred) {
        logS3(`   RESULTADO: ERRO JS CAPTURADO: ${result.errorOccurred.name} - ${result.errorOccurred.message}.`, "error", FNAME_RUNNER);
        document.title = `Heisenbug (TypedArray-TCML) ERR: ${result.errorOccurred.name}`;
    } else {
        logS3(`   RESULTADO: Completou. Detalhes da última sonda relevante (que interagiu com P1 marker): ${result.toJSON_details ? JSON.stringify(result.toJSON_details) : 'N/A'}`, "good", FNAME_RUNNER);
        logS3(`   Stringify Output (Objeto Parseado): ${result.stringifyResult ? JSON.stringify(result.stringifyResult) : 'N/A'}`, "info", FNAME_RUNNER);
        
        let heisenbugOnP1Marker = false;
        if (result.toJSON_details && 
            result.toJSON_details.this_is_marker_P1 &&
            result.toJSON_details.this_type === "[object Object]") {
            heisenbugOnP1Marker = true;
        }

        let anyAddrofSuccess = false;
        const addrofChecks = [
            // {name: "VictimA", res: result.addrof_victim_A}, // Menos relevante agora
            // {name: "VictimB", res: result.addrof_victim_B},
            {name: "MarkerA", res: result.addrof_marker_A},
            {name: "MarkerB", res: result.addrof_marker_B}
        ];

        addrofChecks.forEach(item => {
            if (item.res && item.res.success) {
                 logS3(`     ADDROF ${item.name} SUCESSO! ${item.res.msg}`, "vuln", FNAME_RUNNER); anyAddrofSuccess = true;
            } else if (item.res) {
                 logS3(`     ADDROF ${item.name} FALHOU: ${item.res.msg}`, "warn", FNAME_RUNNER);
            }
        });


        if (result.toJSON_details && result.toJSON_details.error_in_probe) {
            logS3(`     ERRO INTERNO NA SONDA (quando 'this' era P1 marker): ${result.toJSON_details.error_in_probe}`, "warn", FNAME_RUNNER);
            document.title = `Heisenbug (TypedArray-TCML) toJSON_ERR`;
        } else if (heisenbugOnP1Marker) {
            logS3(`     !!!! TYPE CONFUSION NO P1 MARKER OBSERVADA !!!! (Chamada #${result.toJSON_details.call_number})`, "critical", FNAME_RUNNER);
            if (result.toJSON_details.writes_to_marker_P1_attempted) { 
                logS3(`       Tentativas de escrita no payload do P1 marker realizadas.`, "info");
            }
            if (!anyAddrofSuccess) {
                 document.title = `Heisenbug (TypedArray-TCML) P1MarkerTC OK, Addr Fail`;
            } else { // anyAddrofSuccess é true
                 document.title = `Heisenbug (TypedArray-TCML) AddrInP1Marker SUCCESS!`;
            }
        } else if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V27_TCML) || document.title.includes("Probing")) {
            if (!anyAddrofSuccess) {
                 document.title = `Heisenbug (TypedArray-TCML) Test OK`;
            }
        }
    }
    logS3(`   Título da página: ${document.title}`, "info");
    await PAUSE_S3(MEDIUM_PAUSE_S3);

    logS3(`==== Estratégia de Reprodução do Heisenbug (TargetConfusedMarkerForLeak) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V27_TCML}_MainOrchestrator`; 
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Reproduzindo Heisenbug com TypedArray Vítima (TargetConfusedMarkerForLeak) ====`, 'test', FNAME_ORCHESTRATOR);

    await runHeisenbugReproStrategy_TypedArrayVictim();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V27_TCML)) {
        if (!document.title.includes("CRASH") && !document.title.includes("RangeError") && 
            !document.title.includes("SUCESSO") && !document.title.includes("Addr Fail") && 
            !document.title.includes("ERR") && !document.title.includes("P1MarkerTC OK")) { 
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V27_TCML} Concluído`;
        }
    }
}
