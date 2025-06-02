// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeArrayBufferVictimCrashTest,
    FNAME_MODULE_V28
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_ABVictim() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_ABVictim";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug com ArrayBuffer Vítima ====`, 'test', FNAME_RUNNER);

    const result = await executeArrayBufferVictimCrashTest();

    if (result.errorOccurred) {
        logS3(`   RESULTADO: ERRO JS CAPTURADO: ${result.errorOccurred.name} - ${result.errorOccurred.message}.`, "error", FNAME_RUNNER);
        if (result.errorOccurred.name === 'RangeError') {
            logS3(`     RangeError: Maximum call stack size exceeded OCORREU!`, "vuln", FNAME_RUNNER);
            document.title = `Heisenbug (AB) RangeError!`;
         } else {
            document.title = `Heisenbug (AB) ERR: ${result.errorOccurred.name}`;
         }
    } else if (result.potentiallyCrashed) {
         logS3(`   RESULTADO: CONGELAMENTO POTENCIAL. Detalhes da sonda: ${result.toJSON_details ? JSON.stringify(result.toJSON_details) : 'N/A'}`, "critical", FNAME_RUNNER);
         if (!document.title.includes("CONGELOU")) document.title = `Heisenbug (AB) CRASH/FREEZE?`;
    } else {
        logS3(`   RESULTADO: Completou. Detalhes da sonda (toJSON_details): ${result.toJSON_details ? JSON.stringify(result.toJSON_details) : 'N/A'}`, "good", FNAME_RUNNER);

        // Usar a estrutura de toJSON_details da V1.3
        if (result.toJSON_details && result.toJSON_details.error_in_probe) { // Mudado de error_in_probe_for_victim
            logS3(`     ERRO NA SONDA: ${result.toJSON_details.error_in_probe}`, "warn", FNAME_RUNNER);
            document.title = `Heisenbug (AB) ProbeERR`;
        } else if (result.toJSON_details && result.toJSON_details.victim_ab_seen_by_probe && result.toJSON_details.type_of_victim_ab_last_seen === "[object Object]") {
            // Esta é a condição que esperamos replicar do "Log de Referência"
            logS3(`     !!!! TYPE CONFUSION ([object Object]) NO 'victim_ab' DETECTADA PELA SONDA !!!! Último tipo obs no victim_ab: ${result.toJSON_details.type_of_victim_ab_last_seen}`, "critical", FNAME_RUNNER);
            if (result.addrof_attempt_result && result.addrof_attempt_result.success) {
                document.title = `Heisenbug (AB) Addrof SUCCESS!`;
            } else {
                document.title = `Heisenbug (AB) TYPE CONFUSION!`;
            }
        } else if (result.toJSON_details && result.toJSON_details.victim_ab_seen_by_probe) {
            logS3(`     Sonda viu victim_ab. Último tipo obs: ${result.toJSON_details.type_of_victim_ab_last_seen}. Escrita tentada: ${result.toJSON_details.addrof_write_attempted_on_victim}`, "info", FNAME_RUNNER);
            if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_V28.substring(0,10))) {
                 document.title = `Heisenbug (AB) NoConf`;
            }
        } else { 
            if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_V28.substring(0,10))) {
                document.title = `Heisenbug (AB) Test OK`;
            }
        }
    }
    logS3(`   Título da página: ${document.title}`, "info");
    await PAUSE_S3(MEDIUM_PAUSE_S3);

    logS3(`==== Estratégia de Reprodução do Heisenbug com ArrayBuffer Vítima CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_V28}_MainOrchestrator`;
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Reproduzindo Heisenbug com ArrayBuffer Vítima ====`, 'test', FNAME_ORCHESTRATOR);

    await runHeisenbugReproStrategy_ABVictim();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_V28.substring(0,10))) {
        if (!document.title.includes("CRASH") && !document.title.includes("RangeError") &&
            !document.title.includes("SUCCESS") && !document.title.includes("ERR") &&
            !document.title.includes("CONFUSION") && !document.title.includes("NoConf") && !document.title.includes("WriteOK")) {
            document.title = `${FNAME_MODULE_V28} Done`;
        }
    }
}
