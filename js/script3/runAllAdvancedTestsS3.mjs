// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeArrayBufferVictimCrashTest,
    FNAME_MODULE_V28 // Usaremos o nome do módulo que está sendo testado
} from './testArrayBufferVictimCrash.mjs';
// import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs'; // Não usado diretamente aqui
// import { toHex } from '../utils.mjs'; // Não usado diretamente aqui

async function runHeisenbugReproStrategy_ABVictim() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_ABVictim";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug com ArrayBuffer Vítima ====`, 'test', FNAME_RUNNER);

    // executeArrayBufferVictimCrashTest é async
    const result = await executeArrayBufferVictimCrashTest();

    if (result.errorOccurred) {
        logS3(`   RESULTADO: ERRO JS CAPTURADO: ${result.errorOccurred.name} - ${result.errorOccurred.message}.`, "error", FNAME_RUNNER);
        if (result.errorOccurred.name === 'RangeError') {
            logS3(`     RangeError: Maximum call stack size exceeded OCORREU!`, "vuln", FNAME_RUNNER);
            document.title = `Heisenbug (AB) RangeError!`;
         } else {
            document.title = `Heisenbug (AB) ERR: ${result.errorOccurred.name}`;
         }
    } else if (result.potentiallyCrashed) { // Este campo não está sendo muito usado nas versões recentes
         logS3(`   RESULTADO: CONGELAMENTO POTENCIAL (nenhum erro JS capturado). Detalhes da toJSON (se chamada): ${result.toJSON_details ? JSON.stringify(result.toJSON_details) : 'N/A'}`, "critical", FNAME_RUNNER);
         if (!document.title.includes("CONGELOU")) document.title = `Heisenbug (AB) CRASH/FREEZE?`;
    } else {
        logS3(`   RESULTADO: Completou. Detalhes da sonda (toJSON_details): ${result.toJSON_details ? JSON.stringify(result.toJSON_details) : 'N/A'}`, "good", FNAME_RUNNER);
        if (result.toJSON_details && result.toJSON_details.error_in_toJSON) {
            logS3(`     ERRO INTERNO NA toJSON: ${result.toJSON_details.error_in_toJSON}`, "warn", FNAME_RUNNER);
            document.title = `Heisenbug (AB) toJSON_ERR`;
        } else if (result.toJSON_details && result.toJSON_details.probe_called && result.toJSON_details.type_observed_in_probe === "[object Object]") {
            // Condição ajustada para usar type_observed_in_probe
            logS3(`     !!!! TYPE CONFUSION ([object Object]) NO 'victim_ab' DETECTADA PELA SONDA !!!! Tipo observado: ${result.toJSON_details.type_observed_in_probe}`, "critical", FNAME_RUNNER);
            if (result.addrof_attempt_result && result.addrof_attempt_result.success) {
                document.title = `Heisenbug (AB) Addrof SUCCESS!`;
            } else {
                document.title = `Heisenbug (AB) TYPE CONFUSION!`;
            }
        } else if (result.toJSON_details && result.toJSON_details.probe_called) {
            // Se a sonda foi chamada mas o tipo não era [object Object]
            logS3(`     Sonda chamada, mas type confusion para [object Object] não detectada. Tipo observado: ${result.toJSON_details.type_observed_in_probe}`, "info", FNAME_RUNNER);
            if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_V28) || document.title.includes("Probing")) {
                 document.title = `Heisenbug (AB) NoConf`;
            }
        } else {
            // Caso genérico se a sonda não foi chamada ou não há detalhes
            if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_V28) || document.title.includes("Probing")) {
                document.title = `Heisenbug (AB) Test OK`;
            }
        }
    }
    logS3(`   Título da página: ${document.title}`, "info");
    await PAUSE_S3(MEDIUM_PAUSE_S3); // Já estava aqui

    logS3(`==== Estratégia de Reprodução do Heisenbug com ArrayBuffer Vítima CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    // Usar o FNAME_MODULE_V28 importado do testArrayBufferVictimCrash.mjs para o nome do orquestrador
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

    // Lógica de título final
    // FNAME_MODULE_V28 será o nome da versão do teste atual (ex: "OriginalHeisenbug_Addrof_V5_DirectProbe")
    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_V28.substring(0,10))) { // Check por parte do nome do módulo
        if (!document.title.includes("CRASH") && !document.title.includes("RangeError") &&
            !document.title.includes("SUCCESS") && !document.title.includes("ERR") &&
            !document.title.includes("CONFUSION") && !document.title.includes("NoConf")) {
            document.title = `${FNAME_MODULE_V28} Done`;
        }
    }
}
