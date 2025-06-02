// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { 
    executeArrayBufferVictim_CorruptABC_Test,   // NOME DA FUNÇÃO ATUALIZADO
    FNAME_MODULE_V20_CORRUPT_ABC    // NOME DO MÓDULO ATUALIZADO
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_CorruptABC() { // Nome da função do runner atualizado
    const FNAME_RUNNER = "runHeisenbugReproStrategy_CorruptABC";
    logS3(`==== INICIANDO Estratégia de Corrupção de ArrayBufferContents ====`, 'test', FNAME_RUNNER);

    const result = await executeArrayBufferVictim_CorruptABC_Test(); 

    if (result.errorOccurred) {
        logS3(`   RESULTADO: ERRO JS CAPTURADO: ${result.errorOccurred.name} - ${result.errorOccurred.message}.`, "error", FNAME_RUNNER);
        document.title = `Heisenbug (CorruptABC) ERR: ${result.errorOccurred.name}`;
    } else {
        logS3(`   RESULTADO: Completou. Detalhes da sonda: ${result.toJSON_details ? JSON.stringify(result.toJSON_details) : 'N/A'}`, "good", FNAME_RUNNER);
        logS3(`   Stringify Output: ${result.stringifyResult ? JSON.stringify(result.stringifyResult) : 'N/A'}`, "info", FNAME_RUNNER);
        
        if (result.corruption_attempt_result) {
            const res_abc = result.corruption_attempt_result;
            logS3(`   Resultado da Tentativa de Corrupção ABC: Success=${res_abc.success}. Mensagem: ${res_abc.message}`, res_abc.success ? "vuln" : "warn", FNAME_RUNNER);
            if (res_abc.success) {
                 document.title = `Heisenbug (CorruptABC) SUCESSO PARCIAL!`;
            } else if (result.toJSON_details && result.toJSON_details.abc_writes_attempted) {
                 document.title = `Heisenbug (CorruptABC) TC OK, Corrupção Falhou`;
            } else {
                 document.title = `Heisenbug (CorruptABC) Test OK`;
            }
        }

        if (result.toJSON_details && result.toJSON_details.error_in_toJSON) {
            logS3(`     ERRO INTERNO NA SONDA: ${result.toJSON_details.error_in_toJSON}`, "warn", FNAME_RUNNER);
            if (!document.title.includes("SUCESSO")) document.title = `Heisenbug (CorruptABC) toJSON_ERR`;
        } else if (result.toJSON_details && result.toJSON_details.this_type_in_toJSON === "[object Object]" && result.toJSON_details.abc_writes_attempted) {
            logS3(`     !!!! TYPE CONFUSION NO ArrayBuffer VÍTIMA OBSERVADA E ESCRITAS ABC TENTADAS !!!!`, "critical", FNAME_RUNNER);
        }
    }
    logS3(`   Título da página: ${document.title}`, "info");
    await PAUSE_S3(MEDIUM_PAUSE_S3);

    logS3(`==== Estratégia de Corrupção de ArrayBufferContents CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_V20_CORRUPT_ABC}_MainOrchestrator`; 
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Tentando Corromper ArrayBufferContents ====`, 'test', FNAME_ORCHESTRATOR);

    await runHeisenbugReproStrategy_CorruptABC(); // Chama a função de estratégia renomeada

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_V20_CORRUPT_ABC)) {
        if (!document.title.includes("CRASH") && !document.title.includes("RangeError") && 
            !document.title.includes("SUCESSO") && !document.title.includes("Addr Fail") && // Ajustado para nomes de status do v20
            !document.title.includes("Corrupção Falhou") && !document.title.includes("ERR")) { 
            document.title = `${FNAME_MODULE_V20_CORRUPT_ABC} Concluído`;
        }
    }
}
