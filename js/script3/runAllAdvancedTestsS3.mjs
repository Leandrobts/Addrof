// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { 
    executeTypedArrayVictimAddrofTest_Fixed,   // NOME DA FUNÇÃO ATUALIZADO
    FNAME_MODULE_TYPEDARRAY_ADDROF_V1_FIXED    // NOME DO MÓDULO ATUALIZADO
} from './testArrayBufferVictimCrash.mjs';     // O NOME DO ARQUIVO É MANTIDO CONFORME SEU USO
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs'; 
import { toHex } from '../utils.mjs';

async function runHeisenbugReproStrategy_TypedArrayVictim() { // Função renomeada para clareza
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim"; // Nome do runner atualizado
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug com TypedArray Vítima ====`, 'test', FNAME_RUNNER);  // Mensagem atualizada

    // Chama a função de teste com o nome corrigido
    const result = await executeTypedArrayVictimAddrofTest_Fixed(); 

    if (result.errorOccurred) {
        logS3(`   RESULTADO: ERRO JS CAPTURADO: ${result.errorOccurred.name} - ${result.errorOccurred.message}.`, "error", FNAME_RUNNER);
        if (result.errorOccurred.name === 'RangeError') {
            logS3(`     RangeError: Maximum call stack size exceeded OCORREU!`, "vuln", FNAME_RUNNER);
            document.title = `Heisenbug (TypedArray) RangeError!`; // Atualizado para TypedArray
         } else {
            document.title = `Heisenbug (TypedArray) ERR: ${result.errorOccurred.name}`; // Atualizado para TypedArray
         }
    } else if (result.potentiallyCrashed) {
         logS3(`   RESULTADO: CONGELAMENTO POTENCIAL (nenhum erro JS capturado). Detalhes da toJSON (se chamada): ${JSON.stringify(result.toJSON_details)}`, "critical", FNAME_RUNNER);
         if (!document.title.includes("CONGELOU")) document.title = `Heisenbug (TypedArray) CRASH/FREEZE?`; // Atualizado para TypedArray
    } else {
        logS3(`   RESULTADO: Completou. Detalhes da toJSON: ${JSON.stringify(result.toJSON_details)}`, "good", FNAME_RUNNER);
        if (result.toJSON_details && result.toJSON_details.error_in_toJSON) {
            logS3(`     ERRO INTERNO NA toJSON: ${result.toJSON_details.error_in_toJSON}`, "warn", FNAME_RUNNER);
            document.title = `Heisenbug (TypedArray) toJSON_ERR`; // Atualizado para TypedArray
        } else if (result.toJSON_details && result.toJSON_details.probe_called && 
                   (result.toJSON_details.this_type_in_toJSON !== "[object Uint8Array]" && 
                    result.toJSON_details.this_type_in_toJSON !== "[object Float64Array]") && /* Adapte se usar outro TypedArray */
                    result.toJSON_details.this_type_in_toJSON === "[object Object]") { // Confirma que se tornou [object Object]
            logS3(`     !!!! TYPE CONFUSION NO 'victim_typed_array' DETECTADA DENTRO DA toJSON !!!! Tipo de 'this': ${result.toJSON_details.this_type_in_toJSON}`, "critical", FNAME_RUNNER);
            document.title = `Heisenbug (TypedArray) TYPE CONFUSION!`; // Atualizado para TypedArray
        } else if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V1_FIXED) || document.title.includes("Probing")) {
            document.title = `Heisenbug (TypedArray) Test OK`; // Atualizado para TypedArray
        }
    }
    logS3(`   Título da página: ${document.title}`, "info");
    await PAUSE_S3(MEDIUM_PAUSE_S3);

    logS3(`==== Estratégia de Reprodução do Heisenbug com TypedArray Vítima CONCLUÍDA ====`, 'test', FNAME_RUNNER); // Mensagem atualizada
}

export async function runAllAdvancedTestsS3() {
    // Usa a constante do módulo importada corretamente
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V1_FIXED}_MainOrchestrator`; 
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Reproduzindo Heisenbug com TypedArray Vítima ====`, 'test', FNAME_ORCHESTRATOR); // Mensagem atualizada

    await runHeisenbugReproStrategy_TypedArrayVictim(); // Chama a função renomeada

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    // Ajusta a lógica do título para usar o nome do módulo correto
    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V1_FIXED)) {
        if (!document.title.includes("CRASH") && !document.title.includes("RangeError") && !document.title.includes("SUCCESS") && !document.title.includes("ERR") && !document.title.includes("TYPE CONFUSION")) {
            document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V1_FIXED} Concluído`;
        }
    }
}
