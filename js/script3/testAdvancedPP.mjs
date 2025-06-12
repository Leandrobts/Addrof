// js/script3/testAdvancedPP.mjs
// ARQUIVO CORRIGIDO: Agora usa as funções de utilidade do Script 3 (logS3, PAUSE_S3).

import { logS3, PAUSE_S3 } from './s3_utils.mjs';

export async function testAdvancedPPS2() {
    const FNAME = 'testAdvancedPPS2';
    logS3("--- Teste: PP Avançado (Gadgets++) ---", 'test', FNAME);

    const propsToPollute = [
        // Object.prototype
        { name: 'constructor', proto: Object.prototype, protoName: 'Object',
          gadgetCheck: (obj, pollutedValue) => (obj.constructor === pollutedValue && typeof pollutedValue !== 'function') ? 'Object.constructor foi poluído para um valor não funcional!' : null },
        { name: '__proto__', proto: Object.prototype, protoName: 'Object',
          gadgetCheck: (obj, pollutedValue) => {
            try {
                if (obj.__proto__ === pollutedValue) return `Object.prototype.__proto__ foi poluído (valor da propriedade __proto__ em instâncias)!`;
            } catch (e) { /* pode falhar */ }
            return null;
          }},
        { name: 'isAdminPPTest', proto: Object.prototype, protoName: 'Object',
          gadgetCheck: (obj, pollutedValue) => obj.isAdminPPTest === pollutedValue ? 'Nova propriedade Object.prototype.isAdminPPTest poluída com sucesso!' : null },
        { name: 'valueOf', proto: Object.prototype, protoName: 'Object',
          gadgetCheck: (obj, pollutedValue) => {
            if (obj.valueOf === pollutedValue) {
                 try { obj.valueOf(); return "Object.valueOf sobrescrito, mas ainda chamável (improvável se poluído com string)"; }
                 catch(e) { return `Object.valueOf sobrescrito e quebrou ao ser chamado! (${e.message})`; }
            } return null;
          }},
        { name: 'toString', proto: Object.prototype, protoName: 'Object',
          gadgetCheck: (obj, pollutedValue) => {
            if (obj.toString === pollutedValue) {
                 try { obj.toString(); return "Object.toString sobrescrito, mas ainda chamável (improvável se poluído com string)"; }
                 catch(e) { return `Object.toString sobrescrito e quebrou ao ser chamado! (${e.message})`; }
            } return null;
          }},
        { name: 'hasOwnProperty', proto: Object.prototype, protoName: 'Object',
          gadgetCheck: (obj, pollutedValue) => {
            if (obj.hasOwnProperty === pollutedValue) {
                 try { obj.hasOwnProperty('test'); return "Object.hasOwnProperty sobrescrito, mas ainda chamável (improvável se poluído com string)"; }
                 catch(e) { return `Object.hasOwnProperty sobrescrito e quebrou ao ser chamado! (${e.message})`; }
            } return null;
          }},

        // Element & Node prototypes
        { name: 'data-pp-test', proto: Element.prototype, protoName: 'Element', createTarget: () => document.createElement('div'),
          gadgetCheck: (obj, pollutedValue) => obj.getAttribute('data-pp-test') === pollutedValue ? 'Atributo data-pp-test via Element.prototype poluído!' : null,
          polluteLogic: (targetProto, propName, pValue) => { Object.defineProperty(targetProto, propName, { value: pValue, writable: true, configurable: true }); },
          checkLogic: (instance, propName, pValue) => instance[propName] === pValue
        },
        { name: 'innerHTML', proto: Element.prototype, protoName: 'Element', createTarget: () => document.createElement('div'),
          gadgetCheck: (obj, pollutedValue) => {
            if (Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML')?.value === pollutedValue) {
                return "A propriedade 'value' do descritor de Element.prototype.innerHTML foi poluída (altamente improvável para setters/getters nativos).";
            }
            return null;
          }
        },
        { name: 'customDataProp', proto: Node.prototype, protoName: 'Node', createTarget: () => document.createElement('div'),
          gadgetCheck: (obj, pollutedValue) => obj.customDataProp === pollutedValue ? 'Node.prototype.customDataProp poluído!' : null },


        // Array.prototype
        { name: 'customArrayProp', proto: Array.prototype, protoName: 'Array', createTarget: () => [],
          gadgetCheck: (obj, pollutedValue) => obj.customArrayProp === pollutedValue ? 'Array.prototype.customArrayProp poluído!' : null },
        { name: 'map', proto: Array.prototype, protoName: 'Array', createTarget: () => [],
          gadgetCheck: (obj, pollutedValue) => {
            if (obj.map === pollutedValue) {
                 try { obj.map(x=>x); return "Array.map sobrescrito, mas ainda chamável (improvável se poluído com string)"; }
                 catch(e) { return `Array.map sobrescrito e quebrou ao ser chamado! (${e.message})`; }
            } return null;
          }},

        // Function.prototype
        { name: 'customFuncProp', proto: Function.prototype, protoName: 'Function', createTarget: () => function f(){},
          gadgetCheck: (obj, pollutedValue) => obj.customFuncProp === pollutedValue ? 'Function.prototype.customFuncProp poluído!' : null },
        { name: 'call', proto: Function.prototype, protoName: 'Function', createTarget: () => function f(){},
          gadgetCheck: (obj, pollutedValue) => {
            if (obj.call === pollutedValue) {
                 try { obj.call(null); return "Function.call sobrescrito, mas ainda chamável (improvável se poluído com string)"; }
                 catch(e) { return `Function.call sobrescrito e quebrou ao ser chamado! (${e.message})`; }
            } return null;
          }},
    ];

    const testValue = "PP_S3_Isolated_" + Date.now();
    let successCount = 0;
    let gadgetCount = 0;
    let gadgetMessages = [];

    for (const item of propsToPollute) {
        if (!item.proto) {
            logS3(`AVISO: Protótipo não definido para ${item.name} em testAdvancedPPS2. Pulando.`, 'warn', FNAME);
            continue;
        }
        const prop = item.name;
        const targetProto = item.proto;
        const targetProtoName = item.protoName;

        let originalDescriptor = undefined;
        let wasDefined = false;
        let pollutionAttempted = false;

        try {
            originalDescriptor = Object.getOwnPropertyDescriptor(targetProto, prop);
            if (originalDescriptor) {
                wasDefined = true;
            }
        } catch (e) {
            logS3(`AVISO: Erro ao obter descritor original de ${targetProtoName}.${prop}: ${e.message}.`, 'warn', FNAME);
        }

        try {
            if (item.polluteLogic && typeof item.polluteLogic === 'function') {
                item.polluteLogic(targetProto, prop, testValue);
            } else {
                if (prop === 'innerHTML' || prop === 'outerHTML' || prop === 'textContent' || prop === 'href' || prop === 'src' || prop === 'style' || prop === 'value') {
                    logS3(`INFO: Poluição direta de protótipo DOM para '${prop}' é complexa e pulada neste refinamento. Testando em instância se possível.`, 'info', FNAME);
                } else {
                    Object.defineProperty(targetProto, prop, {
                        value: testValue,
                        writable: true,
                        configurable: true,
                        enumerable: wasDefined ? originalDescriptor.enumerable : true
                    });
                }
            }
            pollutionAttempted = true;

            let obj;
            if (item.createTarget) {
                try { obj = item.createTarget(); }
                catch (e) {
                    logS3(`AVISO: Falha ao criar objeto alvo para ${targetProtoName}.${prop}: ${e.message}`, 'warn', FNAME);
                    obj = {};
                }
            } else {
                obj = {};
            }

            let inheritedValue = undefined;
            let checkSuccessful = false;

            if (item.checkLogic && typeof item.checkLogic === 'function') {
                checkSuccessful = item.checkLogic(obj, prop, testValue);
            } else {
                try {
                    inheritedValue = obj[prop];
                    if (inheritedValue === testValue) {
                        checkSuccessful = true;
                    }
                } catch (e) {
                    logS3(`AVISO: Erro ao acessar ${prop} no objeto de teste para ${targetProtoName} após poluição: ${e.message}`, 'warn', FNAME);
                }
            }


            if (checkSuccessful) {
                logS3(`-> VULN: Herança/Efeito PP para '${targetProtoName}.${prop}' OK (valor = testValue ou checkLogic passou).`, 'vuln', FNAME);
                successCount++;

                if (item.gadgetCheck) {
                    let gadgetMsg = null;
                    try {
                        gadgetMsg = item.gadgetCheck(obj, testValue);
                    } catch(e){
                        gadgetMsg = `Erro ao executar gadgetCheck para ${prop}: ${e.message}`;
                    }
                    if (gadgetMsg) {
                        logS3(`-> GADGET? ${gadgetMsg}`, 'critical', FNAME);
                        gadgetMessages.push(`${prop}: ${gadgetMsg}`);
                        gadgetCount++;
                        const dangerousProps = ['constructor', '__proto__', 'hasOwnProperty', 'appendChild', 'addEventListener', 'map', 'call', 'apply'];
                        if (dangerousProps.includes(prop)) {
                            logS3(` ---> *** ALERTA: Potencial Gadget PP perigoso detectado para '${prop}'! ***`, 'escalation', FNAME);
                        }
                    }
                }
            } else if (pollutionAttempted) {
                logS3(`-> FAIL/INFO: Poluição de '${targetProtoName}.${prop}' tentada. Verificação de herança/efeito falhou. ` +
                      `Valor na instância: ${String(inheritedValue).substring(0,100)}`, 'good', FNAME);
            }

        } catch (e) {
            logS3(`Erro principal ao poluir/testar '${targetProtoName}.${prop}': ${e.message}`, 'error', FNAME);
        } finally {
            if (pollutionAttempted) {
                try {
                    if (wasDefined && originalDescriptor) {
                        Object.defineProperty(targetProto, prop, originalDescriptor);
                    } else if (!wasDefined && pollutionAttempted) {
                        delete targetProto[prop];
                    }
                } catch (e) {
                    logS3(`AVISO CRÍTICO: Erro INESPERADO ao limpar/restaurar ${targetProtoName}.${prop}: ${e.message}`, 'critical', FNAME);
                }
            }
        }
        await PAUSE_S3(10); // Pausa mínima entre testes de propriedade
    }

    logS3(`--- Teste PP Avançado (Refinado) Concluído (${successCount} poluições/efeitos verificados, ${gadgetCount} gadgets potenciais) ---`, 'test', FNAME);
    if (gadgetCount > 0) {
        logS3(`Resumo dos Gadgets Potenciais Detectados:`, 'critical', FNAME);
        gadgetMessages.forEach(msg => logS3(`  - ${msg}`, 'critical', FNAME));
    }
    await PAUSE_S3(); // Pausa no final da função
}
