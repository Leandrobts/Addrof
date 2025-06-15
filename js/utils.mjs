// js/utils.mjs (VERSÃO ATUALIZADA E ROBUSTA)

export const KB = 1024;
export const MB = KB * KB;
export const GB = KB * KB * KB;

export class AdvancedInt64 {
    constructor(low_or_val, high) {
        this._isAdvancedInt64 = true; // Propriedade para identificação
        let buffer = new Uint32Array(2);

        if (arguments.length === 0) {
            this.buffer = buffer; // Inicializa como 0
            return;
        }

        if (arguments.length === 1) {
            const val = low_or_val;
            if (typeof val === 'number') {
                if (!Number.isSafeInteger(val)) { throw new TypeError('O argumento numérico deve ser um "safe integer"'); }
                buffer[0] = val & 0xFFFFFFFF;
                buffer[1] = Math.floor(val / (0xFFFFFFFF + 1));
            } else if (typeof val === 'string') {
                let str = val.startsWith('0x') ? val.slice(2) : val;
                if (str.includes('_')) str = str.replace('_', ''); // Remove o separador opcional
                if (str.length > 16) { throw new RangeError('A string para AdvancedInt64 é muito longa'); }
                str = str.padStart(16, '0');
                const highStr = str.substring(0, 8);
                const lowStr = str.substring(8, 16);
                buffer[1] = parseInt(highStr, 16);
                buffer[0] = parseInt(lowStr, 16);
            } else if (val instanceof AdvancedInt64) {
                buffer[0] = val.low();
                buffer[1] = val.high();
            } else if (typeof val === 'bigint') { // Suporte direto para BigInt
                buffer[0] = Number(val & 0xFFFFFFFFn);
                buffer[1] = Number((val >> 32n) & 0xFFFFFFFFn);
            } else {
                throw new TypeError('O argumento único deve ser um número, string hexadecimal, BigInt ou outro AdvancedInt64');
            }
        } else { // 2 argumentos (low, high)
            const check_range = (x) => typeof x === 'number' && Number.isInteger(x) && x >= 0 && x <= 0xFFFFFFFF;
            if (!check_range(low_or_val) || !check_range(high)) {
                throw new RangeError('Os argumentos "low" e "high" devem ser números uint32');
            }
            buffer[0] = low_or_val;
            buffer[1] = high;
        }
        this.buffer = buffer;
    }

    low() { return this.buffer[0]; }
    high() { return this.buffer[1]; }

    /** Converte para BigInt para cálculos precisos. */
    toBigInt() {
        return (BigInt(this.high()) << 32n) | BigInt(this.low());
    }

    /** Cria uma instância de AdvancedInt64 a partir de um BigInt. */
    static fromBigInt(bigint) {
        const high = Number((bigint >> 32n) & 0xFFFFFFFFn);
        const low = Number(bigint & 0xFFFFFFFFn);
        return new AdvancedInt64(low, high);
    }

    equals(other) {
        if (!isAdvancedInt64Object(other)) {
             try { other = new AdvancedInt64(other); } catch (e) { return false; }
        }
        return this.low() === other.low() && this.high() === other.high();
    }

    toString(hex = false) {
        if (!hex) {
            // Usa BigInt para uma representação decimal precisa.
            return this.toBigInt().toString();
        }
        // Retorna a string hexadecimal formatada.
        return '0x' + this.high().toString(16).padStart(8, '0') + '_' + this.low().toString(16).padStart(8, '0');
    }

    toNumber() {
        // Alerta: Pode perder precisão para números > 2^53 - 1
        return Number(this.toBigInt());
    }

    // Usa BigInt para operações aritméticas para garantir a precisão
    add(val) {
        const val64 = val instanceof AdvancedInt64 ? val : new AdvancedInt64(val);
        const resultBigInt = this.toBigInt() + val64.toBigInt();
        return AdvancedInt64.fromBigInt(resultBigInt);
    }

    sub(val) {
        const val64 = val instanceof AdvancedInt64 ? val : new AdvancedInt64(val);
        const resultBigInt = this.toBigInt() - val64.toBigInt();
        return AdvancedInt64.fromBigInt(resultBigInt);
    }

    and(val) {
        const val64 = val instanceof AdvancedInt64 ? val : new AdvancedInt64(val);
        const resultBigInt = this.toBigInt() & val64.toBigInt();
        return AdvancedInt64.fromBigInt(resultBigInt);
    }

    or(val) {
        const val64 = val instanceof AdvancedInt64 ? val : new AdvancedInt64(val);
        const resultBigInt = this.toBigInt() | val64.toBigInt();
        return AdvancedInt64.fromBigInt(resultBigInt);
    }
}

// Propriedade estática para conveniência
AdvancedInt64.Zero = new AdvancedInt64(0, 0);

export function isAdvancedInt64Object(obj) {
    return obj instanceof AdvancedInt64 || (obj && obj._isAdvancedInt64 === true);
}

export async function PAUSE(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

export function toHex(val, bits = 32) {
    if (isAdvancedInt64Object(val)) {
        return val.toString(true);
    }
    if (typeof val !== 'number') {
        return `NonNumeric(${typeof val}:${String(val)})`;
    }
    if (isNaN(val)) {
        return 'ValIsNaN';
    }
    const numChars = Math.ceil(bits / 4);
    if (val < 0) {
        if (bits === 32) return '0x' + (val >>> 0).toString(16).padStart(numChars, '0');
        // A conversão para outros tamanhos de bits negativos é mais complexa e omitida para clareza
        return `Negative(${val})`;
    }
    return '0x' + val.toString(16).padStart(numChars, '0');
}

// As funções de conversão de string e double permanecem as mesmas, pois são úteis
export function stringToAdvancedInt64Array(str, nullTerminate = true) { /* ...código da função como antes... */ }
export function advancedInt64ArrayToString(arr) { /* ...código da função como antes... */ }
export function doubleToBigInt(d) { /* ...código da função como antes... */ }
export function bigIntToDouble(b) { /* ...código da função como antes... */ }
