// js/utils.mjs (R42 - Lógica de Aritmética e Comparação robustecida)

export const KB = 1024;
export const MB = KB * KB;
export const GB = KB * KB * KB;

export class AdvancedInt64 {
    constructor(low, high) {
        this._isAdvancedInt64 = true; 
        let buffer = new Uint32Array(2);
        
        let is_one_arg = false;
        if (arguments.length === 1) { is_one_arg = true; }
        if (arguments.length === 0) { 
            low = 0; high = 0; is_one_arg = false; 
        }

        if (!is_one_arg) {
            if (typeof low !== 'number' || isNaN(low)) { low = 0; }
            if (typeof high !== 'number' || isNaN(high)) { high = 0; }
            if (low instanceof AdvancedInt64 && high === undefined) {
                buffer[0] = low.low(); buffer[1] = low.high();
                this.buffer = buffer; return;
            }
        }
        
        const check_range = (x) => Number.isInteger(x) && x >= 0 && x <= 0xFFFFFFFF;

        if (is_one_arg) {
            if (typeof (low) === 'number') {
                if (!Number.isSafeInteger(low)) { throw TypeError('number arg must be a safe integer'); }
                buffer[0] = low & 0xFFFFFFFF;
                buffer[1] = Math.floor(low / (0xFFFFFFFF + 1));
            } else if (typeof (low) === 'string') {
                let str = low;
                if (str.startsWith('0x')) { str = str.slice(2); } 
                if (str.includes('_')) str = str.replace('_', '');
                if (str.length > 16) { throw RangeError('AdvancedInt64 string input too long'); }
                str = str.padStart(16, '0'); 
                const highStr = str.substring(0, 8); const lowStr = str.substring(8, 16);
                buffer[1] = parseInt(highStr, 16); buffer[0] = parseInt(lowStr, 16);
            } else if (low instanceof AdvancedInt64) { 
                 buffer[0] = low.low(); buffer[1] = low.high();
            } else { throw TypeError('single arg must be number, hex string or AdvancedInt64'); }
        } else { 
            if (!check_range(low) || !check_range(high)) {
                throw RangeError(`low/high (${low}, ${high}) must be uint32 numbers after initial type check.`);
            }
            buffer[0] = low; buffer[1] = high;
        }
        this.buffer = buffer;
    }

    low() { return this.buffer[0]; }
    high() { return this.buffer[1]; }

    equals(other) {
        if (!isAdvancedInt64Object(other)) { return false; }
        return this.low() === other.low() && this.high() === other.high();
    }
    
    toString(hex = false) { 
        if (hex) {
            const high_str = this.high().toString(16).padStart(8, '0');
            const low_str = this.low().toString(16).padStart(8, '0');
            return `0x${high_str}${low_str}`;
        }
        return this.toNumber().toString();
     }    
    toNumber() { 
        return this.high() * (0xFFFFFFFF + 1) + this.low();
    }

    add(val) {
        if (!(val instanceof AdvancedInt64)) { 
            val = new AdvancedInt64(val); 
        }
        
        const a = this.high() >>> 16;
        const b = this.high() & 0xFFFF;
        const c = this.low() >>> 16;
        const d = this.low() & 0xFFFF;

        const other_a = val.high() >>> 16;
        const other_b = val.high() & 0xFFFF;
        const other_c = val.low() >>> 16;
        const other_d = val.low() & 0xFFFF;

        let d_new = d + other_d;
        let c_new = c + other_c + (d_new >>> 16);
        let b_new = b + other_b + (c_new >>> 16);
        let a_new = a + other_a + (b_new >>> 16);
        
        let newLow = (c_new << 16) | (d_new & 0xFFFF);
        let newHigh = (a_new << 16) | (b_new & 0xFFFF);
        
        return new AdvancedInt64(newLow, newHigh);
    }

    sub(val) { 
        if (!(val instanceof AdvancedInt64)) { 
            val = new AdvancedInt64(val);
        }
        // Negação por complemento de dois e adição
        const neg_val = new AdvancedInt64(~val.low(), ~val.high()).add(1);
        return this.add(neg_val);
    }

    and(val) {
        if (!(val instanceof AdvancedInt64)) {
            val = new AdvancedInt64(val);
        }
        return new AdvancedInt64(this.low() & val.low(), this.high() & val.high());
    }
}

export function isAdvancedInt64Object(obj) {
    // Verificação baseada na propriedade marcadora é mais robusta entre módulos
    return obj && obj._isAdvancedInt64 === true;
}

// <<<< FUNÇÃO MOVIDA PARA CÁ PARA CONSISTÊNCIA >>>>
export function advInt64LessThanOrEqual(a, b) {
    if (!isAdvancedInt64Object(a) || !isAdvancedInt64Object(b)) {
        // Silencioso para não poluir o console durante o scan
        return false; 
    }
    if (a.high() < b.high()) return true;
    if (a.high() > b.high()) return false;
    return a.low() <= b.low();
}

export async function PAUSE(ms) { 
    return new Promise(resolve => setTimeout(resolve, ms));
}

export function toHex(val, bits = 32) { 
    if (isAdvancedInt64Object(val)) {
        try {
            return val.toString(true);
        } catch(e) {
            return `AdvInt64(Error)`;
        }
    }
    return '0x' + (val >>> 0).toString(16).padStart(bits / 4, '0');
}
