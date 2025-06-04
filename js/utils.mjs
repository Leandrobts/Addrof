// js/utils.mjs (R37)

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
            if (typeof low !== 'number' || isNaN(low)) {
                low = 0;
            }
            if (typeof high !== 'number' || isNaN(high)) {
                high = 0;
            }
            if (low instanceof AdvancedInt64 && high === undefined) {
                buffer[0] = low.low();
                buffer[1] = low.high();
                this.buffer = buffer;
                return;
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

                const highStr = str.substring(0, 8);
                const lowStr = str.substring(8, 16);

                buffer[1] = parseInt(highStr, 16);
                buffer[0] = parseInt(lowStr, 16);

            } else if (low instanceof AdvancedInt64) { 
                 buffer[0] = low.low();
                 buffer[1] = low.high();
            } else {
                throw TypeError('single arg must be number, hex string or AdvancedInt64');
            }
        } else { 
            if (!check_range(low) || !check_range(high)) {
                throw RangeError(`low/high (${low}, ${high}) must be uint32 numbers after initial type check.`);
            }
            buffer[0] = low;
            buffer[1] = high;
        }
        this.buffer = buffer;
    }

    low() { return this.buffer[0]; }
    high() { return this.buffer[1]; }

    equals(other) {
        if (!isAdvancedInt64Object(other)) { return false; }
        return this.low() === other.low() && this.high() === other.high();
    }
    
    static Zero = new AdvancedInt64(0,0); 

    toString(hex = false) {
        if (!hex) { 
            if (this.high() === 0) return String(this.low());
            if (typeof BigInt !== 'undefined') {
                const val = (BigInt(this.high()) << BigInt(32)) + BigInt(this.low());
                return val.toString();
            }
            return `(H:0x${this.high().toString(16).padStart(8,'0')}, L:0x${this.low().toString(16).padStart(8,'0')})`;
        }
        return '0x' + this.high().toString(16).padStart(8, '0') + '_' + this.low().toString(16).padStart(8, '0');
    }
    
    toNumber() { 
        return this.high() * (0x100000000) + this.low();
    }

    add(val) { 
        if (!(val instanceof AdvancedInt64)) { val = new AdvancedInt64(val); }
        let low = this.low() + val.low();
        let high = this.high() + val.high() + Math.floor(low / (0xFFFFFFFF + 1));
        return new AdvancedInt64(low & 0xFFFFFFFF, high & 0xFFFFFFFF);
    }
    sub(val) { 
        if (!(val instanceof AdvancedInt64)) { val = new AdvancedInt64(val);}
        let newLow = this.low() - val.low(); let newHigh = this.high() - val.high();
        if(newLow < 0){newLow += (0xFFFFFFFF + 1); newHigh -= 1;}
        return new AdvancedInt64(newLow & 0xFFFFFFFF, newHigh & 0xFFFFFFFF);
    }
}

export function isAdvancedInt64Object(obj) {
    return obj && obj._isAdvancedInt64 === true;
}

// <<<< R37: Renomeado de volta para PAUSE e exportado >>>>
export async function PAUSE(ms) { 
    return new Promise(resolve => setTimeout(resolve, ms));
}

export function toHex(val, bits = 32) { /* ... (sem alterações da R36) ... */ }
export function stringToAdvancedInt64Array(str, nullTerminate = true) { /* ... (sem alterações da R36) ... */ }
export function advancedInt64ArrayToString(arr) { /* ... (sem alterações da R36) ... */ }
