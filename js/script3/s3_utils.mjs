// js/script3/s3_utils.mjs (R31)

import { logToDiv } from '../logger.mjs';
// <<<< R31: Importando pauseAsync de utils.mjs >>>>
import { pauseAsync } from '../utils.mjs'; 

export const SHORT_PAUSE_S3 = 50;
export const MEDIUM_PAUSE_S3 = 500;

export const logS3 = (message, type = 'info', funcName = '') => {
    logToDiv('output-advanced', message, type, funcName);
};

// <<<< R31: PAUSE_S3 agora usa pauseAsync >>>>
export const PAUSE_S3 = (ms = SHORT_PAUSE_S3) => pauseAsync(ms);
