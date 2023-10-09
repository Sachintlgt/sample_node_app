/*
 * @Description : Logger library for Handling error logs
 * @Author : Mohit punia
 * @Version : 1.0
 */

import * as winston from 'winston';
import * as fs from 'fs'


const loggerError = (errorMessage, callback) => {
    if (!fs.existsSync('logs'))
        fs.mkdirSync('logs');
    if (!fs.existsSync('logs/filelog-error.log'))
        fs.writeFileSync('logs/filelog-error.log', '');

    var logger = winston.createLogger({
        transports: [
            new (winston.transports.File)({
                // name: 'error-file',
                filename: 'logs/filelog-error.log',
                level: 'error'
            })
        ]
    });
    logger.error(errorMessage);
    return callback("Logged Error Message");
}

const loggerWarn = function (warningMessage, callback) {
    if (!fs.existsSync('log'))
        fs.mkdirSync('log');
    if (!fs.existsSync('log/filelog-warn.log'))
        fs.writeFileSync('log/filelog-warn.log', '');

    var logger = new (winston.Logger)({
        transports: [
            new (winston.transports.File)({
                //name: 'warn-file',
                filename: 'log/filelog-warn.log',
                level: 'warn'
            })
        ]
    });
    logger.warn(warningMessage);
    return callback("Logged Warning Message");
}

const loggerInfo = function (infoMessage, callback) {
    if (!fs.existsSync('log'))
        fs.mkdirSync('log');
    if (!fs.existsSync('log/filelog-info.log'))
        fs.writeFileSync('log/filelog-info.log', '');

    var logger = new (winston.Logger)({
        transports: [
            new (winston.transports.File)({
                //name: 'info-file',
                filename: 'log/filelog-info.log',
                level: 'info'
            })
        ]
    });
    logger.error(infoMessage);
    return callback("Logged Info Message");
}

export {loggerError, loggerWarn, loggerInfo};

