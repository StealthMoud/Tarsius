import chalk from 'chalk';

// colored loging helpers

const LOG_LEVELS = {
    QUIET: -1,
    INFO: 0,
    VERBOSE: 1,
    DEBUG: 2,
};

let currentLevel = LOG_LEVELS.INFO;
let logFile = null;

// set how noisy the output is
// -1=quiet, 0=normal, 1=noisy, 2=everthing
export function setVerbosity(level) {
    currentLevel = level;
}

// set a file to dump debug logs into
export function setLogFile(filepath) {
    logFile = filepath;
}

// green = good news
export function logGreen(message, ...args) {
    if (currentLevel >= LOG_LEVELS.INFO) {
        console.log(chalk.green(formatMessage(message, args)));
    }
}

// red = bad news or warnings
export function logRed(message, ...args) {
    if (currentLevel >= LOG_LEVELS.INFO) {
        console.log(chalk.red(formatMessage(message, args)));
    }
}

// blue = info stuff
export function logBlue(message, ...args) {
    if (currentLevel >= LOG_LEVELS.INFO) {
        console.log(chalk.blue(formatMessage(message, args)));
    }
}

// yellow = highlites
export function logYellow(message, ...args) {
    if (currentLevel >= LOG_LEVELS.INFO) {
        console.log(chalk.yellow(formatMessage(message, args)));
    }
}

// only shows when verbsity is cranked up
export function logVerbose(message, ...args) {
    if (currentLevel >= LOG_LEVELS.VERBOSE) {
        console.log(chalk.gray(formatMessage(message, args)));
    }
}

// format a message with {0} {1} style placeholers
function formatMessage(message, args) {
    if (!args || args.length === 0) return message;
    return message.replace(/\{(\d+)\}/g, (match, index) => {
        const i = parseInt(index, 10);
        return i < args.length ? args[i] : match;
    });
}

export { LOG_LEVELS };
