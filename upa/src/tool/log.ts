import { Logger, createLogger, format, transports } from "winston";
import * as process from "node:process";
import LokiTransport from "winston-loki";
import Transport from "winston-transport";

let logger: Logger | undefined;

export function getLogger() {
  if (!logger) {
    let processBinName = process.argv[1].split("/").pop();
    // Safety measure in case above returns undefined
    processBinName = processBinName ? processBinName : "upa";
    // Replace hyphens with underscores
    const job = processBinName.replace(/-/g, "_");
    const level = process.env["LOG_LEVEL"] || "info";
    const levels = ["debug", "info", "warning", "error"];
    const lokiHost = process.env["LOKI_HOST"] || undefined;
    // Default local Loki URL is "http://localhost:3100"
    const logfile = process.env[`${job}_LOGFILE`] || undefined;
    const logTransports: Transport[] = [
      new transports.Console({
        consoleWarnLevels: levels,
        stderrLevels: levels,
        debugStdout: false,
      }),
    ];

    if (logfile) {
      logTransports.push(
        new transports.File({
          filename: logfile,
          level: level,
        })
      );
    }

    if (lokiHost) {
      logTransports.push(
        new LokiTransport({
          host: lokiHost,
          json: true,
          format: format.json(),
          labels: { job },
          replaceTimestamp: true,
        })
      );
    }

    logger = createLogger({
      level: level,
      transports: logTransports,
      format: format.combine(
        format.colorize(),
        format.timestamp(),
        format.printf(({ timestamp, level, message }) => {
          return `[${timestamp}] ${level}: ${message}`;
        })
      ),
    });
  }
  return logger;
}

export function debug(msg: string) {
  getLogger().debug(msg);
}

export function info(msg: string) {
  getLogger().info(msg);
}

export function warning(msg: string) {
  getLogger().warn(msg);
}

export function error(msg: string) {
  getLogger().error(msg);
}
