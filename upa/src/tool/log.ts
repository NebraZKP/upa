import { Logger, createLogger, format, transports } from "winston";
import * as process from "node:process";

let logger: Logger | undefined;

export function getLogger() {
  if (!logger) {
    const level = process.env["UPA_LOG_LEVEL"] || "info";
    const levels = ["debug", "info", "warning", "error"];
    logger = createLogger({
      level: level,
      transports: [
        new transports.Console({
          consoleWarnLevels: levels,
          stderrLevels: levels,
          debugStdout: false,
        }),
      ],
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
