import * as pkg from "../../package.json";
import { command } from "cmd-ts";

export const version = command({
  name: "version",
  args: {},
  description: "Print the SDK version and exit",
  handler: () => {
    console.log(pkg.version);
  },
});
