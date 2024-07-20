function* walk(json) {
  if (!json) {
    return;
  }
  for (const key of Object.keys(json)) {
    const value = json[key];
    if (value == null) {
      continue;
    }
    if (typeof value !== "object") {
      yield { key, value: `${value}` };
      continue;
    }
    for (const step of walk(value)) {
      yield { key: `${key}_${step.key}`, value: step.value };
    }
  }
}

const KEY = "npm_package";

module.exports = {
  name: "plugin-envs",
  factory: () => ({
    hooks: {
      setupScriptEnvironment(project, processEnv) {
        const workspacesContainingCwd = project.workspaces
          .filter((w) => project.configuration.startingCwd.includes(w.cwd))
          // if we have nested workspaces, we need to sort based on which is included within which
          .sort((wa, wb) => {
            if (wa.cwd.includes(wb.cwd)) {
              return -1;
            }
            if (wb.cwd.includes(wa.cwd)) {
              return 1;
            }
            return 0;
          });

        if (workspacesContainingCwd.length === 0) {
          return;
        }

        // the one containing all the others is the workspace matching the current cwd
        const workspace = workspacesContainingCwd[0];

        const json = Object.assign({}, workspace.manifest.raw);

        // Unwanted fields
        delete json.author;
        delete json.contributors;
        delete json.repository;
        delete json.funding;
        delete json.license;
        delete json.readmeFilename;

        for (const step of walk(json)) {
          processEnv[`${KEY}_${step.key}`] = step.value;
        }

        const currentCmd = processEnv.npm_lifecycle_event;
        if (currentCmd) {
          try {
            processEnv["npm_lifecycle_script"] = json.scripts[currentCmd];
          } catch (e) {}
        }
      },
    },
  }),
};
