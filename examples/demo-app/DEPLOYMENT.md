# Demo-app Deployment Checklist

- Build `demo-app` and `upa`.
- Run `./scripts/build_demo` to build the demo. It will appear as a git
  repository in the `demo-app` directory.
- Deploy demo-app (If doing a new setup, or circuit/contract changes).
- Update the instance files (for re-deployed UPA or demo-app contracts):
  - `core/upa.instance`
  - `core/demo-app.instance`
  - `frontend/public/instances/demo-app.instance.json`
  - `frontend/public/instances/upa.instance.json`
- Update demo-app circuit files (if we re-ran the demo-app setup):
  - `core/circuits/circuit.zkey`
  - `core/circuits/upa_verification_key.json`
  - `core/contracts/CircuitVerifier.sol`
  - `frontend/public/circuit.zkey`
- Test and then push changes to https://github.com/NebraZKP/demo-app
