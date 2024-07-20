# Demo App Frontend

This is the frontend for the demo app. The currently deployed version can be viewed at [https://demo-app.nebra.one](https://demo-app.nebra.one). The corresponding codebase for this deployment can be found [here](https://github.com/NebraZKP/demo-app).

The code in the UPA monorepo does not include the required UPA and demo-app deployment info. To use the frontend add the following files to the `public` directory:

1. `public/instances/upa.instance.json` - The UPA instance info.
2. `public/instances/demo-app.instance.json` - The demo app instance info.
3. `public/circuit.wasm` - The demo-app circuit wasm file.
4. `public/circuit.zkey` - The demo-app circuit zkey file.

## Local Development

1. Run `yarn` to install dependencies.
2. `yarn next dev` to start the development server.
