/* eslint-env node */
module.exports = {
  extends: [
    "eslint:recommended",
    "plugin:@typescript-eslint/recommended",
    "prettier",
  ],
  parser: "@typescript-eslint/parser",
  plugins: ["@typescript-eslint"],
  root: true,
  ignorePatterns: ["dist/**", "depends/**", "node_modules/**", "docs/**"],
  rules: {
    "@typescript-eslint/no-var-requires": 0,
    "max-len": ["error", { code: 80 }],
    "linebreak-style": ["error", "unix"],
  },
};
