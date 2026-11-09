// Copyright 2026 Insomniac-VibeLabs
// Author: Stephan Busch
// SPDX-License-Identifier: Apache-2.0
import js from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["dist/", "build/", "node_modules/", "eslint.config.js"] },
  js.configs.recommended,
  ...tseslint.configs.strictTypeChecked,
  {
    languageOptions: {
      parserOptions: { project: "./tsconfig.test.json", tsconfigRootDir: import.meta.dirname },
    },
  },
  {
    // node:test runs each test() it is given, and awaits it; the promise test() returns needs no handler.
    files: ["test/**/*.ts"],
    rules: { "@typescript-eslint/no-floating-promises": "off" },
  },
);
