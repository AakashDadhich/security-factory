import noUnsanitized from "eslint-plugin-no-unsanitized";
import security from "eslint-plugin-security";
import tseslint from "typescript-eslint";

const files = ["**/*.{js,ts,mjs,cjs}"];

export default [
  {
    ignores: ["**/node_modules/**", "**/dist/**", "**/build/**", "**/.factory/**", "**/coverage/**"],
  },
  {
    files,
    languageOptions: {
      parser: tseslint.parser,
      sourceType: "module",
    },
    linterOptions: { reportUnusedDisableDirectives: "off" },
  },
  { ...security.configs.recommended, files },
  { ...noUnsanitized.configs.recommended, files },
];
