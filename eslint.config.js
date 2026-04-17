/** @type {import('eslint').Linter.Config[]} */
module.exports = [
	{
		ignores: [
			"**/.claude/**",
			"**/node_modules/**",
			// Local repro clones / benchmark artifacts (not authored product JS)
			"build/**",
			// ESM files — not subject to ES5 constraint
			"eslint.config.js",
			"js-tests/**",
			// Go template files contain ${...} placeholders that are not valid JS
			// syntax and cannot be parsed by ESLint
			"infrastructure/code/template/scripts.js",
			"internal/html/ignore/ignore_scripts.js",
			"infrastructure/code/testdata/**",
			"benchmark/**",
			"domain/ide/treeview/template/js-tests/**",
			// Minified vendor polyfill — not authored code
			"infrastructure/configuration/template/js/core/polyfills.js",
		],
	},
	{
		languageOptions: {
			ecmaVersion: 5,
			sourceType: "script",
		},
	},
];
