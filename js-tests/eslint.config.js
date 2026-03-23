export default [
	{
		// Go template files contain ${...} placeholders that are not valid JS syntax
		// and cannot be parsed by ESLint. Exclude them from linting.
		ignores: [
			"**/node_modules/**",
			"../infrastructure/code/template/scripts.js",
			"../internal/html/ignore/ignore_scripts.js",
			"../infrastructure/code/testdata/**",
			"../domain/ide/treeview/template/js-tests/**",
		],
	},
	{
		files: ["../**/*.js"],
		languageOptions: {
			ecmaVersion: 5,
			sourceType: "script",
		},
	},
];
