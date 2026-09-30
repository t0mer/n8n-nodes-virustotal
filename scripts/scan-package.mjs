// Pre-publish check with n8n's community package scanner (the same ESLint rules the
// Creator Portal runs). The CLI only accepts a published package name, so this runs
// `analyzePackage` on the repo source and on the unpacked `npm pack` tarball.
// Usage: node scripts/scan-package.mjs <sourceDir> <unpackedTarballDir>
// Needs `npm install --no-save @n8n/scan-community-package` first.
import {
	analyzePackage,
	SOURCE_FILE_PATTERNS,
} from '@n8n/scan-community-package/scanner/scanner.mjs';

const [sourceDir, tarballDir] = process.argv.slice(2);
if (!sourceDir || !tarballDir) {
	console.error('Usage: node scripts/scan-package.mjs <sourceDir> <unpackedTarballDir>');
	process.exit(2);
}

let failed = false;
for (const [label, dir, patterns] of [
	['source', sourceDir, SOURCE_FILE_PATTERNS],
	['tarball', tarballDir, ['**/*.js', 'package.json']],
]) {
	const result = await analyzePackage(dir, patterns);
	if (result.passed) {
		console.log(`✓ ${label}: passed${result.message ? ` (${result.message})` : ''}`);
	} else {
		failed = true;
		console.error(`✗ ${label}: ${result.message}\n${result.details ?? ''}`);
	}
}
process.exit(failed ? 1 : 0);
