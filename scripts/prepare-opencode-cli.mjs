import { readFileSync, writeFileSync } from "node:fs";
import { gzipSync } from "node:zlib";

const binaryPath = "node_modules/@opencode/cli/bin/opencode.exe";
const outputPath = "server/opencode-cli.b64";
const binary = readFileSync(binaryPath);
const compressedBase64 = gzipSync(binary, { level: 9 }).toString("base64");
writeFileSync(outputPath, compressedBase64 + "\n");
console.log(
  `Prepared OpenCode CLI: ${binary.byteLength} bytes -> ${compressedBase64.length} base64 characters.`,
);
