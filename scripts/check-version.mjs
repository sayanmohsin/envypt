import { readFile } from "node:fs/promises";
import { join, resolve } from "node:path";

const root = resolve(import.meta.dirname ?? import.meta.dir, "..");
const packageJson = JSON.parse(await readFile(join(root, "package.json"), "utf8"));
const cargo = await readFile(join(root, "Cargo.toml"), "utf8");
const tag = process.env.GITHUB_REF_NAME;
const version = packageJson.version;

if (typeof version !== "string" || !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(version))
  throw new Error("package.json must contain a valid SemVer version");
if (!new RegExp(`^version = "${version.replaceAll(".", "\\.")}"`, "m").test(cargo))
  throw new Error(`Cargo.toml is not synchronized with package.json (${version})`);
if (tag?.startsWith("v") && tag.slice(1) !== version)
  throw new Error(`Git tag ${tag} does not match package.json (${version})`);

console.log(`Version contract passed: ${version}`);
