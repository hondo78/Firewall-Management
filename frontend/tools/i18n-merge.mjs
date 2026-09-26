// Führt Übersetzungen (JSON-Objekte) in src/i18n/<lang>.js zusammen: node tools/i18n-merge.mjs en teil1.json teil2.json …
// Vorhandene Einträge bleiben erhalten, neue kommen hinzu; die Datei wird alphabetisch sortiert geschrieben.
import fs from 'node:fs'
import path from 'node:path'
const [lang, ...files] = process.argv.slice(2)
const target = path.resolve('src/i18n', `${lang}.js`)
const current = fs.existsSync(target) ? (await import(target)).default : {}
const merged = { ...current }
for (const f of files) Object.assign(merged, JSON.parse(fs.readFileSync(f, 'utf8')))
const body = Object.keys(merged).sort((a, b) => a.localeCompare(b, 'de')).map((k) => `  ${JSON.stringify(k)}: ${JSON.stringify(merged[k])},`).join('\n')
fs.writeFileSync(target, `/* eslint-disable */\n// Übersetzungen Deutsch → ${lang}. Schlüssel = deutscher Originaltext (siehe src/i18n/index.js).\nexport default {\n${body}\n}\n`)
console.log(`${target}: ${Object.keys(merged).length} Einträge`)
