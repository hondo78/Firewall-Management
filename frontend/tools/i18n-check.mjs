/**
 * Prüft die Übersetzungen: sammelt alle Schlüssel aus t('…')-Aufrufen und meldet je Sprache fehlende und
 * nicht mehr benutzte Einträge. Außerdem: deutsch aussehende Texte, die (noch) nicht in t() stehen.
 * Aufruf: npm run i18n:check [-- --keys datei.json]  (schreibt optional die Schlüsselliste)
 */
import fs from 'node:fs'
import path from 'node:path'
import { parse } from '@babel/parser'
import _traverse from '@babel/traverse'
const traverse = _traverse.default || _traverse

const walk = (d) => fs.readdirSync(d, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? (e.name === 'i18n' ? [] : walk(path.join(d, e.name)))
  : /\.jsx?$/.test(e.name) ? [path.join(d, e.name)] : []))
const keys = new Map()
const untranslated = []
for (const f of walk('src')) {
  const code = fs.readFileSync(f, 'utf8')
  const ast = parse(code, { sourceType: 'module', plugins: ['jsx'] })
  traverse(ast, {
    CallExpression(p) {
      if (p.node.callee.type === 'Identifier' && p.node.callee.name === 't') {
        const a = p.node.arguments[0]
        if (a?.type === 'StringLiteral') keys.set(a.value, `${f}:${a.loc.start.line}`)
        if (a?.type === 'ConditionalExpression') for (const x of [a.consequent, a.alternate]) if (x.type === 'StringLiteral') keys.set(x.value, `${f}:${x.loc.start.line}`)
      }
    },
    'StringLiteral|TemplateElement|JSXText'(p) {
      const v = p.node.type === 'TemplateElement' ? p.node.value.cooked : p.node.value
      if (!/[äöüÄÖÜß]/.test(v)) return
      const call = p.findParent((x) => x.isCallExpression() && x.node.callee.type === 'Identifier' && x.node.callee.name === 't')
      if (call && call.node.arguments[0] && p.node.start >= call.node.arguments[0].start && p.node.end <= call.node.arguments[0].end) return
      if (p.parentPath.isImportDeclaration()) return
      untranslated.push(`${f}:${p.node.loc.start.line}  ${v.replace(/\s+/g, ' ').trim().slice(0, 90)}`)
    },
  })
}
// Feste Texte aus dem Backend (Objekttypen, Rechte, Fehlermeldungen), die das Frontend übersetzt anzeigt.
// Neu erzeugen: siehe tools/README-i18n.md
for (const k of JSON.parse(fs.readFileSync('tools/i18n-backend-keys.json', 'utf8'))) if (!keys.has(k)) keys.set(k, 'backend')
const out = process.argv.indexOf('--keys')
if (out > 0) fs.writeFileSync(process.argv[out + 1], JSON.stringify([...keys.keys()].sort(), null, 1))

let problems = 0
for (const file of fs.readdirSync('src/i18n').filter((n) => /^[a-z]{2}\.js$/.test(n))) {
  const lang = file.slice(0, 2)
  const dict = (await import(path.resolve('src/i18n', file))).default
  const missing = [...keys.keys()].filter((k) => !(k in dict))
  const unused = Object.keys(dict).filter((k) => !keys.has(k))
  if (process.argv.includes('--prune') && unused.length) {
    // Nicht mehr benutzte Einträge entfernen (Datei neu schreiben)
    const keep = Object.fromEntries(Object.entries(dict).filter(([k]) => keys.has(k)))
    const body = Object.keys(keep).sort((a, b) => a.localeCompare(b, 'de')).map((k) => `  ${JSON.stringify(k)}: ${JSON.stringify(keep[k])},`).join('\n')
    const head = fs.readFileSync(path.resolve('src/i18n', file), 'utf8').split('export default {')[0]
    fs.writeFileSync(path.resolve('src/i18n', file), `${head}export default {\n${body}\n}\n`)
    console.log(`[${lang}] ${unused.length} unbenutzte Einträge entfernt`)
  }
  const badArgs = Object.entries(dict).filter(([k, v]) => (k.match(/\{\d+\}/g) || []).sort().join() !== (v.match(/\{\d+\}/g) || []).sort().join())
  console.log(`[${lang}] ${Object.keys(dict).length} Einträge, ${missing.length} fehlen, ${unused.length} unbenutzt, ${badArgs.length} mit abweichenden Platzhaltern`)
  missing.slice(0, 40).forEach((k) => console.log(`   fehlt: ${JSON.stringify(k)}  (${keys.get(k)})`))
  badArgs.forEach(([k]) => console.log(`   Platzhalter: ${JSON.stringify(k)}`))
  problems += missing.length + badArgs.length
}
console.log(`${keys.size} Schlüssel im Code; ${untranslated.length} deutsche Texte außerhalb von t():`)
untranslated.slice(0, 80).forEach((u) => console.log('   ' + u))
process.exit(problems ? 1 : 0)
