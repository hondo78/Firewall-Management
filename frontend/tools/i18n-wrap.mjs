/**
 * Einmaliger Umbau: deutsche UI-Texte in t('…') einpacken (Formatierung bleibt erhalten – es werden nur die
 * betroffenen Quelltextstellen ersetzt). Aufruf: node tools/i18n-wrap.mjs [--write] [dateien…]
 * Ohne --write: nur anzeigen, was ersetzt würde.
 */
import fs from 'node:fs'
import path from 'node:path'
import { parse } from '@babel/parser'
import _traverse from '@babel/traverse'

const traverse = _traverse.default || _traverse
const ROOT = path.resolve('src')
const write = process.argv.includes('--write')
const only = process.argv.slice(2).filter((a) => !a.startsWith('--'))

const TEXT_ATTRS = new Set(['label', 'title', 'placeholder', 'hint', 'aria-label', 'alt', 'emptyLabel', 'none', 'desc', 'text'])
const SKIP_ATTRS = new Set(['className', 'key', 'type', 'name', 'id', 'role', 'href', 'to', 'src', 'value', 'htmlFor', 'method',
  'autoComplete', 'list', 'step', 'min', 'max', 'rel', 'target', 'accept', 'inputMode', 'pattern', 'icon', 'kind', 'entity',
  'format', 'size', 'ch', 'path', 'style', 'defaultValue', 'field'])
const SKIP_CALLEES = new Set(['api', 'download', 'upload', 'fetch', 'require', 't', 'Error', 'RegExp', 'Symbol'])
const UMLAUT = /[äöüÄÖÜß„“…–]/

// Datenwerte der Firewall-APIs (nie übersetzen)
const DATA = new Set(['Enable', 'Disable', 'Accept', 'Drop', 'Reject', 'None', 'Any', 'Network', 'Service', 'Zone', 'Range', 'List',
  'Host', 'Services', 'Bottom', 'Top', 'After', 'Before', 'All The Time', 'Any IPv4', 'Any IPv6', 'HTTPBased', 'Yes', 'No'])

// Klein geschriebene deutsche Einzelwörter, die als Anzeige-Text vorkommen
const WORDS = new Set(['aus', 'ja', 'nein', 'leer', 'inaktiv', 'nie', 'neu', 'aktiv', 'wiederkehrend', 'monatlich', 'einmalig',
  'alle', 'zulassen', 'zu offen', 'verdeckt', 'ungenutzt', 'unbegrenzt', 'streng', 'starten', 'sofort', 'planen', 'niedrig',
  'moderat', 'mittel', 'keine', 'hoch', 'geteilt', 'gestartet', 'geplant', 'garantiert', 'doppelt', 'blockieren', 'automatisch',
  'ablehnen', 'täglich', 'wöchentlich', 'protokolliert', 'unverändert', 'geändert', 'älteste', 'manuell', 'beliebig', 'immer'])

function looksLikeText(s) {
  const v = s.trim()
  if (DATA.has(v)) return false
  if (WORDS.has(v)) return true
  if (v.length < 2 || !/[A-Za-zÄÖÜäöüß]/.test(v)) return false
  if ((v.match(/\d/g) || []).length > (v.match(/[A-Za-zÄÖÜäöüß]/g) || []).length) return false   // SVG-Pfade, Zahlen
  if (/^Bearer /.test(v)) return false
  if (UMLAUT.test(v)) return true
  if (/^(https?:|\/|#|\.|\w+:\/\/)/.test(v)) return false             // URLs, Pfade, Selektoren
  if (/^[a-z0-9_.\-/:]+$/.test(v)) return false                       // Bezeichner, Schlüssel, CSS-Klassen
  if (/^[A-Z0-9_]+$/.test(v)) return false                            // KONSTANTEN, Protokolle
  if (/^[A-Za-z][a-z]*[A-Z][A-Za-z0-9]*$/.test(v)) return false       // camelCase / IPv4 / HTTPBased
  if (/\s/.test(v)) return /[A-ZÄÖÜ]/.test(v) || /[a-zäöüß]{3,} [a-zäöüß]{2,}/.test(v)
  return /^[A-ZÄÖÜ][a-zäöüß]{2,}[.:!?]?$/.test(v) || /^[A-ZÄÖÜ][a-zäöüß]+(-[A-ZÄÖÜa-zäöüß]+)+$/.test(v)
}

function calleeName(node) {
  if (node.type === 'Identifier') return node.name
  if (node.type === 'MemberExpression') return null
  return null
}

function skipByContext(p) {
  const parent = p.parentPath
  const pn = parent.node
  if (pn.type === 'ImportDeclaration' || pn.type === 'ExportNamedDeclaration' || pn.type === 'ExportAllDeclaration') return true
  if ((pn.type === 'ObjectProperty' || pn.type === 'ObjectMethod') && pn.key === p.node && !pn.computed) return true
  if (pn.type === 'MemberExpression' && pn.property === p.node) return true
  if (pn.type === 'BinaryExpression' && ['==', '===', '!=', '!==', 'in'].includes(pn.operator)) return true
  if (pn.type === 'SwitchCase') return true
  if (pn.type === 'TaggedTemplateExpression') return true
  if (pn.type === 'CallExpression' || pn.type === 'NewExpression') {
    if (pn.callee.type === 'MemberExpression') return true            // arr.join(', '), store.get('…'), s.includes('x')
    const n = calleeName(pn.callee)
    if (n && SKIP_CALLEES.has(n)) return true
    if (n === 'listOf' || n === 'names') return true                   // XML-Tag-Namen
  }
  if (pn.type === 'JSXAttribute') {
    const name = pn.name.name
    if (SKIP_ATTRS.has(name) || name.startsWith('data-')) return true
    return !TEXT_ATTRS.has(name) && !(p.node.value && /\s/.test(p.node.value) && /[A-ZÄÖÜ]/.test(p.node.value))
  }
  if (pn.type === 'JSXExpressionContainer' && parent.parentPath.node.type === 'JSXAttribute') {
    const name = parent.parentPath.node.name.name
    if (SKIP_ATTRS.has(name)) return true
  }
  // Auf der linken Seite in Array-Paaren wie [['accept', 'Annehmen']] steht der Schlüssel – der ist klein geschrieben
  return false
}

function quote(s) { return JSON.stringify(s) }

function processFile(file) {
  const code = fs.readFileSync(file, 'utf8')
  let ast
  try {
    ast = parse(code, { sourceType: 'module', plugins: ['jsx'] })
  } catch (e) {
    console.error('Parse-Fehler', file, e.message)
    return []
  }
  const edits = []
  const keys = []
  traverse(ast, {
    JSXText(p) {
      const raw = p.node.value
      const core = raw.replace(/\s+/g, ' ').trim()
      if (!looksLikeText(core) && !(core.length >= 2 && /[A-Za-zÄÖÜäöüß]{2,}/.test(core) && /[a-zäöüß]/.test(core))) return
      if (/^[\s\-–·|/()…:,.]*$/.test(core)) return
      const lead = raw.match(/^\s*/)[0]
      const trail = raw.match(/\s*$/)[0]
      // Führende/abschließende Leerzeichen ohne Zeilenumbruch sind in JSX sichtbar → erhalten
      edits.push([p.node.start, p.node.end, `${lead}{t(${quote(core)})}${trail}`])
      keys.push(core)
    },
    StringLiteral(p) {
      const v = p.node.value
      if (!looksLikeText(v) || skipByContext(p)) return
      const pn = p.parentPath.node
      if (pn.type === 'JSXAttribute') edits.push([p.node.start, p.node.end, `{t(${quote(v)})}`])
      else edits.push([p.node.start, p.node.end, `t(${quote(v)})`])
      keys.push(v)
    },
    TemplateLiteral(p) {
      const quasis = p.node.quasis.map((q) => q.value.cooked)
      const joined = quasis.join('{}')
      if (!looksLikeText(joined.replace(/\{\}/g, ' x ')) || skipByContext(p)) return
      if (p.parentPath.node.type === 'JSXExpressionContainer' && p.parentPath.parentPath.node.type === 'JSXAttribute'
        && p.parentPath.parentPath.node.name.name === 'className') return
      // Nur Texte mit Wörtern (nicht z. B. `${a}:${b}` oder CSS-Klassen)
      const words = quasis.join(' ').match(/[A-Za-zÄÖÜäöüß]{3,}/g) || []
      if (!words.length) return
      let key = ''
      p.node.quasis.forEach((q, i) => { key += q.value.cooked; if (i < p.node.expressions.length) key += `{${i}}` })
      const args = p.node.expressions.map((e) => code.slice(e.start, e.end))
      edits.push([p.node.start, p.node.end, `t(${quote(key)}${args.length ? ', ' + args.join(', ') : ''})`])
      keys.push(key)
      p.skip()
    },
  })
  if (!edits.length) return keys
  edits.sort((a, b) => b[0] - a[0])
  // Überlappungen (z. B. String in bereits ersetztem Template) verwerfen
  const clean = []
  let lastStart = Infinity
  for (const e of edits) { if (e[1] <= lastStart) { clean.push(e); lastStart = e[0] } }
  let out = code
  for (const [s, e, r] of clean) out = out.slice(0, s) + r + out.slice(e)
  if (!/import \{[^}]*\bt\b[^}]*\} from '[./]*\/?i18n'/.test(out)) {
    const rel = path.relative(path.dirname(file), path.join(ROOT, 'i18n')).replace(/\\/g, '/')
    const spec = rel.startsWith('.') ? rel : `./${rel}`
    const imports = [...out.matchAll(/^import .*$/gm)]
    const at = imports.length ? imports[imports.length - 1].index + imports[imports.length - 1][0].length : 0
    out = out.slice(0, at) + `${at ? '\n' : ''}import { t } from '${spec}'` + (at ? '' : '\n') + out.slice(at)
  }
  if (write) fs.writeFileSync(file, out)
  else console.log(`\n### ${path.relative(ROOT, file)} (${clean.length})\n` + clean.map((e) => '  ' + code.slice(e[0], e[1]).replace(/\s+/g, ' ').slice(0, 110)).reverse().join('\n'))
  return keys
}

function walk(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((d) => {
    const f = path.join(dir, d.name)
    if (d.isDirectory()) return d.name === 'i18n' ? [] : walk(f)
    return /\.(jsx?|mjs)$/.test(d.name) ? [f] : []
  })
}

const files = only.length ? only.map((f) => path.resolve(f)) : walk(ROOT)
const all = files.flatMap(processFile)
console.error(`\n${new Set(all).size} verschiedene Texte in ${files.length} Dateien`)
