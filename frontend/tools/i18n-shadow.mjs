// Findet t('…')-Aufrufe, bei denen „t“ lokal verdeckt ist (z. B. map((t) => …)) – die würden zur Laufzeit scheitern.
import fs from 'node:fs'
import path from 'node:path'
import { parse } from '@babel/parser'
import _traverse from '@babel/traverse'
const traverse = _traverse.default || _traverse
const walk = (d) => fs.readdirSync(d, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(path.join(d, e.name)) : /\.jsx?$/.test(e.name) ? [path.join(d, e.name)] : []))
let bad = 0
for (const f of walk('src')) {
  const code = fs.readFileSync(f, 'utf8')
  const ast = parse(code, { sourceType: 'module', plugins: ['jsx'] })
  traverse(ast, {
    CallExpression(p) {
      if (p.node.callee.type !== 'Identifier' || p.node.callee.name !== 't') return
      const b = p.scope.getBinding('t')
      if (!b || b.kind !== 'module') { bad++; console.log(`${f}:${p.node.loc.start.line} t verdeckt (${b ? b.kind : 'unbekannt'})`) }
    },
  })
}
console.log(bad ? `${bad} Probleme` : 'ok')
process.exit(bad ? 1 : 0)
