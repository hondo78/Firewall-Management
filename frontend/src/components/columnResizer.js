/**
 * Veränderbare Spaltenbreiten für alle Tabellen mit Kopfzeile: Ziehgriff am rechten Rand jeder Kopfzelle,
 * Doppelklick setzt die Tabelle zurück. Breiten werden je Tabelle im Browser gespeichert (Seite + Spaltentitel).
 * Wird einmal beim Start installiert und hängt die Griffe per MutationObserver an neue Tabellen – die einzelnen
 * Tabellen-Komponenten müssen dafür nichts wissen. Tabellen mit Klasse „no-resize“ bleiben unverändert.
 */
const STORE = 'fwm.colwidths'
const MIN = 40

function load() {
  try { return JSON.parse(localStorage.getItem(STORE) || '{}') } catch { return {} }
}
function save(all) {
  try { localStorage.setItem(STORE, JSON.stringify(all)) } catch { /* privater Modus */ }
}

function headCells(table) {
  const row = table.tHead?.rows?.[0]
  return row ? [...row.cells] : []
}

function keyOf(table) {
  // Seite ohne IDs + Spaltentitel → stabil über Firewalls/Datensätze hinweg, eigene Breiten je Tabelle
  const path = window.location.pathname.replace(/\/[0-9a-f]{8}-[0-9a-f-]{27,}/gi, '/:id')
  return `${path}#${headCells(table).map((c) => c.textContent.trim()).join('|')}`
}

function applyWidths(table, widths) {
  const cells = headCells(table)
  if (!widths || widths.length !== cells.length) return false
  cells.forEach((c, i) => { c.style.width = `${widths[i]}px` })
  table.style.tableLayout = 'fixed'
  table.style.width = `${widths.reduce((a, b) => a + b, 0)}px`
  table.classList.add('cols-fixed')
  return true
}

function reset(table) {
  headCells(table).forEach((c) => { c.style.width = '' })
  table.style.tableLayout = ''
  table.style.width = ''
  table.classList.remove('cols-fixed')
}

function startDrag(e, table, index) {
  e.preventDefault()
  e.stopPropagation()
  const cells = headCells(table)
  // Beim ersten Ziehen die aktuellen Breiten übernehmen, damit sich nur die gezogene Spalte ändert
  const widths = cells.map((c) => Math.round(c.getBoundingClientRect().width))
  applyWidths(table, widths)
  const startX = e.clientX
  const start = widths[index]
  const handle = e.currentTarget
  handle.classList.add('active')
  document.body.classList.add('col-resizing')
  const move = (ev) => {
    widths[index] = Math.max(MIN, Math.round(start + ev.clientX - startX))
    applyWidths(table, widths)
  }
  const up = () => {
    document.removeEventListener('mousemove', move)
    document.removeEventListener('mouseup', up)
    handle.classList.remove('active')
    document.body.classList.remove('col-resizing')
    const all = load()
    all[table.dataset.colkey] = widths
    save(all)
  }
  document.addEventListener('mousemove', move)
  document.addEventListener('mouseup', up)
}

function enhance(table) {
  if (table.classList.contains('no-resize') || !table.tHead) return
  const key = keyOf(table)
  if (table.dataset.colkey !== key) {
    // Neue Tabelle oder andere Spalten (z. B. Spaltenauswahl) → gespeicherte Breiten dieser Variante anwenden
    reset(table)
    table.dataset.colkey = key
    applyWidths(table, load()[key])
  }
  const cells = headCells(table)
  cells.forEach((cell, i) => {
    if (i === cells.length - 1 || cell.querySelector(':scope > .col-resizer')) return
    const h = document.createElement('span')
    h.className = 'col-resizer'
    h.setAttribute('aria-hidden', 'true')
    h.title = ''
    h.addEventListener('mousedown', (e) => startDrag(e, table, headCells(table).indexOf(cell)))
    h.addEventListener('click', (e) => e.stopPropagation())
    h.addEventListener('dblclick', (e) => {
      e.stopPropagation()
      const all = load()
      delete all[table.dataset.colkey]
      save(all)
      reset(table)
    })
    cell.appendChild(h)
  })
}

export function installColumnResizer() {
  let scheduled = false
  const scan = () => {
    scheduled = false
    document.querySelectorAll('table').forEach(enhance)
  }
  const schedule = () => {
    if (!scheduled) { scheduled = true; requestAnimationFrame(scan) }
  }
  new MutationObserver(schedule).observe(document.body, { childList: true, subtree: true, characterData: true })
  window.addEventListener('popstate', schedule)
  schedule()
}
