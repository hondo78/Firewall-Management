import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { ACTION_LABEL, crNo } from '../../api'
import Icon from '../../components/icons'

/** Gemeinsame Bausteine der Tabellen im Konfigurations-Editor (Objekt- und Regeltabellen). */

const SEV_CLASS = { high: 'b-danger', medium: 'b-warn', info: '' }
export const store = {
  get(k, d) { try { const v = localStorage.getItem(k); return v == null ? d : JSON.parse(v) } catch { return d } },
  set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)) } catch { /* privater Modus */ } },
}

/** Schließt ein Menü bei Klick außerhalb oder Escape. */
export function useDismiss(open, setOpen) {
  const ref = useRef(null)
  useEffect(() => {
    if (!open) return undefined
    const onDown = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false) }
    const onKey = (e) => { if (e.key === 'Escape') { e.stopPropagation(); setOpen(false) } }
    document.addEventListener('mousedown', onDown)
    document.addEventListener('keydown', onKey, true)
    return () => { document.removeEventListener('mousedown', onDown); document.removeEventListener('keydown', onKey, true) }
  }, [open, setOpen])
  return ref
}

export function PendingBadges({ pending, draftAction }) {
  return (
    <span className="chips">
      {draftAction && <span className={`badge ${draftAction === 'add' ? 'b-ok' : draftAction === 'remove' ? 'b-danger' : 'b-warn'}`}>
        Entwurf: {ACTION_LABEL[draftAction]}</span>}
      {(pending || []).filter((p) => p.status !== 'draft').map((p) => (
        <Link key={p.change_id} to={`/changes/${p.change_id}`} className={`badge st-${p.status}`} title={`${ACTION_LABEL[p.action]} – ${p.status}`}>
          {crNo(p.number)}
        </Link>
      ))}
    </span>
  )
}

export function Analysis({ findings }) {
  if (!findings?.length) return <span className="muted small">–</span>
  const worst = findings.find((f) => f.severity === 'high') || findings.find((f) => f.severity === 'medium') || findings[0]
  return (
    <span className={`badge ${SEV_CLASS[worst.severity]}`} title={findings.map((f) => `• ${f.message}`).join('\n')}>
      {findings.length === 1 ? { any_any: 'zu offen', wan_open: 'offen (WAN)', no_log_wan: 'ohne Log', shadowed: 'verdeckt', disabled: 'inaktiv', unused: 'ungenutzt', duplicate_address: 'doppelt' }[worst.code] || worst.code : `${findings.length} Hinweise`}
    </span>
  )
}

export function IconButton({ icon, title, onClick, danger, disabled }) {
  return (
    <button className={`icon-btn ${danger ? 'danger' : ''}`} title={title} aria-label={title} onClick={onClick} disabled={disabled}>
      <Icon name={icon} size={15} />
    </button>
  )
}

export function ColumnPicker({ cols, visible, onChange, label = 'Spalten', icon = 'columns' }) {
  const [open, setOpen] = useState(false)
  const ref = useDismiss(open, setOpen)
  if (!cols.length) return null
  return (
    <div className="dropdown" ref={ref}>
      <button onClick={() => setOpen(!open)} aria-expanded={open} title="Spalten auswählen" aria-label="Spalten auswählen">
        <Icon name={icon} size={label ? 14 : 17} />{label && ` ${label}`}</button>
      {open && <div className="dropdown-menu align-right">
        {cols.map((c) => (
          <label key={c.key} className="check"><input type="checkbox" checked={visible.includes(c.key)}
            onChange={() => onChange(visible.includes(c.key) ? visible.filter((k) => k !== c.key) : [...visible, c.key])} />{c.label}</label>
        ))}
      </div>}
    </div>
  )
}

export const PAGE_SIZES = [25, 50, 100, 250]

/** Seitenfuß wie in SFOS: „1–43 von 43“ und « ‹ [Seite] › » */
export function Pager({ total, page, size, setPage, setSize }) {
  const pages = Math.max(1, Math.ceil(total / size))
  const from = total ? page * size + 1 : 0
  const to = Math.min(total, (page + 1) * size)
  return (
    <div className="sf-pager">
      <span>{from}–{to} von {total}</span>
      <div className="sf-pager-nav">
        <button className="ghost" disabled={page === 0} onClick={() => setPage(0)} aria-label="Erste Seite">«</button>
        <button className="ghost" disabled={page === 0} onClick={() => setPage(page - 1)} aria-label="Vorherige Seite">‹</button>
        <span className="sf-pager-cur">{page + 1}<span className="muted"> / {pages}</span></span>
        <button className="ghost" disabled={page >= pages - 1} onClick={() => setPage(page + 1)} aria-label="Nächste Seite">›</button>
        <button className="ghost" disabled={page >= pages - 1} onClick={() => setPage(pages - 1)} aria-label="Letzte Seite">»</button>
      </div>
      <select value={size} onChange={(e) => { setSize(Number(e.target.value)); setPage(0) }} aria-label="Einträge pro Seite" style={{ width: 'auto' }}>
        {PAGE_SIZES.map((n) => <option key={n} value={n}>{n} pro Seite</option>)}
      </select>
    </div>
  )
}

/** Seitenweise Anzeige, Seitengröße je Tabelle gemerkt */
export function usePaging(key, total) {
  const [size, setSizeState] = useState(() => store.get(`fwm.pagesize.${key}`, 50))
  const [page, setPage] = useState(0)
  const pages = Math.max(1, Math.ceil(total / size))
  const cur = Math.min(page, pages - 1)
  const setSize = (n) => { setSizeState(n); store.set(`fwm.pagesize.${key}`, n) }
  return { page: cur, size, setPage, setSize, slice: (list) => list.slice(cur * size, (cur + 1) * size) }
}

/** Zeilenmenü (⋮) – fest positioniert, damit es nicht vom Scrollbereich der Tabelle abgeschnitten wird */
export function RowMenu({ items, label }) {
  const [pos, setPos] = useState(null)
  const btn = useRef(null)
  const ref = useDismiss(!!pos, () => setPos(null))
  useEffect(() => {
    if (!pos) return undefined
    const close = () => setPos(null)
    window.addEventListener('scroll', close, true)
    window.addEventListener('resize', close)
    return () => { window.removeEventListener('scroll', close, true); window.removeEventListener('resize', close) }
  }, [pos])
  const open = () => {
    const r = btn.current.getBoundingClientRect()
    const up = r.bottom + 40 * items.length > window.innerHeight
    setPos({ right: window.innerWidth - r.right, ...(up ? { bottom: window.innerHeight - r.top } : { top: r.bottom }) })
  }
  return (
    <div ref={ref} className="row-menu">
      <button ref={btn} className="icon-btn kebab" title="Aktionen" aria-label={`Aktionen für ${label}`} aria-haspopup="menu"
        aria-expanded={!!pos} onClick={() => (pos ? setPos(null) : open())}>⋮</button>
      {pos && (
        <div className="dropdown-menu row-menu-pop" role="menu" style={{ position: 'fixed', ...pos }}>
          {items.filter(Boolean).map((it) => (
            <button key={it.label} role="menuitem" disabled={it.disabled} className={it.danger ? 'danger' : ''}
              onClick={() => { setPos(null); it.onClick() }}>
              {it.icon && <Icon name={it.icon} size={14} />} {it.label}
            </button>
          ))}
        </div>
      )}
    </div>
  )
}
