import { useEffect, useMemo, useRef, useState } from 'react'
import { STATUS_LABEL } from '../api'
import { t } from '../i18n'

export function Modal({ title, onClose, children, wide }) {
  useEffect(() => {
    const onKey = (e) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])
  return (
    <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className={`modal ${wide ? 'wide' : ''}`} role="dialog" aria-label={title}>
        <div className="modal-head">
          <h2>{title}</h2>
          <button className="icon" onClick={onClose} aria-label={t("Schließen")}>×</button>
        </div>
        {children}
      </div>
    </div>
  )
}

export function Status({ value }) {
  return <span className={`badge st-${value}`}>{STATUS_LABEL[value] || value}</span>
}

export function ErrorBox({ error }) {
  return error ? <div className="alert error">{error}</div> : null
}

export function Empty({ children }) {
  return <div className="empty">{children}</div>
}

export function Field({ label, hint, children }) {
  return (
    <label className="field">
      <span>{label}</span>
      {children}
      {hint && <small>{hint}</small>}
    </label>
  )
}

export function Tabs({ tabs, value, onChange }) {
  return (
    <div className="tabs" role="tablist">
      {tabs.filter(Boolean).map(([key, label]) => (
        <button key={key} role="tab" aria-selected={value === key} className={value === key ? 'active' : ''}
          onClick={() => onChange(key)}>{label}</button>
      ))}
    </div>
  )
}

export function Seg({ options, value, onChange }) {
  return (
    <div className="seg">
      {options.map(([key, label]) => (
        <button key={key} className={value === key ? 'active' : ''} onClick={() => onChange(key)}>{label}</button>
      ))}
    </div>
  )
}

/** Liste von Namen als Chips; leer = „Beliebig“. */
export function Chips({ items, kind, any = t("Beliebig") }) {
  if (!items?.length) return <span className="chip any">{any}</span>
  return <span className="chips">{items.map((i) => <span key={i} className={`chip ${kind || ''}`}>{i}</span>)}</span>
}

const DEPLOY_PHASE = {
  queued: t("Wartet auf ein anderes Ausrollen …"), drift: t("Lese Konfiguration (Drift-Prüfung) …"),
  apply: t("Übertrage auf die Firewall"), verify: t("Kontrolle nach dem Ausrollen …"),
}

/** Fortschritt beim Ausrollen auf die Firewall (progress kommt vom Backend, nur während „deploying“). */
export function DeployBar({ progress, compact }) {
  if (!progress) return null
  const { phase, done, total } = progress
  // Lesen/Kontrolle haben keinen Zähler: Balken für diese Phasen fest anteilig, Übertragen dazwischen
  const pct = phase === 'queued' ? 0 : phase === 'drift' ? 3
    : phase === 'verify' ? 97 : 5 + Math.round((total ? done / total : 0) * 90)
  const indeterminate = phase === 'queued' || phase === 'drift' || phase === 'verify'
  return (
    <div className={`deploybar ${compact ? 'compact' : ''}`}>
      <div className={`deploybar-track ${indeterminate ? 'busy' : ''}`}><div className="deploybar-fill" style={{ width: `${pct}%` }} /></div>
      {!compact && <div className="row small" style={{ justifyContent: 'space-between', marginTop: 4 }}>
        <span>{DEPLOY_PHASE[phase] || phase}{phase === 'apply' && progress.current && <span className="muted"> · {progress.current}</span>}</span>
        {phase === 'apply' && <b>{t("{0} von {1} Objekten", done, total)} ({pct > 95 ? 100 : Math.round((total ? done / total : 0) * 100)} %)</b>}
      </div>}
      {compact && <span className="small muted">{phase === 'apply' ? `${done}/${total}` : DEPLOY_PHASE[phase]}</span>}
    </div>
  )
}

export function Progress({ value, max }) {
  return (
    <span className="progress" title={t("{0} von {1} Genehmigungen", value, max)}>
      {Array.from({ length: max }, (_, i) => <i key={i} className={i < value ? 'on' : ''} />)}
    </span>
  )
}

/**
 * Mehrfachauswahl mit Suche. options: [{ value, kind }]
 */
export function Picker({ value, options, onChange, placeholder = t("Hinzufügen …"), emptyLabel = t("Beliebig") }) {
  const [q, setQ] = useState('')
  const [open, setOpen] = useState(false)
  const ref = useRef(null)
  useEffect(() => {
    const onDoc = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false) }
    document.addEventListener('mousedown', onDoc)
    return () => document.removeEventListener('mousedown', onDoc)
  }, [])
  const selected = new Set(value)
  const f = q.toLowerCase()
  const shown = useMemo(() => options.filter((o) => !selected.has(o.value) && o.value.toLowerCase().includes(f)).slice(0, 80),
    [options, value, f])  // eslint-disable-line react-hooks/exhaustive-deps
  const add = (v) => { onChange([...value, v]); setQ('') }
  return (
    <div className="picker" ref={ref}>
      <div className="selected">
        {value.length === 0 && <span className="chip any">{emptyLabel}</span>}
        {value.map((v) => (
          <span key={v} className="chip">{v}<button type="button" aria-label={`${v} entfernen`}
            onClick={(e) => { e.preventDefault(); onChange(value.filter((x) => x !== v)) }}>×</button></span>
        ))}
      </div>
      <input value={q} placeholder={placeholder} onFocus={() => setOpen(true)}
        onChange={(e) => { setQ(e.target.value); setOpen(true) }}
        onKeyDown={(e) => {
          if (e.key === 'Enter') { e.preventDefault(); if (shown[0]) add(shown[0].value) }
          // Escape schließt nur die Liste, nicht den umgebenden Dialog
          if (e.key === 'Escape' && open) { e.stopPropagation(); setOpen(false) }
          if (e.key === 'Tab') setOpen(false)
        }} />
      {open && shown.length > 0 && (
        <div className="options">
          {shown.map((o) => (
            // preventDefault: Picker steckt in <label> (Field) – sonst leitet der Browser den Klick nach dem Neuzeichnen
            // an das erste Bedienelement im Label weiter (das × des neuen Chips) und entfernt den Eintrag sofort wieder
            <button type="button" key={`${o.kind}:${o.value}`} onMouseDown={(e) => e.preventDefault()}
              onClick={(e) => { e.preventDefault(); add(o.value) }}>
              {o.value}{o.kind && <span className="kind">{o.kind}</span>}
            </button>
          ))}
        </div>
      )}
    </div>
  )
}

export function DiffTable({ rows }) {
  if (!rows?.length) return <div className="muted small">{t("Keine Feldänderungen.")}</div>
  return (
    <div className="table-wrap">
      <table className="diff">
        <thead><tr><th>{t("Feld")}</th><th>{t("Vorher")}</th><th>{t("Nachher")}</th></tr></thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.field}>
              <td>{r.field}</td>
              <td className={r.before != null ? 'before' : ''}>{r.before ?? '—'}</td>
              <td className={r.after != null ? 'after' : ''}>{r.after ?? '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export function useLoad(fn, deps) {
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  const [n, setN] = useState(0)
  useEffect(() => {
    let alive = true
    fn().then((d) => { if (alive) { setData(d); setError('') } }).catch((e) => alive && setError(e.message))
    return () => { alive = false }
  }, [...deps, n])  // eslint-disable-line react-hooks/exhaustive-deps
  return [data, error, () => setN((x) => x + 1), setData]
}
