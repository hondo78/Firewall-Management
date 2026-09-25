import { useState } from 'react'
import { Link } from 'react-router-dom'
import { api, crNo, fmt } from '../../api'
import { DiffTable, Empty, ErrorBox, Field, useLoad } from '../../components/ui'

const REASON = { initial: 'Erster Stand', sync: 'Änderung erkannt (außerhalb des Tools)', deploy: 'Ausgerollter Antrag' }

function SummaryChips({ summary }) {
  const entries = Object.entries(summary || {})
  if (!entries.length) return <span className="muted small">–</span>
  return (
    <span className="chips">
      {entries.map(([e, s]) => (
        <span key={e} className="chip small">{e}: {s.added ? `+${s.added} ` : ''}{s.removed ? `−${s.removed} ` : ''}{s.modified ? `~${s.modified}` : ''}{s.order_changed && !s.added && !s.removed && !s.modified ? 'Reihenfolge' : ''}</span>
      ))}
    </span>
  )
}

/** Vergleich wie im Config Studio: hinzugefügt / entfernt / geändert / unverändert. */
function CompareResult({ result }) {
  const [open, setOpen] = useState({})
  if (!result.entities.length) return <Empty>Keine Unterschiede.</Empty>
  return (
    <div className="stack">
      <div className="row">
        <span className="badge b-ok">{result.totals.added} hinzugefügt</span>
        <span className="badge b-danger">{result.totals.removed} entfernt</span>
        <span className="badge b-warn">{result.totals.modified} geändert</span>
      </div>
      {result.entities.map((e) => (
        <div className="panel" key={e.entity}>
          <div className="panel-head">
            <h3>{e.label}</h3>
            <span className="muted small">{e.unchanged} unverändert{e.order_changed ? ' · Reihenfolge geändert' : ''}</span>
          </div>
          <div className="panel-pad stack">
            {e.added.map((n) => <div key={`a${n}`}><span className="badge b-ok">hinzugefügt</span> {n}</div>)}
            {e.removed.map((n) => <div key={`r${n}`}><span className="badge b-danger">entfernt</span> {n}</div>)}
            {e.modified.map((m) => (
              <div key={`m${m.name}`}>
                <button className="link" onClick={() => setOpen({ ...open, [e.entity + m.name]: !open[e.entity + m.name] })}>
                  <span className="badge b-warn">geändert</span> {m.name} ({m.fields.length} Feld{m.fields.length === 1 ? '' : 'er'})
                </button>
                {open[e.entity + m.name] && <div style={{ marginTop: 6 }}><DiffTable rows={m.fields} /></div>}
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  )
}

export default function CompareTab({ fw }) {
  const [snaps, error] = useLoad(() => api(`/firewalls/${fw.id}/snapshots`), [fw.id])
  const [others] = useLoad(() => api('/firewalls'), [])
  const [a, setA] = useState('')
  const [b, setB] = useState('current')
  const [result, setResult] = useState(null)
  const [cmpError, setCmpError] = useState('')

  const run = async (aa = a, bb = b) => {
    setCmpError('')
    try {
      const params = new URLSearchParams({ a: aa })
      if (bb.startsWith('fw:')) params.set('other_firewall', bb.slice(3))
      else params.set('b', bb)
      setResult(await api(`/firewalls/${fw.id}/compare?${params}`))
    } catch (e) { setCmpError(e.message) }
  }
  if (error) return <ErrorBox error={error} />
  if (!snaps) return null
  const label = (s) => `${fmt(s.created_at)} – ${REASON[s.reason] || s.reason}${s.change_number ? ` (${crNo(s.change_number)})` : ''}`
  return (
    <div className="stack">
      <div className="panel panel-pad">
        <div className="form-grid" style={{ alignItems: 'end' }}>
          <Field label="Stand A (älter)">
            <select value={a} onChange={(e) => setA(e.target.value)}>
              <option value="">– wählen –</option>
              <option value="current">Aktueller Stand</option>
              {snaps.map((s) => <option key={s.id} value={s.id}>{label(s)}</option>)}
            </select>
          </Field>
          <Field label="Stand B (neuer) oder andere Firewall">
            <select value={b} onChange={(e) => setB(e.target.value)}>
              <option value="current">Aktueller Stand</option>
              {snaps.map((s) => <option key={s.id} value={s.id}>{label(s)}</option>)}
              <optgroup label="Aktueller Stand einer anderen Firewall">
                {(others || []).filter((o) => o.id !== fw.id).map((o) => <option key={o.id} value={`fw:${o.id}`}>{o.name}</option>)}
              </optgroup>
            </select>
          </Field>
          <div><button className="primary" disabled={!a} onClick={() => run()}>Vergleichen</button></div>
        </div>
      </div>
      <ErrorBox error={cmpError} />
      {result && <CompareResult result={result} />}
      <div className="panel">
        <div className="panel-head"><h3>Versionsstände</h3><span className="muted small">Ein neuer Stand entsteht, sobald sich die Konfiguration ändert</span></div>
        {!snaps.length ? <Empty>Noch keine Versionsstände – bitte synchronisieren.</Empty> : (
          <div className="table-wrap"><table>
            <thead><tr><th>Zeitpunkt</th><th>Anlass</th><th>Änderungen gegenüber Vorgänger</th><th>Hash</th><th /></tr></thead>
            <tbody>
              {snaps.map((s, i) => (
                <tr key={s.id}>
                  <td className="nowrap">{fmt(s.created_at)}</td>
                  <td>{s.reason === 'sync' ? <span className="badge b-warn">{REASON.sync}</span> : REASON[s.reason] || s.reason}
                    {s.change_id && <> · <Link to={`/changes/${s.change_id}`}>{crNo(s.change_number)}</Link></>}</td>
                  <td><SummaryChips summary={s.summary} /></td>
                  <td className="mono small muted">{s.hash}</td>
                  <td className="actions">{snaps[i + 1] && <button className="ghost sm" onClick={() => { setA(snaps[i + 1].id); setB(s.id); run(snaps[i + 1].id, s.id) }}>Details</button>}</td>
                </tr>
              ))}
            </tbody>
          </table></div>
        )}
      </div>
    </div>
  )
}
