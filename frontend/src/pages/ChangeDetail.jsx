import { useEffect, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { useAuth } from '../App'
import { EVENT_LABEL, STATUS_LABEL, api, crNo, fmt } from '../api'
import { ErrorBox, Field, Modal, Progress, Status, useLoad } from '../components/ui'
import { OperationCard } from './FirewallView'
import Findings from '../components/Findings'

function DecisionBox({ cr, onDone }) {
  const [comment, setComment] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const decide = async (decision) => {
    setBusy(true)
    setError('')
    try { onDone(await api(`/changes/${cr.id}/decision`, { method: 'POST', body: { decision, comment } })) } catch (e) { setError(e.message) }
    setBusy(false)
  }
  return (
    <div className="panel panel-pad stack" style={{ borderColor: 'var(--warn)' }}>
      <h3 style={{ margin: 0 }}>Ihre Entscheidung</h3>
      <div className="muted small">Bitte prüfen Sie jede Änderung inklusive des XML-Aufrufs. Nach Ihrer Freigabe
        {cr.required_approvals - cr.approvals > 1 ? ` fehlen noch ${cr.required_approvals - cr.approvals - 1} weitere Genehmigung(en).` : ' wird der Antrag ausgerollt' + (cr.deploy_after ? ` (frühestens ${fmt(cr.deploy_after)}).` : '.')}</div>
      <Field label="Kommentar" hint="Bei Ablehnung Pflicht"><textarea rows={2} value={comment} onChange={(e) => setComment(e.target.value)} /></Field>
      <ErrorBox error={error} />
      <div className="row">
        <button className="ok" disabled={busy} onClick={() => decide('approve')}>Genehmigen</button>
        <button className="danger" disabled={busy || !comment.trim()} onClick={() => decide('reject')}>Ablehnen</button>
      </div>
    </div>
  )
}

function RevertModal({ cr, onClose, onDone }) {
  const [form, setForm] = useState({ justification: '', ticket_ref: cr.ticket_ref || '', deploy_after: '' })
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const set = (k) => (e) => setForm({ ...form, [k]: e.target.value })
  const submit = async () => {
    setBusy(true)
    setError('')
    try {
      const body = { ...form, deploy_after: form.deploy_after ? new Date(form.deploy_after).toISOString() : null }
      onDone(await api(`/changes/${cr.id}/revert`, { method: 'POST', body }))
    } catch (e) { setError(e.message) } finally { setBusy(false) }
  }
  return (
    <Modal title={`${crNo(cr.number)} rückgängig machen`} onClose={onClose}>
      <div className="stack">
        <div className="alert info small">Es wird ein neuer Antrag eingereicht, der die {cr.operations.length} Änderung(en) umkehrt.
          Auch die Rücknahme muss von einer <b>anderen Person</b> genehmigt werden (Vier-Augen-Prinzip), danach wird sie ausgerollt.</div>
        <Field label="Begründung"><textarea rows={3} value={form.justification} onChange={set('justification')} autoFocus
          placeholder="Warum wird die Änderung zurückgenommen?" /></Field>
        <div className="form-grid">
          <Field label="Ticket-Referenz"><input value={form.ticket_ref} onChange={set('ticket_ref')} /></Field>
          <Field label="Frühestens ausrollen ab" hint="leer = sofort nach Genehmigung">
            <input type="datetime-local" value={form.deploy_after} onChange={set('deploy_after')} /></Field>
        </div>
        <ErrorBox error={error} />
      </div>
      <div className="modal-foot">
        <button onClick={onClose}>Abbrechen</button>
        <button className="primary" disabled={busy || !form.justification.trim()} onClick={submit}>Rücknahme einreichen</button>
      </div>
    </Modal>
  )
}

function DeployLog({ lines }) {
  if (!lines?.length) return null
  return (
    <div className="log mono">
      {lines.map((l, i) => (
        <div key={i} className={/FEHL|KONFLIKT|WARNUNG/.test(l.msg) ? 'err' : ''}>
          <span className="ts">{new Date(l.ts).toLocaleTimeString('de-DE')}</span>{l.msg}
        </div>
      ))}
    </div>
  )
}

export default function ChangeDetail() {
  const { id } = useParams()
  const nav = useNavigate()
  const { refreshCounts } = useAuth()
  const [cr, error, reload, setCr] = useLoad(() => api(`/changes/${id}`), [id])
  const [comment, setComment] = useState('')
  const [actionError, setActionError] = useState('')
  const [reverting, setReverting] = useState(false)

  // Während des Ausrollens regelmäßig aktualisieren
  useEffect(() => {
    if (cr?.status !== 'deploying' && !(cr?.status === 'approved')) return undefined
    const t = setInterval(reload, 3000)
    return () => clearInterval(t)
  }, [cr?.status, reload])

  const act = async (fn) => {
    setActionError('')
    try { await fn(); refreshCounts() } catch (e) { setActionError(e.message) }
  }
  if (error) return <ErrorBox error={error} />
  if (!cr) return null

  const withdraw = () => act(async () => setCr(await api(`/changes/${cr.id}/withdraw`, { method: 'POST' })))
  const deploy = () => act(async () => setCr(await api(`/changes/${cr.id}/deploy`, { method: 'POST' })))
  const addComment = () => act(async () => { setCr(await api(`/changes/${cr.id}/comments`, { method: 'POST', body: { text: comment } })); setComment('') })
  const approvedBy = cr.events.filter((e) => e.kind === 'approved').map((e) => e.actor)

  return (
    <>
      <div className="page-head">
        <div>
          <div className="small"><Link to="/changes">Änderungsanträge</Link></div>
          <h1>{crNo(cr.number)} · {cr.title || 'Entwurf'}</h1>
        </div>
        <Status value={cr.status} />
        <div className="right row">
          {cr.can.deploy && <button className="primary" onClick={deploy}>{cr.status === 'failed' ? 'Erneut ausrollen' : 'Jetzt ausrollen'}</button>}
          {cr.can.revert && <button onClick={() => setReverting(true)} title="Reicht einen Antrag ein, der diese Änderungen umkehrt">Rückgängig machen …</button>}
          {cr.can.withdraw && <button className="danger" onClick={withdraw}>Zurückziehen</button>}
        </div>
      </div>
      <ErrorBox error={actionError} />
      <div className="panel fw-head">
        <div className="meta">
          <div><span>Firewall</span>{cr.firewall_archived ? <>{cr.firewall} <span className="badge">entfernt</span></> : <Link to={`/firewalls/${cr.firewall_id}`}>{cr.firewall}</Link>}</div>
          <div><span>Antragsteller</span>{cr.created_by}</div>
          <div><span>Eingereicht</span>{fmt(cr.submitted_at)}</div>
          <div><span>Ticket</span>{cr.ticket_ref || '–'}</div>
          <div><span>Genehmigungen</span><Progress value={cr.approvals} max={cr.required_approvals} /> {cr.approvals}/{cr.required_approvals}{approvedBy.length > 0 && <span className="muted"> ({approvedBy.join(', ')})</span>}</div>
          <div><span>Ausrollen ab</span>{cr.deploy_after ? fmt(cr.deploy_after) : 'sofort'}</div>
          {cr.expires_at && <div><span>Befristet bis</span>{fmt(cr.expires_at)}
            {cr.expiry_state === 'reverted' && <span className="muted"> · zurückgenommen</span>}
            {cr.expiry_state === 'failed' && <span className="text-error"> · Rücknahme fehlgeschlagen</span>}</div>}
          {cr.deployed_at && <div><span>Ausgerollt</span>{fmt(cr.deployed_at)}</div>}
          <div><span>Schreibweg</span>{{ rest: 'SFOS REST-API', central: 'Sophos Central', xmlapi: 'XML-API (alt)' }[cr.connector] || cr.connector}</div>
        </div>
      </div>
      {cr.batch?.length > 0 && (
        <div className="panel" style={{ marginBottom: 12 }}>
          <div className="panel-head"><h3>Sammelantrag · {cr.batch.length} Firewalls</h3>
            <span className="muted small">gemeinsam genehmigt, je Firewall ausgerollt</span></div>
          <div className="table-wrap"><table><tbody>{cr.batch.map((m) => (
            <tr key={m.id}><td><Link to={`/changes/${m.id}`}>{crNo(m.number)}</Link>{m.id === cr.id && <span className="muted small"> (dieser)</span>}</td>
              <td>{m.firewall}</td><td><Status value={m.status} /></td><td className="small text-error">{m.error}</td></tr>))}
          </tbody></table></div>
        </div>
      )}
      {cr.reverts && <div className="alert info small">Dieser Antrag nimmt <Link to={`/changes/${cr.reverts.id}`}>{crNo(cr.reverts.number)}</Link> zurück.</div>}
      {cr.reverted_by && <div className="alert warn small">Rücknahme beantragt bzw. erfolgt: <Link to={`/changes/${cr.reverted_by.id}`}>{crNo(cr.reverted_by.number)}</Link> ({STATUS_LABEL[cr.reverted_by.status] || cr.reverted_by.status})</div>}
      {reverting && <RevertModal cr={cr} onClose={() => setReverting(false)}
        onDone={(r) => { setReverting(false); refreshCounts(); nav(`/changes/${r.id}`) }} />}
      {cr.own && cr.status === 'pending' && <div className="alert info small">Ihr Antrag wartet auf die Genehmigung durch eine andere Person (Vier-Augen-Prinzip).</div>}
      {cr.overlaps?.length > 0 && <div className="alert warn small">Andere offene Anträge betreffen dieselben Objekte: {cr.overlaps.map((o) => <Link key={o.id} to={`/changes/${o.id}`} style={{ marginRight: 8 }}>{crNo(o.number)}</Link>)} – beim Ausrollen wird auf Abweichungen geprüft.</div>}
      {cr.error && <div className="alert error"><b>{cr.status === 'conflict' ? 'Konflikt – die Konfiguration hat sich seit dem Einreichen geändert' : 'Fehler'}:</b> {cr.error}
        {cr.status === 'conflict' && <div className="small" style={{ marginTop: 4 }}>Bitte Antrag auf Basis des aktuellen Stands neu stellen.</div>}</div>}

      <div className="grid detail-grid">
        <div className="stack">
          {cr.can.approve && <DecisionBox cr={cr} onDone={(r) => { setCr(r); refreshCounts() }} />}
          {['pending', 'approved', 'draft'].includes(cr.status) && (
            <div className="panel panel-pad stack" style={cr.analysis.some((f) => f.severity === 'high') ? { borderColor: 'var(--danger)' } : undefined}>
              <h3 style={{ margin: 0 }}>Regel-Prüfung</h3>
              <Findings findings={cr.analysis} empty="Keine neuen Auffälligkeiten durch diesen Antrag." compact />
            </div>
          )}
          <div className="panel panel-pad">
            <h3 style={{ marginTop: 0 }}>Begründung</h3>
            <div style={{ whiteSpace: 'pre-wrap' }}>{cr.justification || <span className="muted">–</span>}</div>
          </div>
          <div>
            <h2>Änderungen ({cr.operations.length})</h2>
            {cr.operations.map((op, i) => <OperationCard key={i} op={op} />)}
          </div>
          {cr.deploy_log?.length > 0 && <div><h2>Ausroll-Protokoll</h2><DeployLog lines={cr.deploy_log} /></div>}
        </div>
        <div className="panel panel-pad">
          <h3 style={{ marginTop: 0 }}>Verlauf</h3>
          <ul className="timeline">
            {cr.events.filter((e) => e.kind !== 'draft_changed' || cr.status === 'draft').map((e, i) => (
              <li key={i}>
                <div className="when">{fmt(e.ts)}</div>
                <div className="what"><b>{EVENT_LABEL[e.kind] || e.kind}</b> <span className="muted">· {e.actor}</span>
                  {e.text && <div className="txt small">{e.text}</div>}</div>
              </li>
            ))}
          </ul>
          {cr.status !== 'draft' && (
            <div className="stack" style={{ marginTop: 10 }}>
              <textarea rows={2} placeholder="Kommentar oder Rückfrage …" value={comment} onChange={(e) => setComment(e.target.value)} />
              <div><button disabled={!comment.trim()} onClick={addComment}>Kommentieren</button></div>
            </div>
          )}
        </div>
      </div>
    </>
  )
}
