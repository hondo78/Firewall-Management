import { useEffect, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { useAuth } from '../App'
import { EVENT_LABEL, STATUS_LABEL, api, crNo, fmt } from '../api'
import { ErrorBox, Field, Modal, Progress, Status, useLoad } from '../components/ui'
import { OperationCard } from './FirewallView'
import Findings from '../components/Findings'
import { ReauthModal } from '../components/Reauth'
import { locale, t } from '../i18n'

function DecisionBox({ cr, onDone }) {
  const [comment, setComment] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [reauthFor, setReauthFor] = useState(null)
  const decide = async (decision) => {
    setBusy(true)
    setError('')
    try { onDone(await api(`/changes/${cr.id}/decision`, { method: 'POST', body: { decision, comment } })) } catch (e) {
      if (e.code === 'reauth_required') setReauthFor(decision)
      else setError(e.message)
    }
    setBusy(false)
  }
  return (
    <div className="panel panel-pad stack" style={{ borderColor: 'var(--warn)' }}>
      <h3 style={{ margin: 0 }}>{t("Ihre Entscheidung")}</h3>
      <div className="muted small">{t("Bitte prüfen Sie jede Änderung inklusive des XML-Aufrufs. Nach Ihrer Freigabe")}
        {cr.required_approvals - cr.approvals > 1 ? t(" fehlen noch {0} weitere Genehmigung(en).", cr.required_approvals - cr.approvals - 1) : t(" wird der Antrag ausgerollt") + (cr.deploy_after ? t(" (frühestens {0}).", fmt(cr.deploy_after)) : '.')}</div>
      <Field label={t("Kommentar")} hint={t("Bei Ablehnung Pflicht")}><textarea rows={2} value={comment} onChange={(e) => setComment(e.target.value)} /></Field>
      <ErrorBox error={error} />
      {reauthFor && <ReauthModal onClose={() => setReauthFor(null)} onDone={() => { const d = reauthFor; setReauthFor(null); decide(d) }} />}
      {cr.batch?.length > 1 && <div className="alert info small">{t("Sammelantrag: Ihre Entscheidung gilt für alle")} {cr.batch.length} {t("Firewalls.")}</div>}
      <div className="row">
        <button className="ok" disabled={busy} onClick={() => decide('approve')}>{t("Genehmigen")}</button>
        <button className="danger" disabled={busy || !comment.trim()} onClick={() => decide('reject')}>{t("Ablehnen")}</button>
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
    <Modal title={t("{0} rückgängig machen", crNo(cr.number))} onClose={onClose}>
      <div className="stack">
        <div className="alert info small">{t("Es wird ein neuer Antrag eingereicht, der die")} {cr.operations.length} {t("Änderung(en) umkehrt. Auch die Rücknahme muss von einer")} <b>{t("anderen Person")}</b> {t("genehmigt werden (Vier-Augen-Prinzip), danach wird sie ausgerollt.")}</div>
        <Field label={t("Begründung")}><textarea rows={3} value={form.justification} onChange={set('justification')} autoFocus
          placeholder={t("Warum wird die Änderung zurückgenommen?")} /></Field>
        <div className="form-grid">
          <Field label={t("Ticket-Referenz")}><input value={form.ticket_ref} onChange={set('ticket_ref')} /></Field>
          <Field label={t("Frühestens ausrollen ab")} hint={t("leer = sofort nach Genehmigung")}>
            <input type="datetime-local" value={form.deploy_after} onChange={set('deploy_after')} /></Field>
        </div>
        <ErrorBox error={error} />
      </div>
      <div className="modal-foot">
        <button onClick={onClose}>{t("Abbrechen")}</button>
        <button className="primary" disabled={busy || !form.justification.trim()} onClick={submit}>{t("Rücknahme einreichen")}</button>
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
          <span className="ts">{new Date(l.ts).toLocaleTimeString(locale)}</span>{l.msg}
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
          <div className="small"><Link to="/changes">{t("Änderungsanträge")}</Link></div>
          <h1>{crNo(cr.number)} · {cr.title || t("Entwurf")}</h1>
        </div>
        <Status value={cr.status} />
        <div className="right row">
          {cr.can.deploy && <button className="primary" onClick={deploy}>{cr.status === 'failed' ? t("Erneut ausrollen") : t("Jetzt ausrollen")}</button>}
          {cr.can.revert && <button onClick={() => setReverting(true)} title={t("Reicht einen Antrag ein, der diese Änderungen umkehrt")}>{t("Rückgängig machen …")}</button>}
          {cr.can.withdraw && <button className="danger" onClick={withdraw}>{t("Zurückziehen")}</button>}
        </div>
      </div>
      <ErrorBox error={actionError} />
      <div className="panel fw-head">
        <div className="meta">
          <div><span>{t("Firewall")}</span>{cr.firewall_archived ? <>{cr.firewall} <span className="badge">{t("entfernt")}</span></> : <Link to={`/firewalls/${cr.firewall_id}`}>{cr.firewall}</Link>}</div>
          <div><span>{t("Antragsteller")}</span>{cr.created_by}</div>
          <div><span>{t("Eingereicht")}</span>{fmt(cr.submitted_at)}</div>
          <div><span>{t("Ticket")}</span>{cr.ticket_ref || '–'}</div>
          <div><span>{t("Genehmigungen")}</span><Progress value={cr.approvals} max={cr.required_approvals} /> {cr.approvals}/{cr.required_approvals}{approvedBy.length > 0 && <span className="muted"> ({approvedBy.join(', ')})</span>}</div>
          <div><span>{t("Ausrollen ab")}</span>{cr.deploy_after ? fmt(cr.deploy_after) : t("sofort")}</div>
          {cr.expires_at && <div><span>{t("Befristet bis")}</span>{fmt(cr.expires_at)}
            {cr.expiry_state === 'reverted' && <span className="muted"> {t("· zurückgenommen")}</span>}
            {cr.expiry_state === 'failed' && <span className="text-error"> {t("· Rücknahme fehlgeschlagen")}</span>}</div>}
          {cr.deployed_at && <div><span>{t("Ausgerollt")}</span>{fmt(cr.deployed_at)}</div>}
          <div><span>{t("Schreibweg")}</span>{{ rest: t("SFOS REST-API"), central: t("Sophos Central"), xmlapi: t("XML-API (alt)") }[cr.connector] || cr.connector}</div>
        </div>
      </div>
      {cr.batch?.length > 0 && (
        <div className="panel" style={{ marginBottom: 12 }}>
          <div className="panel-head"><h3>{t("Sammelantrag ·")} {cr.batch.length} {t("Firewalls")}</h3>
            <span className="muted small">{t("gemeinsam genehmigt, je Firewall ausgerollt")}</span></div>
          <div className="table-wrap"><table><tbody>{cr.batch.map((m) => (
            <tr key={m.id}><td><Link to={`/changes/${m.id}`}>{crNo(m.number)}</Link>{m.id === cr.id && <span className="muted small"> {t("(dieser)")}</span>}</td>
              <td>{m.firewall}</td><td><Status value={m.status} /></td><td className="small text-error">{m.error}</td></tr>))}
          </tbody></table></div>
        </div>
      )}
      {cr.reverts && <div className="alert info small">{t("Dieser Antrag nimmt")} <Link to={`/changes/${cr.reverts.id}`}>{crNo(cr.reverts.number)}</Link> {t("zurück.")}</div>}
      {cr.reverted_by && <div className="alert warn small">{t("Rücknahme beantragt bzw. erfolgt:")} <Link to={`/changes/${cr.reverted_by.id}`}>{crNo(cr.reverted_by.number)}</Link> ({STATUS_LABEL[cr.reverted_by.status] || cr.reverted_by.status})</div>}
      {reverting && <RevertModal cr={cr} onClose={() => setReverting(false)}
        onDone={(r) => { setReverting(false); refreshCounts(); nav(`/changes/${r.id}`) }} />}
      {cr.own && cr.status === 'pending' && <div className="alert info small">{t("Ihr Antrag wartet auf die Genehmigung durch eine andere Person (Vier-Augen-Prinzip).")}</div>}
      {cr.overlaps?.length > 0 && <div className="alert warn small">{t("Andere offene Anträge betreffen dieselben Objekte:")} {cr.overlaps.map((o) => <Link key={o.id} to={`/changes/${o.id}`} style={{ marginRight: 8 }}>{crNo(o.number)}</Link>)} {t("– beim Ausrollen wird auf Abweichungen geprüft.")}</div>}
      {cr.error && <div className="alert error"><b>{cr.status === 'conflict' ? t("Konflikt – die Konfiguration hat sich seit dem Einreichen geändert") : t("Fehler")}:</b> {cr.error}
        {cr.status === 'conflict' && <div className="small" style={{ marginTop: 4 }}>{t("Bitte Antrag auf Basis des aktuellen Stands neu stellen.")}</div>}</div>}

      <div className="grid detail-grid">
        <div className="stack">
          {cr.can.approve && <DecisionBox cr={cr} onDone={(r) => { setCr(r); refreshCounts() }} />}
          {['pending', 'approved', 'draft'].includes(cr.status) && (
            <div className="panel panel-pad stack" style={cr.analysis.some((f) => f.severity === 'high') ? { borderColor: 'var(--danger)' } : undefined}>
              <h3 style={{ margin: 0 }}>{t("Regel-Prüfung")}</h3>
              <Findings findings={cr.analysis} empty={t("Keine neuen Auffälligkeiten durch diesen Antrag.")} compact />
            </div>
          )}
          <div className="panel panel-pad">
            <h3 style={{ marginTop: 0 }}>{t("Begründung")}</h3>
            <div style={{ whiteSpace: 'pre-wrap' }}>{cr.justification || <span className="muted">–</span>}</div>
          </div>
          <div>
            <h2>{t("Änderungen (")}{cr.operations.length})</h2>
            {cr.operations.map((op, i) => <OperationCard key={i} op={op} />)}
          </div>
          {cr.deploy_log?.length > 0 && <div><h2>{t("Ausroll-Protokoll")}</h2><DeployLog lines={cr.deploy_log} /></div>}
        </div>
        <div className="panel panel-pad">
          <h3 style={{ marginTop: 0 }}>{t("Verlauf")}</h3>
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
              <textarea rows={2} placeholder={t("Kommentar oder Rückfrage …")} value={comment} onChange={(e) => setComment(e.target.value)} />
              <div><button disabled={!comment.trim()} onClick={addComment}>{t("Kommentieren")}</button></div>
            </div>
          )}
        </div>
      </div>
    </>
  )
}
