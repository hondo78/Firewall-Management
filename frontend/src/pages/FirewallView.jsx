import { useCallback, useMemo, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { useAuth } from '../App'
import { ACTION_LABEL, api, can, crNo, download, fmt } from '../api'
import { FORM_ENTITIES, ObjectEditor, RuleEditor } from '../components/Editors'
import { PRIMARY_RULES, RULE_TABLE_ENTITIES, anyRuleView, anySummary, canonical, isRestEntity, oname } from '../components/entities'
import FirewallForm from '../components/FirewallForm'
import { Chips, DiffTable, Empty, ErrorBox, Field, Modal, Status, Tabs, useLoad } from '../components/ui'
import { SyncState } from './Firewalls'
import Diagnose from '../components/Diagnose'
import AnalysisTab from './firewall/AnalysisTab'
import Editor from './firewall/Editor'
import CentralTab from './firewall/CentralTab'
import Findings from '../components/Findings'
import CompareTab from './firewall/CompareTab'
import FirmwareTab from './firewall/FirmwareTab'
import BackupsTab from './firewall/BackupsTab'
import { t } from '../i18n'

const PERM_SHORT = {
  'firewall.view': t("Lesen"), 'change.create': t("Beantragen"), 'change.approve': t("Genehmigen"), 'change.deploy': t("Ausrollen"),
  'firewall.manage': t("Verwalten"), 'firmware.manage': t("Firmware"),
}

// --- Entwurf -------------------------------------------------------------------------------------------------

export function OperationCard({ op, onRemove, open }) {
  return (
    <div className="op">
      <div className="op-head">
        <span className={`badge ${op.action === 'add' ? 'b-ok' : op.action === 'remove' ? 'b-danger' : 'b-warn'}`}>{ACTION_LABEL[op.action]}</span>
        <b>{t(op.label)}</b><span>„{op.name}“</span>
        {op.position && <span className="muted small">{t("Position:")} {{ top: t("ganz oben"), bottom: t("ganz unten"), after: t("nach „{0}“", op.position.ref), before: t("vor „{0}“", op.position.ref) }[op.position.type]}</span>}
        {onRemove && <button className="ghost sm right" onClick={onRemove}>{t("Aus Entwurf entfernen")}</button>}
      </div>
      <div className="op-body">
        {op.action === 'remove' ? <div className="muted small">{t("Objekt wird gelöscht.")}</div> : <DiffTable rows={op.diff} />}
        <details open={open}><summary>{t("API-Aufruf (")}{op.xml?.startsWith('<') ? 'XML' : 'REST'})</summary><pre className="xml">{op.xml}</pre></details>
      </div>
    </div>
  )
}

function SubmitModal({ draft, onClose, onDone, requireTicket, settings, fw }) {
  const [form, setForm] = useState({ title: draft.title || '', justification: '', ticket_ref: '', deploy_after: '', expires_at: '' })
  const [extra, setExtra] = useState([])
  const [fws] = useLoad(() => api('/firewalls'), [])
  // gleiche Formate, Recht zum Beantragen, bereits synchronisiert
  const candidates = (fws || []).filter((f) => f.id !== fw.id && f.last_sync_at && f.capabilities.format === fw.capabilities.format && f.permissions.includes('change.create'))
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const set = (k) => (e) => setForm({ ...form, [k]: e.target.value })
  const submit = async () => {
    setBusy(true)
    try {
      const body = { ...form, deploy_after: form.deploy_after ? new Date(form.deploy_after).toISOString() : null,
        expires_at: form.expires_at ? new Date(form.expires_at).toISOString() : null, extra_firewall_ids: extra }
      const r = await api(`/changes/${draft.id}/submit`, { method: 'POST', body })
      onDone(r)
    } catch (e) { setError(e.message) } finally { setBusy(false) }
  }
  return (
    <Modal title={t("Antrag {0} einreichen", crNo(draft.number))} onClose={onClose} wide>
      <div className="stack">
        <div className="alert info small">{t("Nach dem Einreichen prüft ein Approver den Antrag (Vier-Augen-Prinzip). Sie können Ihren eigenen Antrag nicht genehmigen.")}</div>
        <div className="form-grid">
          <Field label={t("Titel")}><input value={form.title} onChange={set('title')} autoFocus placeholder={t("z. B. Freigabe HTTPS für neuen Webserver")} /></Field>
          <Field label={t("Ticket-Referenz{0}", requireTicket ? ' (Pflicht)' : '')}><input value={form.ticket_ref} onChange={set('ticket_ref')} placeholder="CHG-1234" /></Field>
          <Field label={t("Frühestens ausrollen ab")} hint={t("leer = sofort nach Genehmigung")}>
            <input type="datetime-local" value={form.deploy_after} onChange={set('deploy_after')} />
          </Field>
          <Field label={t("Befristet bis")} hint={t("optional – danach wird die Änderung automatisch zurückgenommen")}>
            <input type="datetime-local" value={form.expires_at} onChange={set('expires_at')} />
          </Field>
        </div>
        {form.expires_at && <div className="alert info small">{t("Befristeter Antrag: Nach Ablauf legt das System automatisch eine Rücknahme an")}
          {settings?.temp_revert_preapproved ? t(" und rollt sie ohne erneute Freigabe aus – die Befristung ist Teil dieser Genehmigung.") : t(", die erneut genehmigt werden muss.")}</div>}
        <Field label={t("Begründung")}><textarea rows={3} value={form.justification} onChange={set('justification')}
          placeholder={t("Warum wird die Änderung benötigt? Wer hat sie angefordert?")} /></Field>
        {candidates.length > 0 && (
          <details>
            <summary>{t("Auch auf weiteren Firewalls ausrollen (Sammelantrag)")}{extra.length ? t(" – {0} ausgewählt", extra.length) : ''}</summary>
            <div className="stack" style={{ marginTop: 8 }}>
              <div className="muted small">{t("Gleiche Änderungen, einmal genehmigt, je Firewall einzeln geprüft und ausgerollt. Passt eine Änderung auf eine Firewall nicht, wird nichts eingereicht.")}</div>
              <div className="perm-grid">{candidates.map((f) => (
                <label key={f.id} className="check"><input type="checkbox" checked={extra.includes(f.id)}
                  onChange={(e) => setExtra(e.target.checked ? [...extra, f.id] : extra.filter((x) => x !== f.id))} />
                  <span>{f.name}{f.group && <span className="muted small"> · {f.group}</span>}</span></label>))}</div>
            </div>
          </details>
        )}
        {draft.analysis?.length > 0 && <div className="panel panel-pad stack" style={{ borderColor: 'var(--warn)' }}>
          <h3 style={{ margin: 0 }}>{t("Regel-Prüfung")}</h3>
          <div className="muted small">{t("Diese Befunde sieht auch der Approver. Bitte prüfen oder in der Begründung erklären.")}</div>
          <Findings findings={draft.analysis} compact />
        </div>}
        <h3>{draft.operations.length} {t("Änderung(en)")}</h3>
        {draft.operations.map((op, i) => <OperationCard key={i} op={op} />)}
        <ErrorBox error={error} />
      </div>
      <div className="modal-foot">
        <button onClick={onClose}>{t("Abbrechen")}</button>
        <button className="primary" disabled={busy || !form.title || !form.justification} onClick={submit}>{t("Zur Genehmigung einreichen")}</button>
      </div>
    </Modal>
  )
}

function DraftBar({ draft, onChanged, requireTicket, settings, fw }) {
  const [tplName, setTplName] = useState('')
  const [tplMsg, setTplMsg] = useState(null)
  const saveTemplate = async () => {
    try { await api('/templates', { method: 'POST', body: { name: tplName, change_id: draft.id } }); setTplMsg({ kind: 'ok', text: t("Vorlage „{0}“ gespeichert.", tplName) }); setTplName('') } catch (e) { setTplMsg({ kind: 'error', text: e.message }) }
  }
  const nav = useNavigate()
  const { refreshCounts } = useAuth()
  const [show, setShow] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState('')
  if (!draft?.operations?.length) return null
  const removeOp = async (i) => {
    try { await api(`/changes/${draft.id}/operations/${i}`, { method: 'DELETE' }); onChanged() } catch (e) { setError(e.message) }
  }
  const discard = async () => {
    try { await api(`/changes/${draft.id}/withdraw`, { method: 'POST' }); setShow(false); onChanged() } catch (e) { setError(e.message) }
  }
  return (
    <>
      <div className="draftbar">
        <span className="badge b-accent">{t("Entwurf")} {crNo(draft.number)}</span>
        <b>{draft.operations.length} {t("Änderung")}{draft.operations.length === 1 ? '' : 'en'}</b>
        <span className="muted small">{t("noch nicht aktiv – erst nach Genehmigung und Ausrollen")}</span>
        <div className="right row">
          <button onClick={() => setShow(true)}>{t("Anzeigen")}</button>
          <button className="primary" onClick={() => setSubmitting(true)}>{t("Einreichen …")}</button>
        </div>
      </div>
      {show && (
        <Modal title={t("Entwurf {0}", crNo(draft.number))} onClose={() => setShow(false)} wide>
          {draft.operations.map((op, i) => <OperationCard key={i} op={op} onRemove={() => removeOp(i)} />)}
          <div className="row" style={{ marginTop: 8 }}>
            <input placeholder={t("Name der Vorlage")} value={tplName} onChange={(e) => setTplName(e.target.value)} style={{ maxWidth: 280 }} />
            <button className="sm" disabled={!tplName.trim()} onClick={saveTemplate}>{t("Als Vorlage speichern")}</button>
            {tplMsg && <span className={`small ${tplMsg.kind === 'ok' ? 'text-ok' : 'text-error'}`}>{tplMsg.text}</span>}
          </div>
          <ErrorBox error={error} />
          <div className="modal-foot">
            <button className="danger" onClick={discard}>{t("Entwurf verwerfen")}</button>
            <button onClick={() => setShow(false)}>{t("Schließen")}</button>
            <button className="primary" onClick={() => { setShow(false); setSubmitting(true) }}>{t("Einreichen …")}</button>
          </div>
        </Modal>
      )}
      {submitting && <SubmitModal draft={draft} requireTicket={requireTicket} settings={settings} fw={fw} onClose={() => setSubmitting(false)}
        onDone={(cr) => { setSubmitting(false); refreshCounts(); nav(`/changes/${cr.id}`) }} />}
    </>
  )
}

// --- Weitere Tabs --------------------------------------------------------------------------------------------

function ChangesTab({ fw }) {
  const [rows] = useLoad(() => api(`/firewalls/${fw.id}/changes`), [fw.id])
  if (!rows) return null
  if (!rows.length) return <div className="panel"><Empty>{t("Noch keine Anträge für diese Firewall.")}</Empty></div>
  return (
    <div className="panel table-wrap">
      <table>
        <thead><tr><th>{t("Nr.")}</th><th>{t("Titel")}</th><th>{t("Antragsteller")}</th><th>{t("Status")}</th><th>{t("Eingereicht")}</th><th>{t("Ausgerollt")}</th></tr></thead>
        <tbody>{rows.map((c) => (
          <tr key={c.id}>
            <td><Link to={`/changes/${c.id}`}>{crNo(c.number)}</Link></td><td>{c.title}</td><td>{c.created_by}</td>
            <td><Status value={c.status} /></td><td className="small">{fmt(c.submitted_at)}</td><td className="small">{fmt(c.deployed_at)}</td>
          </tr>))}
        </tbody>
      </table>
    </div>
  )
}

function SettingsTab({ fw, onSaved }) {
  const nav = useNavigate()
  const [groups] = useLoad(() => api('/groups'), [])
  const [test, setTest] = useState(null)
  const [error, setError] = useState('')
  const [confirm, setConfirm] = useState(false)
  const runTest = async () => { setTest({ message: t("Teste …") }); setTest(await api(`/firewalls/${fw.id}/test`, { method: 'POST' })) }
  const remove = async () => {
    try { await api(`/firewalls/${fw.id}`, { method: 'DELETE' }); nav('/firewalls') } catch (e) { setError(e.message) }
  }
  return (
    <div className="grid two">
      <div className="panel panel-pad">
        <h3 style={{ marginTop: 0 }}>{fw.may_edit_connection ? t("Anbindung") : t("Allgemein")}</h3>
        {groups && <FirewallForm fw={fw} groups={groups} onSaved={onSaved} />}
      </div>
      <div className="stack">
        {fw.may_edit_connection && <>
        <div className="panel panel-pad stack">
          <h3 style={{ margin: 0 }}>{t("Verbindungstest")}</h3>
          <div><button onClick={runTest}>{t("Verbindung testen")}</button></div>
          {test && <div className={`alert ${test.ok === undefined ? 'info' : test.ok ? 'ok' : 'error'} small`}>{test.message}</div>}
        </div>
        <div className="panel panel-pad stack">
          <h3 style={{ margin: 0 }}>{t("Probelauf")}</h3>
          <div className="muted small">{t("Prüft Anmeldung, Leserechte und alle benötigten Endpunkte, bevor Änderungen ausgerollt werden.")}</div>
          <Diagnose path={`/firewalls/${fw.id}/diagnose`} />
        </div>
        </>}
        {fw.central_id && <div className="panel panel-pad small">
          <h3 style={{ marginTop: 0 }}>{t("Sophos Central")}</h3>
          <div>{t("Firewall-ID:")} <code>{fw.central_id}</code></div>
          <div>{t("Status:")} {Object.entries(fw.central_status || {}).filter(([, v]) => typeof v !== 'object').map(([k, v]) => `${k}: ${v}`).join(' · ')}</div>
          {fw.external_ips?.length > 0 && <div>{t("Externe IPs:")} {fw.external_ips.join(', ')}</div>}
        </div>}
        <div className="panel panel-pad stack">
          <h3 style={{ margin: 0 }}>{t("Aus der Verwaltung entfernen")}</h3>
          <div className="muted small">{t("Die Firewall selbst bleibt unverändert. Anträge, Versionsstände und Audit-Log bleiben erhalten (archiviert); gespeicherte Zugangsdaten werden gelöscht.")}</div>
          {!confirm ? <div><button className="danger" onClick={() => setConfirm(true)}>{t("Entfernen …")}</button></div>
            : <div className="row"><button className="danger solid" onClick={remove}>{t("Wirklich entfernen")}</button><button onClick={() => setConfirm(false)}>{t("Abbrechen")}</button></div>}
          <ErrorBox error={error} />
        </div>
      </div>
    </div>
  )
}

// --- Seite ---------------------------------------------------------------------------------------------------

export default function FirewallView() {
  const { id, tab = 'config' } = useParams()
  const nav = useNavigate()
  const { me } = useAuth()
  const [fw, error, reloadFw, setFw] = useLoad(() => api(`/firewalls/${id}`), [id])
  // Anzeigenamen der Objekttypen/Bereiche kommen vom Backend (deutsch) → hier übersetzen
  const [cfg, cfgError, reloadCfg] = useLoad(() => api(`/firewalls/${id}/config`).then((c) => ({
    ...c, entities: c.entities.map((e) => ({ ...e, label: t(e.label), section: t(e.section) })) })), [id])
  const [draft, , reloadDraft] = useLoad(() => api(`/firewalls/${id}/draft`), [id])
  const [settings] = useLoad(() => api('/settings'), [])
  const [syncing, setSyncing] = useState(false)
  const [syncMsg, setSyncMsg] = useState(null)

  const reload = useCallback(() => { reloadCfg(); reloadDraft() }, [reloadCfg, reloadDraft])
  const sync = async () => {
    setSyncing(true)
    setSyncMsg(null)
    try {
      const r = await api(`/firewalls/${id}/sync`, { method: 'POST' })
      setSyncMsg({ kind: 'ok', text: r.changed ? t("Synchronisiert – Konfiguration hat sich geändert (neuer Versionsstand).") : t("Synchronisiert – keine Änderungen.") })
    } catch (e) { setSyncMsg({ kind: 'error', text: e.message }) }
    setSyncing(false)
    reloadFw()
    reload()
  }
  if (error) return <ErrorBox error={error} />
  if (!fw) return null
  const tabs = [['config', t("Konfiguration")], ['analysis', t("Analyse")], ['compare', t("Vergleich & Versionen")], ['changes', t("Anträge")], ['backups', t("Sicherungen")],
    fw.central_id && ['firmware', t("Firmware")], fw.central_id && ['central', t("Lizenzen & Alerts")], can(me, 'firewall.manage', fw) && ['settings', t("Einstellungen")]]

  return (
    <>
      <div className="page-head">
        <div>
          <div className="small"><Link to="/firewalls">{t("Firewalls")}</Link>{fw.group && <span className="muted"> › {fw.group}</span>}</div>
          <h1>{fw.name}</h1>
        </div>
        <div className="right row">
          <button className="primary sm" disabled={syncing} onClick={sync}>{syncing ? t("Synchronisiere …") : t("Jetzt synchronisieren")}</button>
        </div>
      </div>
      <div className="panel fw-head">
        <div className="meta">
          <div><span>{t("Status")}</span><SyncState fw={fw} /></div>
          <div><span>{t("Anbindung")}</span>{fw.connector_label}</div>
          {fw.connector === 'rest' && fw.may_edit_connection && <div><span>{t("API-Key gültig bis")}</span>{fw.api_key_expires_at
            ? <span className={new Date(fw.api_key_expires_at) - Date.now() < 30 * 86400000 ? 'text-error' : ''}>{fmt(fw.api_key_expires_at).split(',')[0]}</span>
            : <span className="muted">{t("nicht hinterlegt")}</span>}</div>}
          <div><span>{t("Modell")}</span>{fw.model?.split('_')[0] || '–'}</div>
          <div><span>{t("Firmware")}</span>{fw.firmware || '–'}</div>
          <div><span>{t("Seriennummer")}</span>{fw.serial || '–'}</div>
          <div><span>{t("Hostname")}</span>{fw.hostname || fw.api_url || '–'}</div>
          <div><span>{t("Ihre Rechte")}</span>{fw.permissions.length ? fw.permissions.map((p) => PERM_SHORT[p] || p).join(', ') : '–'}</div>
        </div>
      </div>
      {fw.last_sync_error && <div className="alert error small">{t("Letzte Synchronisation fehlgeschlagen:")} {fw.last_sync_error}</div>}
      {syncMsg && <div className={`alert ${syncMsg.kind} small`}>{syncMsg.text}</div>}
      <Tabs tabs={tabs} value={tab} onChange={(t) => nav(`/firewalls/${id}/${t}`)} />
      {tab === 'config' && (cfgError ? <ErrorBox error={cfgError} /> : cfg && <Editor key={cfg.format} fw={fw} cfg={cfg} draft={draft} reload={reload} />)}
      {tab === 'analysis' && <AnalysisTab fw={fw} />}
      {tab === 'compare' && <CompareTab fw={fw} />}
      {tab === 'changes' && <ChangesTab fw={fw} />}
      {tab === 'firmware' && <FirmwareTab fw={fw} />}
      {tab === 'backups' && <BackupsTab fw={fw} onDraftChanged={reload} />}
      {tab === 'central' && <CentralTab fw={fw} />}
      {tab === 'settings' && <SettingsTab fw={fw} onSaved={(f) => { setFw({ ...fw, ...f }); reload() }} />}
      <DraftBar draft={draft} onChanged={reload} requireTicket={settings?.require_ticket} settings={settings} fw={fw} />
    </>
  )
}
