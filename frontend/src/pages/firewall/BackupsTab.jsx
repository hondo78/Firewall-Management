import { Fragment, useState } from 'react'
import { Link } from 'react-router-dom'
import { useAuth } from '../../App'
import { api, download, fmt } from '../../api'
import Icon from '../../components/icons'
import { RestObjectEditor } from '../../components/RestEditors'
import { DiffTable, Empty, ErrorBox, Modal, useLoad } from '../../components/ui'
import { RowMenu } from './tableParts'
import { t } from '../../i18n'

/**
 * Sicherungen: automatische/manuelle Sicherungen der Konfiguration im Tool (Download, Anheften, Wiederherstellen
 * über den Entwurf) und der eingebaute Sicherungszeitplan der Firewall (SFOS, Änderung per Antrag).
 */

const FREQ = { daily: t("täglich"), weekly: t("wöchentlich"), monthly: t("monatlich") }
const WEEKDAY = [t("Montag"), t("Dienstag"), t("Mittwoch"), t("Donnerstag"), t("Freitag"), t("Samstag"), t("Sonntag")]
const SFOS_DAY = { sunday: t("Sonntag"), monday: t("Montag"), tuesday: t("Dienstag"), wednesday: t("Mittwoch"), thursday: t("Donnerstag"), friday: t("Freitag"), saturday: t("Samstag") }
const STORAGE = { local: t("Lokal auf der Firewall"), ftp: 'FTP-Server', email: 'E-Mail' }
const kb = (n) => (n < 1024 * 1024 ? `${Math.max(1, Math.round(n / 1024))} KB` : `${(n / 1024 / 1024).toFixed(1)} MB`)
const two = (n) => String(n ?? 0).padStart(2, '0')

export function scheduleText(s) {
  if (!s.enabled) return t("aus")
  const when = s.frequency === 'weekly' ? `jeden ${WEEKDAY[s.weekday]}` : s.frequency === 'monthly' ? t("am {0}. des Monats", s.monthday) : t("täglich")
  return t("{0} um {1} Uhr", when, s.time)
}

function sfosSchedule(sc) {
  if (!sc || sc.frequency === 'never') return t("nie")
  const time = t("{0}:{1} Uhr", two(sc.hour), two(sc.minute))
  if (sc.frequency === 'weekly') return t("wöchentlich, {0}, {1}", SFOS_DAY[sc.dayOfWeek] || sc.dayOfWeek, time)
  if (sc.frequency === 'monthly') return t("monatlich am {0}., {1}", sc.dayOfMonth, time)
  return `${FREQ[sc.frequency] || sc.frequency}, ${time}`
}

const STATUS = [['changed', t("Abweichend")], ['new', t("Nur in der Sicherung")], ['removed', t("Nur aktuell vorhanden")]]

function RestoreModal({ fw, backup, review, onClose, onApplied }) {
  const [tab, setTab] = useState(review.counts.changed ? 'changed' : review.counts.new ? 'new' : 'removed')
  // Löschen nur nach bewusster Auswahl
  const [sel, setSel] = useState(() => new Set(review.items.filter((i) => i.status !== 'removed').map((i) => i.key)))
  const [open, setOpen] = useState(null)
  const [q, setQ] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const f = q.toLowerCase()
  const list = review.items.filter((i) => i.status === tab && (!f || `${i.name} ${i.label}`.toLowerCase().includes(f)))
  const groups = list.reduce((m, i) => ({ ...m, [t(i.label)]: [...(m[t(i.label)] || []), i] }), {})
  const toggle = (k) => { const n = new Set(sel); n.has(k) ? n.delete(k) : n.add(k); setSel(n) }
  const toggleAll = (items) => { const n = new Set(sel); const all = items.every((i) => n.has(i.key)); items.forEach((i) => (all ? n.delete(i.key) : n.add(i.key))); setSel(n) }
  const removals = review.items.filter((i) => i.status === 'removed' && sel.has(i.key)).length
  const apply = async () => {
    setBusy(true)
    setError('')
    try {
      onApplied(await api(`/firewalls/${fw.id}/backups/${backup.id}/restore/apply`, { method: 'POST', body: { token: review.token, keys: [...sel] } }))
    } catch (e) { setError(e.message) }
    setBusy(false)
  }
  const total = review.items.length
  return (
    <Modal title={t("Wiederherstellen: Sicherung vom {0}", fmt(backup.created_at))} onClose={onClose} wide>
      <div className="stack">
        <div className="muted small">{t("Unterschiede zwischen der Sicherung und dem aktuellen Stand von „")}{fw.name}{t("“. Ausgewählte Punkte landen in Ihrem Entwurf und werden erst nach Vier-Augen-Freigabe ausgerollt – auf der Firewall ändert sich jetzt nichts.")}</div>
        {!total ? <div className="alert ok small">{t("Der aktuelle Stand entspricht der Sicherung – nichts wiederherzustellen.")}</div> : <>
          <div className="seg" style={{ alignSelf: 'flex-start' }}>
            {STATUS.map(([k, l]) => <button key={k} className={tab === k ? 'active' : ''} onClick={() => setTab(k)}>{l} ({review.counts[k]})</button>)}
          </div>
          {tab === 'removed' && <div className="alert warn small">{t("Diese Objekte gab es zum Zeitpunkt der Sicherung noch nicht. Ausgewählte werden gelöscht – nur auswählen, wenn sie wirklich weg sollen.")}</div>}
          <input placeholder={t("Filtern …")} value={q} onChange={(e) => setQ(e.target.value)} aria-label={t("Einträge filtern")} />
          <div className="table-wrap" style={{ maxHeight: 420, overflowY: 'auto' }}>
            {!list.length ? <Empty>{t("Keine Einträge.")}</Empty> : <table><tbody>
              {Object.entries(groups).map(([label, items]) => (
                <Fragment key={label}>
                  <tr className="group-row"><td colSpan={4}>
                    <input type="checkbox" checked={items.every((i) => sel.has(i.key))} onChange={() => toggleAll(items)} style={{ marginRight: 8 }} aria-label={t("{0} alle auswählen", label)} />
                    <b>{label}</b> <span className="muted small">({items.length})</span></td></tr>
                  {items.map((i) => (
                    <Fragment key={i.key}>
                      <tr>
                        <td style={{ width: 28 }}><input type="checkbox" checked={sel.has(i.key)} onChange={() => toggle(i.key)} aria-label={t("{0} auswählen", i.name)} /></td>
                        <td>{i.name}</td>
                        <td className="small muted">{i.status === 'changed' ? t("{0} Feld(er) abweichend", i.diff.length) : i.status === 'new' ? t("wird angelegt") : t("wird gelöscht")}</td>
                        <td className="actions">{i.diff?.length > 0 && <button className="ghost sm" onClick={() => setOpen(open === i.key ? null : i.key)}>{t("Unterschiede")}</button>}</td>
                      </tr>
                      {open === i.key && <tr><td colSpan={4}><div className="muted small" style={{ marginBottom: 4 }}>{t("„Vorher“ = aktuell, „Nachher“ = Stand der Sicherung")}</div><DiffTable rows={i.diff} /></td></tr>}
                    </Fragment>
                  ))}
                </Fragment>
              ))}
            </tbody></table>}
          </div>
          <div className="muted small">{t("Hinweis: Die Reihenfolge bestehender Regeln wird nicht zurückgesetzt – wiederhergestellte Regeln werden an ihrer früheren Position eingefügt.")}</div>
        </>}
        <ErrorBox error={error} />
        <div className="modal-foot">
          <button onClick={onClose}>{t("Abbrechen")}</button>
          {total > 0 && <button className="primary" disabled={busy || !sel.size} onClick={apply}>
            {busy ? t("Übernehme …") : t("{0} Änderungen in den Entwurf{1}", sel.size, removals ? t(" (davon {0} löschen)", removals) : '')}</button>}
        </div>
      </div>
    </Modal>
  )
}

function SfosCard({ fw, sfos, mayEdit, onDraft }) {
  const [editing, setEditing] = useState(false)
  return (
    <div className="panel panel-pad stack">
      <div className="row between">
        <h3 style={{ margin: 0 }}><Icon name="clock" size={17} /> {t("Sicherungszeitplan der Firewall")}</h3>
        {sfos && mayEdit && <button onClick={() => setEditing(true)}><Icon name="edit" size={13} /> {t("Ändern (per Antrag)")}</button>}
      </div>
      <div className="muted small">{t("Die eingebaute SFOS-Sicherung (Sicherung & Firmware › Sicherung & Wiederherstellung) erzeugt eine vollständige .bak-Datei inkl. Zertifikaten. Die REST-API kann diese Datei nicht abrufen – hier lässt sich nur ihr Zeitplan steuern.")}</div>
      {!sfos ? <div className="alert info small">{t("Nicht verfügbar: Die Firewall liefert den Sicherungszeitplan nicht. Das API-Profil braucht Leserecht für „System › Sicherung“ (erscheint nach der nächsten Synchronisation).")}</div> : (
        <div className="sf-details">
          <div>
            <div className="sf-line"><span>{t("Zeitplan")}</span><div>{sfosSchedule(sfos.schedule)}</div></div>
            <div className="sf-line"><span>{t("Ziel")}</span><div>{STORAGE[sfos.backupStorage] || sfos.backupStorage}</div></div>
            <div className="sf-line"><span>{t("Präfix")}</span><div>{sfos.backupPrefix || '–'}</div></div>
          </div>
          <div>
            {sfos.backupStorage === 'ftp' && <>
              <div className="sf-line"><span>{t("FTP-Server")}</span><div>{sfos.ftp?.server || '–'}</div></div>
              <div className="sf-line"><span>{t("Pfad")}</span><div>{sfos.ftp?.path || '–'}</div></div>
              <div className="sf-line"><span>{t("Benutzer")}</span><div>{sfos.ftp?.username || '–'}</div></div>
            </>}
            {sfos.backupStorage === 'email' && <div className="sf-line"><span>{t("Empfänger")}</span><div>{(sfos.emailRecipients || []).join(', ') || '–'}</div></div>}
            {sfos.schedule?.frequency === 'never' && <div className="alert warn small" style={{ marginTop: 6 }}>{t("Die Firewall sichert sich nicht selbst.")}</div>}
          </div>
        </div>
      )}
      {editing && <RestObjectEditor entity="backupSettings" label={t("Sicherungs-Zeitplan")} config={{}} object={sfos}
        onClose={() => setEditing(false)}
        onSubmit={async (op) => { const r = await api(`/firewalls/${fw.id}/draft/operations`, { method: 'POST', body: op }); onDraft(); return r }} />}
    </div>
  )
}

export default function BackupsTab({ fw, onDraftChanged }) {
  const { me } = useAuth()
  const [data, error, reload] = useLoad(() => api(`/firewalls/${fw.id}/backups`), [fw.id])
  const [busy, setBusy] = useState(false)
  const [note, setNote] = useState('')
  const [msg, setMsg] = useState(null)
  const [restore, setRestore] = useState(null)
  const [confirmDel, setConfirmDel] = useState(null)
  if (error) return <ErrorBox error={error} />
  if (!data) return null
  const s = data.schedule
  const isAdmin = me.is_superadmin || me.permissions.global.includes('admin')

  const backupNow = async () => {
    setBusy(true)
    setMsg({ kind: 'info', text: t("Lese die Konfiguration von der Firewall …") })
    try {
      const b = await api(`/firewalls/${fw.id}/backups`, { method: 'POST', body: { note } })
      setMsg({ kind: 'ok', text: t("Gesichert: {0} Objekte ({1}).", b.object_count, kb(b.size)) })
      setNote('')
    } catch (e) { setMsg({ kind: 'error', text: e.message }) }
    setBusy(false)
    reload()
  }
  const patch = async (b, body) => {
    try { await api(`/firewalls/${fw.id}/backups/${b.id}`, { method: 'PATCH', body }); reload() } catch (e) { setMsg({ kind: 'error', text: e.message }) }
  }
  const remove = async (b) => {
    setConfirmDel(null)
    try { await api(`/firewalls/${fw.id}/backups/${b.id}`, { method: 'DELETE' }); reload() } catch (e) { setMsg({ kind: 'error', text: e.message }) }
  }
  const startRestore = async (b) => {
    setMsg(null)
    try { setRestore({ backup: b, review: await api(`/firewalls/${fw.id}/backups/${b.id}/restore/review`, { method: 'POST' }) }) } catch (e) { setMsg({ kind: 'error', text: e.message }) }
  }
  const stamp = (b) => new Date(b.created_at).toISOString().slice(0, 16).replace(/[T:]/g, '-')

  return (
    <div className="stack">
      <div className="grid two">
        <div className="panel panel-pad stack">
          <div className="row between">
            <h3 style={{ margin: 0 }}><Icon name="download" size={17} /> {t("Automatische Sicherung im Tool")}</h3>
            {isAdmin && <Link to="/admin/settings" className="small">{t("Zeitplan ändern")}</Link>}
          </div>
          <div className="sf-details">
            <div>
              <div className="sf-line"><span>{t("Zeitplan")}</span><div>{scheduleText(s)}</div></div>
              <div className="sf-line"><span>{t("Nächste")}</span><div>{s.enabled && s.next_run ? fmt(s.next_run) : '–'}</div></div>
            </div>
            <div>
              <div className="sf-line"><span>{t("Aufbewahrung")}</span><div>{t("die letzten")} {s.keep} {t("(angeheftete immer)")}</div></div>
              <div className="sf-line"><span>{t("Zusätzlich als Datei")}</span><div>{s.to_directory ? t("ja (Verzeichnis backups/)") : t("nein")}</div></div>
            </div>
          </div>
          <div className="muted small">{t("Gesichert wird die vollständige per API gelesene Konfiguration (")}{fw.connector === 'rest' ? 'REST-JSON' : 'Entities.xml-Format'}{t("). Wiederherstellen erzeugt einen Entwurf – ausgerollt wird nur nach Vier-Augen-Freigabe.")}</div>
          {data.may_backup && <div className="row" style={{ flexWrap: 'wrap' }}>
            <input placeholder={t("Notiz (optional), z. B. „vor Firmware-Update“")} value={note} maxLength={300} onChange={(e) => setNote(e.target.value)} style={{ flex: '1 1 240px' }} aria-label={t("Notiz zur Sicherung")} />
            <button className="primary" disabled={busy} onClick={backupNow}><Icon name="download" size={14} /> {busy ? t("Sichere …") : t("Jetzt sichern")}</button>
          </div>}
        </div>
        {fw.connector === 'rest' && <SfosCard fw={fw} sfos={data.sfos} mayEdit={data.may_restore}
          onDraft={() => { setMsg({ kind: 'ok', text: t("Änderung des Sicherungszeitplans liegt in Ihrem Entwurf – zum Einreichen unten „Einreichen …“ wählen.") }); onDraftChanged?.() }} />}
      </div>

      {msg && <div className={`alert ${msg.kind} small`}>{msg.text}</div>}

      <div className="panel">
        <div className="panel-head"><Icon name="clock" size={18} className="text-accent" /><h3>{t("Sicherungen")} <span className="muted" style={{ fontWeight: 400 }}>({data.items.length})</span></h3></div>
        {!data.items.length ? <Empty>{t("Noch keine Sicherung vorhanden")}{s.enabled && s.next_run ? t(" – die erste automatische folgt am {0}", fmt(s.next_run)) : ''}.</Empty> : (
          <div className="table-wrap">
            <table className="cs-grid">
              <thead><tr><th>{t("Zeitpunkt")}</th><th>{t("Art")}</th><th>{t("Objekte")}</th><th>{t("Größe")}</th><th>{t("Stand")}</th><th>{t("Notiz")}</th><th className="actions" /></tr></thead>
              <tbody>
                {data.items.map((b) => (
                  <tr key={b.id}>
                    <td className="nowrap">{b.pinned && <span title={t("Angeheftet – wird nie automatisch entfernt")} aria-label="angeheftet">📌 </span>}{fmt(b.created_at)}</td>
                    <td className="small">{b.trigger === 'scheduled' ? t("automatisch") : `manuell${b.created_by ? ` (${b.created_by})` : ''}`}{b.has_file && <span className="badge" style={{ marginLeft: 6 }} title={t("Auch als Datei abgelegt")}>{t("Datei")}</span>}</td>
                    <td>{b.object_count}</td>
                    <td className="small">{kb(b.size)}</td>
                    <td>{b.unchanged === null ? <span className="muted small">{t("älteste")}</span> : b.unchanged ? <span className="muted small">{t("unverändert")}</span> : <span className="badge b-info">{t("geändert")}</span>}</td>
                    <td className="small">{b.note || <span className="muted">–</span>}</td>
                    <td className="actions">
                      {confirmDel === b.id ? <span className="row nowrap">
                        <button className="sm danger" onClick={() => remove(b)}>{t("Endgültig löschen")}</button>
                        <button className="sm" onClick={() => setConfirmDel(null)}>{t("Abbrechen")}</button>
                      </span> : <RowMenu label={fmt(b.created_at)} items={[
                        { label: t("Download (JSON)"), icon: 'download', onClick: () => download(`/firewalls/${fw.id}/backups/${b.id}/download`, `Sicherung_${fw.name}_${stamp(b)}.json`) },
                        b.format === 'xml' && { label: t("Download (Entities.xml)"), icon: 'download', onClick: () => download(`/firewalls/${fw.id}/backups/${b.id}/download?format=xml`, `Entities_${fw.name}_${stamp(b)}.xml`) },
                        data.may_restore && { label: t("Vergleichen / Wiederherstellen …"), icon: 'sync', onClick: () => startRestore(b) },
                        data.may_backup && { label: b.pinned ? t("Nicht mehr anheften") : t("Anheften (dauerhaft behalten)"), icon: 'flag', onClick: () => patch(b, { pinned: !b.pinned }) },
                        data.may_delete && { label: t("Löschen"), icon: 'trash', danger: true, onClick: () => setConfirmDel(b.id) },
                      ]} />}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {restore && <RestoreModal fw={fw} backup={restore.backup} review={restore.review} onClose={() => setRestore(null)}
        onApplied={(r) => {
          setRestore(null)
          setMsg({ kind: r.skipped.length ? 'warn' : 'ok', text: t("{0} Änderungen in Ihren Entwurf übernommen – im Tab „Konfiguration“ prüfen und einreichen.{1}", r.added, r.skipped.length ? t(" Übersprungen: {0}{1}", r.skipped.slice(0, 5).join('; '), r.skipped.length > 5 ? ' …' : '') : '') })
          onDraftChanged?.()
        }} />}
    </div>
  )
}
