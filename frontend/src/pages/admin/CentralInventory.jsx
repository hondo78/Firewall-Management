import { Fragment, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api } from '../../api'
import { Empty, ErrorBox, Field, Modal, Tabs, useLoad } from '../../components/ui'
import { t } from '../../i18n'

/**
 * Inventar eines Sophos-Central-Kontos verwalten (Firewall Management API): Firewalls umbenennen, verorten,
 * Verwaltung freigeben, aus Central entfernen; Firewall-Gruppen anlegen, ändern, löschen, Sync-Status.
 * Verwaltungsaktionen am Tenant – direkt ausgeführt (Superadmin) und im Audit-Log. Konfigurationsänderungen
 * laufen weiterhin über Anträge.
 */

const MANAGING = {
  approvedByCustomer: [t("verwaltet"), 'b-ok'], approvalPending: [t("Freigabe ausstehend"), 'b-warn'],
  pendingApproval: [t("Freigabe ausstehend"), 'b-warn'], notApproved: [t("nicht freigegeben"), 'b-danger'],
}
const SYNC = { inSync: [t("synchron"), 'b-ok'], syncing: [t("wird synchronisiert"), 'b-info'], outOfSync: [t("abweichend"), 'b-warn'],
  suspended: [t("ausgesetzt"), 'b-danger'], notAvailable: [t("nicht verfügbar"), ''] }

const fwLabel = (f) => f.name || f.hostname || f.serialNumber

function FirewallModal({ acc, fw, onClose, onDone }) {
  const [name, setName] = useState(fw.name || '')
  const [lat, setLat] = useState(fw.geoLocation?.latitude ?? '')
  const [lon, setLon] = useState(fw.geoLocation?.longitude ?? '')
  const [error, setError] = useState('')
  const save = async () => {
    const body = {}
    if (name !== (fw.name || '')) body.name = name.trim()
    if (String(lat) !== String(fw.geoLocation?.latitude ?? '') || String(lon) !== String(fw.geoLocation?.longitude ?? '')) {
      if (lat === '' || lon === '') { setError(t('Breiten- und Längengrad angeben')); return }
      body.geo = { latitude: Number(lat), longitude: Number(lon) }
    }
    try { await api(`/central-accounts/${acc}/firewalls/${fw.id}`, { method: 'PATCH', body }); onDone(t('„{0}“ in Sophos Central geändert.', name)) } catch (e) { setError(e.message) }
  }
  return (
    <Modal title={t("Firewall in Sophos Central: {0}", fwLabel(fw))} onClose={onClose}>
      <div className="stack">
        <Field label={t("Name in Sophos Central")} hint={t("3–40 Zeichen. Der Name im Tool bleibt unverändert.")}><input value={name} maxLength={40} onChange={(e) => setName(e.target.value)} /></Field>
        <div className="form-grid">
          <Field label={t("Breitengrad")}><input type="number" step="any" min={-90} max={90} value={lat} onChange={(e) => setLat(e.target.value)} placeholder="53.55" /></Field>
          <Field label={t("Längengrad")}><input type="number" step="any" min={-180} max={180} value={lon} onChange={(e) => setLon(e.target.value)} placeholder="9.99" /></Field>
        </div>
        <ErrorBox error={error} />
      </div>
      <div className="modal-foot"><button onClick={onClose}>{t("Abbrechen")}</button>
        <button className="primary" disabled={name.trim().length < 3} onClick={save}>{t("Speichern")}</button></div>
    </Modal>
  )
}

function DeleteFirewallModal({ acc, fw, onClose, onDone }) {
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState('')
  const name = fwLabel(fw)
  const run = async () => {
    try {
      const r = await api(`/central-accounts/${acc}/firewalls/${fw.id}`, { method: 'DELETE', body: { confirm } })
      onDone(t('„{0}“ aus Sophos Central entfernt.', name) + (r.note ? ` ${r.note}` : ''))
    } catch (e) { setError(e.message) }
  }
  return (
    <Modal title={t("Aus Sophos Central entfernen")} onClose={onClose}>
      <div className="stack">
        <div className="alert warn small">{t("Die Firewall wird aus Sophos Central entfernt: keine zentrale Verwaltung, keine Berichte, kein MDR-Threat-Feed und keine Firmware-Updates über Central mehr. Die Firewall selbst und ihre Konfiguration bleiben unverändert.")}</div>
        {fw.local && <div className="small">{t("Im Tool:")} <b>{fw.local.name}</b> – {t("über Central angebundene Firewalls werden archiviert, direkt angebundene verlieren nur die Central-Zuordnung.")}</div>}
        <Field label={t("Zur Bestätigung den Namen eingeben: {0}", name)}><input value={confirm} onChange={(e) => setConfirm(e.target.value)} autoFocus /></Field>
        <ErrorBox error={error} />
      </div>
      <div className="modal-foot"><button onClick={onClose}>{t("Abbrechen")}</button>
        <button className="danger solid" disabled={confirm.trim() !== name} onClick={run}>{t("Endgültig entfernen")}</button></div>
    </Modal>
  )
}

function GroupModal({ acc, group, groups, firewalls, onClose, onDone }) {
  const isNew = !group
  const members = new Set((group?.firewalls?.items || []).map((f) => f.id))
  const [name, setName] = useState(group?.name || '')
  const [parent, setParent] = useState('')
  const [sel, setSel] = useState(new Set(members))
  const [importFrom, setImportFrom] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const toggle = (id) => { const s = new Set(sel); s.has(id) ? s.delete(id) : s.add(id); setSel(s) }
  const save = async () => {
    setBusy(true); setError('')
    try {
      const r = isNew
        ? await api(`/central-accounts/${acc}/groups`, { method: 'POST', body: { name: name.trim(), parent_id: parent || null, assign: [...sel], import_from: importFrom || null } })
        : await api(`/central-accounts/${acc}/groups/${group.id}`, { method: 'PATCH', body: {
          ...(name !== group.name ? { name: name.trim() } : {}),
          assign: [...sel].filter((id) => !members.has(id)), unassign: [...members].filter((id) => !sel.has(id)) } })
      onDone((isNew ? t('Gruppe „{0}“ angelegt.', name) : t('Gruppe „{0}“ geändert.', name)) + (r.sync_error ? ` ${t('Inventar-Abgleich: {0}', r.sync_error)}` : ''))
    } catch (e) { setError(e.message) } finally { setBusy(false) }
  }
  return (
    <Modal title={isNew ? t("Neue Firewall-Gruppe in Sophos Central") : t("Gruppe „{0}“ bearbeiten", group.name)} onClose={onClose} wide>
      <div className="stack">
        <div className="form-grid">
          <Field label={t("Name")} hint={t("3–40 Zeichen")}><input value={name} maxLength={40} onChange={(e) => setName(e.target.value)} autoFocus /></Field>
          {isNew && <Field label={t("Übergeordnete Gruppe")}><select value={parent} onChange={(e) => setParent(e.target.value)}>
            <option value="">{t("– keine –")}</option>
            {groups.map((g) => <option key={g.id} value={g.id}>{g.name}</option>)}</select></Field>}
        </div>
        <Field label={t("Firewalls ({0} ausgewählt)", sel.size)}>
          <div className="stack" style={{ maxHeight: 220, overflowY: 'auto', gap: 4 }}>
            {firewalls.map((f) => <label key={f.id} className="check"><input type="checkbox" checked={sel.has(f.id)} onChange={() => toggle(f.id)} />
              <span>{fwLabel(f)} <span className="muted small">{f.serialNumber}{f.group ? ` · ${f.group.name}` : ''}</span></span></label>)}
          </div>
        </Field>
        {isNew && <Field label={t("Konfiguration übernehmen von")} hint={t("optional – die Gruppe übernimmt die Konfiguration dieser Firewall und verteilt sie an alle Mitglieder")}>
          <select value={importFrom} onChange={(e) => setImportFrom(e.target.value)}>
            <option value="">{t("– nicht übernehmen –")}</option>
            {firewalls.filter((f) => sel.has(f.id)).map((f) => <option key={f.id} value={f.id}>{fwLabel(f)}</option>)}</select></Field>}
        {importFrom && <div className="alert warn small">{t("Sophos Central überträgt diese Konfiguration auf alle Firewalls der Gruppe – außerhalb der Vier-Augen-Freigabe dieses Tools. Nur bei gleichartigen Firewalls verwenden.")}</div>}
        <ErrorBox error={error} />
      </div>
      <div className="modal-foot"><button onClick={onClose}>{t("Abbrechen")}</button>
        <button className="primary" disabled={busy || name.trim().length < 3} onClick={save}>{busy ? t("Speichere …") : isNew ? t("Anlegen") : t("Speichern")}</button></div>
    </Modal>
  )
}

function SyncStatus({ acc, group, firewalls }) {
  const [rows, error] = useLoad(() => api(`/central-accounts/${acc}/groups/${group.id}/sync-status`), [group.id])
  const byId = Object.fromEntries(firewalls.map((f) => [f.id, f]))
  if (error) return <ErrorBox error={error} />
  if (!rows) return <div className="muted small">{t("Lade …")}</div>
  if (!rows.length) return <div className="muted small">{t("Keine Mitglieder.")}</div>
  return (
    <table className="no-resize"><tbody>
      {rows.map((r) => {
        const [label, cls] = SYNC[r.status] || [r.status, '']
        return <tr key={r.firewall?.id}><td>{byId[r.firewall?.id] ? fwLabel(byId[r.firewall.id]) : r.firewall?.id}</td>
          <td><span className={`badge ${cls}`}>{label}</span></td><td className="muted small">{r.lastUpdatedAt ? new Date(r.lastUpdatedAt).toLocaleString() : ''}</td></tr>
      })}
    </tbody></table>
  )
}

export default function CentralInventory() {
  const { id } = useParams()
  const [accounts] = useLoad(() => api('/central-accounts'), [])
  const [inv, error, reload] = useLoad(() => api(`/central-accounts/${id}/inventory`), [id])
  const [tab, setTab] = useState('firewalls')
  const [modal, setModal] = useState(null)
  const [msg, setMsg] = useState(null)
  const [open, setOpen] = useState(null)
  const acc = accounts?.find((a) => a.id === id)
  const done = (text) => { setModal(null); setMsg({ kind: 'ok', text }); reload() }
  const approve = async (f) => {
    try { await api(`/central-accounts/${id}/firewalls/${f.id}/approve`, { method: 'POST' }); done(t('Verwaltung von „{0}“ freigegeben.', fwLabel(f))) } catch (e) { setMsg({ kind: 'error', text: e.message }) }
  }
  const link = async (f, firewallId) => {
    try {
      await api(`/central-accounts/${id}/firewalls/${f.id}/link`, { method: 'PUT', body: { firewall_id: firewallId } })
      done(firewallId ? t('„{0}“ mit der Firewall im Tool verknüpft – MDR-Threat-Feed, Firmware und Lizenzen stehen dort jetzt bereit.', fwLabel(f)) : t('Central-Zuordnung von „{0}“ gelöst.', fwLabel(f)))
    } catch (e) { setMsg({ kind: 'error', text: e.message }) }
  }
  const removeGroup = async (g) => {
    try { await api(`/central-accounts/${id}/groups/${g.id}`, { method: 'DELETE' }); done(t('Gruppe „{0}“ gelöscht – die Firewalls bleiben erhalten.', g.name)) } catch (e) { setMsg({ kind: 'error', text: e.message }) }
    setOpen(null)
  }
  const groups = inv?.groups || []
  const firewalls = inv?.firewalls || []
  return (
    <>
      <div className="page-head">
        <div><Link to="/admin/central" className="small">{t("Sophos Central")}</Link>
          <h1>{t("Inventar: {0}", acc?.name || '…')}</h1>
          <div className="muted small">{t("Firewalls und Gruppen direkt in Sophos Central verwalten. Jede Aktion wird sofort ausgeführt und im Audit-Log festgehalten; Konfigurationsänderungen laufen weiterhin über Anträge.")}</div></div>
        <button className="right" onClick={reload}>{t("Neu laden")}</button>
      </div>
      <ErrorBox error={error} />
      {msg && <div className={`alert ${msg.kind}`}>{msg.text}</div>}
      <Tabs tabs={[['firewalls', t("Firewalls ({0})", firewalls.length)], ['groups', t("Gruppen ({0})", groups.length)]]} value={tab} onChange={setTab} />
      {!inv ? (!error && <div className="muted">{t("Lade …")}</div>) : tab === 'firewalls' ? (
        <div className="panel table-wrap">
          {!firewalls.length ? <Empty>{t("Keine Firewalls in diesem Tenant.")}</Empty> : <table>
            <thead><tr><th>{t("Name")}</th><th>{t("Seriennummer")}</th><th>{t("Modell / Firmware")}</th><th>{t("Gruppe")}</th><th>{t("Status")}</th><th>{t("Standort")}</th><th>{t("Im Tool")}</th><th className="actions" /></tr></thead>
            <tbody>{firewalls.map((f) => {
              const [ml, mc] = MANAGING[f.status?.managing] || [f.status?.managing || '–', '']
              return (
                <tr key={f.id}>
                  <td><b>{fwLabel(f)}</b><div className="muted small">{f.hostname}</div></td>
                  <td className="small mono">{f.serialNumber}</td>
                  <td className="small">{f.model}<div className="muted">{f.firmwareVersion}</div></td>
                  <td className="small">{f.group?.name || '–'}</td>
                  <td><span className={`badge ${mc}`}>{ml}</span>{' '}
                    {f.status?.connected === false && <span className="badge b-danger">{t("getrennt")}</span>}
                    {f.status?.suspended && <span className="badge b-warn">{t("ausgesetzt")}</span>}</td>
                  <td className="small">{f.geoLocation ? `${f.geoLocation.latitude}, ${f.geoLocation.longitude}` : '–'}</td>
                  <td className="small">{f.local ? (f.local.archived ? <span className="muted">{t("archiviert")}</span> : <>
                    <Link to={`/firewalls/${f.local.id}`}>{f.local.name}</Link>
                    {f.local.connector !== 'central' && <button className="link small" style={{ marginLeft: 6 }} title={t("Central-Zuordnung lösen")} onClick={() => link(f, null)}>{t("lösen")}</button>}</>)
                    : inv.link_candidates?.length ? <select className="sm" value="" onChange={(e) => e.target.value && link(f, e.target.value)} aria-label={t("Mit Firewall im Tool verknüpfen")}>
                      <option value="">{t("verknüpfen mit …")}</option>
                      {inv.link_candidates.map((c) => <option key={c.id} value={c.id}>{c.name}{c.serial === f.serialNumber ? ` ✓ ${t("gleiche Seriennummer")}` : ''}</option>)}
                    </select> : '–'}</td>
                  <td className="actions nowrap">
                    {['approvalPending', 'pendingApproval'].includes(f.status?.managing) && <button className="sm primary" onClick={() => approve(f)}>{t("Verwaltung freigeben")}</button>}{' '}
                    <button className="sm" onClick={() => setModal({ kind: 'fw', fw: f })}>{t("Bearbeiten")}</button>{' '}
                    <button className="sm danger" onClick={() => setModal({ kind: 'delete', fw: f })}>{t("Entfernen …")}</button>
                  </td>
                </tr>
              )
            })}</tbody>
          </table>}
        </div>
      ) : (
        <div className="stack">
          <div className="row"><button className="primary right" onClick={() => setModal({ kind: 'group' })}>{t("Neue Gruppe")}</button></div>
          <div className="panel table-wrap">
            {!groups.length ? <Empty>{t("Keine Gruppen.")}</Empty> : <table>
              <thead><tr><th>{t("Name")}</th><th>{t("Übergeordnet")}</th><th>{t("Firewalls")}</th><th>{t("Konfig-Übernahme")}</th><th className="actions" /></tr></thead>
              <tbody>{groups.map((g) => (<Fragment key={g.id}>
                <tr>
                  <td><b>{g.name}</b>{g.lockedByManagingAccount && <span className="badge b-info" style={{ marginLeft: 6 }}>{t("vom Partner gesperrt")}</span>}</td>
                  <td className="small">{g.parentGroup?.name || '–'}</td>
                  <td className="small">{g.firewalls?.total ?? (g.firewalls?.items || []).length}</td>
                  <td className="small">{g.configImport ? `${g.configImport.status}${g.configImport.percentComplete != null ? ` (${g.configImport.percentComplete} %)` : ''}` : '–'}
                    {(g.configImport?.errors || []).length > 0 && <div className="text-error">{g.configImport.errors.map((e) => e.message || JSON.stringify(e)).join('; ')}</div>}</td>
                  <td className="actions nowrap">
                    <button className="sm" onClick={() => setOpen(open === g.id ? null : g.id)}>{t("Sync-Status")}</button>{' '}
                    {!g.lockedByManagingAccount && <>
                      <button className="sm" onClick={() => setModal({ kind: 'group', group: g })}>{t("Bearbeiten")}</button>{' '}
                      {open === `del:${g.id}`
                        ? <button className="sm danger solid" onClick={() => removeGroup(g)}>{t("Wirklich löschen")}</button>
                        : <button className="sm danger" onClick={() => setOpen(`del:${g.id}`)}>{t("Löschen")}</button>}
                    </>}
                  </td>
                </tr>
                {open === g.id && <tr><td colSpan={5}><SyncStatus acc={id} group={g} firewalls={firewalls} /></td></tr>}
              </Fragment>))}</tbody>
            </table>}
          </div>
        </div>
      )}
      {modal?.kind === 'fw' && <FirewallModal acc={id} fw={modal.fw} onClose={() => setModal(null)} onDone={done} />}
      {modal?.kind === 'delete' && <DeleteFirewallModal acc={id} fw={modal.fw} onClose={() => setModal(null)} onDone={done} />}
      {modal?.kind === 'group' && <GroupModal acc={id} group={modal.group} groups={groups.filter((g) => g.id !== modal.group?.id)}
        firewalls={firewalls} onClose={() => setModal(null)} onDone={done} />}
    </>
  )
}
