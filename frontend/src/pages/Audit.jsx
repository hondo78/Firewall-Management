import { Fragment, useState } from 'react'
import { Link } from 'react-router-dom'
import { api, crNo, download, fmt } from '../api'
import { Empty, ErrorBox, useLoad } from '../components/ui'

export const AUDIT_LABEL = {
  'auth.login': 'Anmeldung', 'auth.login_failed': 'Anmeldung fehlgeschlagen', 'auth.password_changed': 'Passwort geändert',
  'user.bootstrap': 'Erster Admin angelegt', 'user.created': 'Benutzer angelegt', 'user.updated': 'Benutzer geändert',
  'user.deactivated': 'Benutzer deaktiviert', 'role.created': 'Rolle angelegt', 'role.updated': 'Rolle geändert',
  'role.deleted': 'Rolle gelöscht', 'settings.updated': 'Einstellungen geändert',
  'central.account_created': 'Central-Konto angelegt', 'central.account_updated': 'Central-Konto geändert',
  'central.account_deleted': 'Central-Konto gelöscht', 'central.inventory_synced': 'Central-Inventar übernommen',
  'group.created': 'Gruppe angelegt', 'group.updated': 'Gruppe geändert', 'group.deleted': 'Gruppe gelöscht',
  'firewall.created': 'Firewall hinzugefügt', 'firewall.updated': 'Firewall-Anbindung geändert',
  'firewall.removed': 'Firewall entfernt', 'firewall.synced': 'Firewall synchronisiert',
  'firewall.sync_failed': 'Synchronisation fehlgeschlagen', 'config.drift_detected': 'Änderung außerhalb des Tools erkannt',
  'config.exported': 'Konfiguration exportiert',
  'change.submitted': 'Antrag eingereicht', 'change.approved': 'Antrag genehmigt', 'change.rejected': 'Antrag abgelehnt',
  'change.withdrawn': 'Antrag zurückgezogen', 'change.revert_submitted': 'Rücknahme eingereicht', 'change.expiry_failed': 'Automatische Rücknahme fehlgeschlagen', 'change.commented': 'Kommentar', 'change.deploy_requested': 'Ausrollen angestoßen',
  'change.deployed': 'Antrag ausgerollt', 'change.deploy_failed': 'Ausrollen fehlgeschlagen', 'change.conflict': 'Konflikt beim Ausrollen',
  'firmware.upgrade_scheduled': 'Firmware-Update geplant', 'firmware.upgrade_failed': 'Firmware-Update fehlgeschlagen',
  'firmware.upgrade_cancelled': 'Firmware-Update storniert', 'audit.verified': 'Audit-Kette geprüft', 'notifications.updated': 'Benachrichtigungen geändert', 'template.created': 'Vorlage angelegt', 'auth.totp_enabled': '2FA eingerichtet', 'auth.totp_disabled': '2FA deaktiviert', 'auth.totp_reset': '2FA zurückgesetzt', 'auth.reauth': 'Neu angemeldet', 'oidc.updated': 'SSO-Konfiguration geändert', 'template.deleted': 'Vorlage gelöscht', 'user.telegram_linked': 'Telegram verknüpft', 'user.telegram_unlinked': 'Telegram getrennt', 'user.notification_prefs': 'Benachrichtigungs-Einstellungen', 'central.diagnosed': 'Probelauf Sophos Central', 'firewall.diagnosed': 'Probelauf Firewall', 'audit.exported': 'Audit-Log exportiert',
}

const PREFIXES = [['', 'Alle Bereiche'], ['auth.', 'Anmeldungen'], ['change.', 'Anträge'], ['firewall.', 'Firewalls'],
  ['config.', 'Konfiguration'], ['firmware.', 'Firmware'], ['user.', 'Benutzer'], ['role.', 'Rollen'],
  ['central.', 'Sophos Central'], ['settings.', 'Einstellungen'], ['audit.', 'Audit']]

function target(e) {
  if (e.target_type === 'change') return <Link to={`/changes/${e.target_id}`}>{e.details?.number ? crNo(e.details.number) : 'Antrag'}</Link>
  if (e.target_type === 'firewall' && e.action !== 'firewall.removed') return <Link to={`/firewalls/${e.target_id}`}>{e.details?.firewall || e.details?.name || 'Firewall'}</Link>
  return e.details?.name || e.details?.username || e.details?.firewall || e.details?.account || ''
}

export default function Audit() {
  const [filter, setFilter] = useState({ action: '', actor: '', q: '', since: '', until: '' })
  const [offset, setOffset] = useState(0)
  const [open, setOpen] = useState({})
  const [verify, setVerify] = useState(null)
  const qs = new URLSearchParams(Object.entries({ ...filter, since: filter.since ? new Date(filter.since).toISOString() : '', until: filter.until ? new Date(`${filter.until}T23:59:59`).toISOString() : '' }).filter(([, v]) => v))
  const [data, error] = useLoad(() => api(`/audit?${qs}&offset=${offset}&limit=100`), [qs.toString(), offset])
  const set = (k) => (e) => { setOffset(0); setFilter({ ...filter, [k]: e.target.value }) }

  return (
    <>
      <div className="page-head">
        <h1>Audit-Log</h1>
        <span className="sub">Manipulationssicher durch Hash-Kette – jeder Eintrag enthält den Hash seines Vorgängers</span>
        <div className="right row">
          <button onClick={async () => setVerify(await api('/audit/verify'))}>Integrität prüfen</button>
          <button onClick={() => download(`/audit/export.csv?${qs}`, 'audit-log.csv')}>CSV-Export</button>
        </div>
      </div>
      {verify && <div className={`alert ${verify.ok ? 'ok' : 'error'}`}>{verify.ok
        ? `Hash-Kette intakt – ${verify.checked} Einträge geprüft.`
        : `Hash-Kette unterbrochen bei Eintrag #${verify.broken_at} – Log wurde nachträglich verändert!`}</div>}
      <div className="panel panel-pad" style={{ marginBottom: 14 }}>
        <div className="form-grid">
          <select value={filter.action} onChange={set('action')} aria-label="Bereich">{PREFIXES.map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select>
          <input placeholder="Benutzer" value={filter.actor} onChange={set('actor')} />
          <input placeholder="Suche in Details …" value={filter.q} onChange={set('q')} />
          <input type="date" value={filter.since} onChange={set('since')} aria-label="Von" />
          <input type="date" value={filter.until} onChange={set('until')} aria-label="Bis" />
        </div>
      </div>
      <ErrorBox error={error} />
      {data && (!data.items.length ? <div className="panel"><Empty>Keine Einträge.</Empty></div> : (
        <div className="panel table-wrap">
          <table>
            <thead><tr><th>#</th><th>Zeit</th><th>Benutzer</th><th>Ereignis</th><th>Objekt</th><th>IP</th></tr></thead>
            <tbody>
              {data.items.map((e) => (
                <Fragment key={e.id}>
                  <tr className="clickable" onClick={() => setOpen({ ...open, [e.id]: !open[e.id] })}>
                    <td className="muted small">{e.id}</td>
                    <td className="nowrap small">{fmt(e.ts)}</td>
                    <td>{e.actor}</td>
                    <td><span className={/failed|conflict|drift|rejected|revert/.test(e.action) ? 'text-error' : ''}>{AUDIT_LABEL[e.action] || e.action}</span>
                      <div className="small muted mono">{e.action}</div></td>
                    <td onClick={(ev) => ev.stopPropagation()}>{target(e)}</td>
                    <td className="small muted">{e.ip}</td>
                  </tr>
                  {open[e.id] && (
                    <tr><td colSpan={6}>
                      <pre className="xml">{JSON.stringify(e.details, null, 2)}</pre>
                      <div className="small muted mono" style={{ marginTop: 4 }}>hash {e.hash}…</div>
                    </td></tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
          <div className="row" style={{ padding: 12 }}>
            <span className="muted small">{offset + 1}–{offset + data.items.length} von {data.total}</span>
            <div className="right row">
              <button className="sm" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - 100))}>Zurück</button>
              <button className="sm" disabled={offset + 100 >= data.total} onClick={() => setOffset(offset + 100)}>Weiter</button>
            </div>
          </div>
        </div>
      ))}
    </>
  )
}
