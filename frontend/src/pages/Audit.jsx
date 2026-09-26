import { Fragment, useState } from 'react'
import { Link } from 'react-router-dom'
import { api, crNo, download, fmt } from '../api'
import { Empty, ErrorBox, useLoad } from '../components/ui'
import { t } from '../i18n'

export const AUDIT_LABEL = {
  'auth.login': t("Anmeldung"), 'auth.login_failed': t("Anmeldung fehlgeschlagen"), 'auth.password_changed': t("Passwort geändert"),
  'user.bootstrap': t("Erster Admin angelegt"), 'user.created': t("Benutzer angelegt"), 'user.updated': t("Benutzer geändert"),
  'user.deactivated': t("Benutzer deaktiviert"), 'role.created': t("Rolle angelegt"), 'role.updated': t("Rolle geändert"),
  'role.deleted': t("Rolle gelöscht"), 'settings.updated': t("Einstellungen geändert"),
  'central.account_created': t("Central-Konto angelegt"), 'central.account_updated': t("Central-Konto geändert"),
  'central.account_deleted': t("Central-Konto gelöscht"), 'central.inventory_synced': t("Central-Inventar übernommen"),
  'group.created': t("Gruppe angelegt"), 'group.updated': t("Gruppe geändert"), 'group.deleted': t("Gruppe gelöscht"),
  'firewall.created': t("Firewall hinzugefügt"), 'firewall.updated': t("Firewall-Anbindung geändert"),
  'firewall.removed': t("Firewall entfernt"), 'firewall.synced': t("Firewall synchronisiert"),
  'firewall.sync_failed': t("Synchronisation fehlgeschlagen"), 'config.drift_detected': t("Änderung außerhalb des Tools erkannt"),
  'config.exported': t("Konfiguration exportiert"),
  'change.submitted': t("Antrag eingereicht"), 'change.approved': t("Antrag genehmigt"), 'change.rejected': t("Antrag abgelehnt"),
  'change.withdrawn': t("Antrag zurückgezogen"), 'change.revert_submitted': t("Rücknahme eingereicht"), 'change.expiry_failed': t("Automatische Rücknahme fehlgeschlagen"), 'change.commented': t("Kommentar"), 'change.deploy_requested': t("Ausrollen angestoßen"),
  'change.deployed': t("Antrag ausgerollt"), 'change.deploy_failed': t("Ausrollen fehlgeschlagen"), 'change.conflict': t("Konflikt beim Ausrollen"),
  'firmware.upgrade_scheduled': t("Firmware-Update geplant"), 'firmware.upgrade_failed': t("Firmware-Update fehlgeschlagen"),
  'firmware.upgrade_cancelled': t("Firmware-Update storniert"), 'audit.verified': t("Audit-Kette geprüft"), 'notifications.updated': t("Benachrichtigungen geändert"), 'template.created': t("Vorlage angelegt"), 'auth.totp_enabled': t("2FA eingerichtet"), 'auth.totp_disabled': t("2FA deaktiviert"), 'auth.totp_reset': t("2FA zurückgesetzt"), 'auth.reauth': t("Neu angemeldet"), 'oidc.updated': t("SSO-Konfiguration geändert"), 'template.deleted': t("Vorlage gelöscht"), 'user.telegram_linked': t("Telegram verknüpft"), 'user.telegram_unlinked': t("Telegram getrennt"), 'user.notification_prefs': t("Benachrichtigungs-Einstellungen"), 'central.diagnosed': t("Probelauf Sophos Central"), 'firewall.diagnosed': t("Probelauf Firewall"), 'audit.exported': t("Audit-Log exportiert"),
}

const PREFIXES = [['', t("Alle Bereiche")], ['auth.', t("Anmeldungen")], ['change.', t("Anträge")], ['firewall.', t("Firewalls")],
  ['config.', t("Konfiguration")], ['firmware.', t("Firmware")], ['user.', t("Benutzer")], ['role.', t("Rollen")],
  ['central.', t("Sophos Central")], ['settings.', t("Einstellungen")], ['audit.', t("Audit")]]

function target(e) {
  if (e.target_type === 'change') return <Link to={`/changes/${e.target_id}`}>{e.details?.number ? crNo(e.details.number) : t("Antrag")}</Link>
  if (e.target_type === 'firewall' && e.action !== 'firewall.removed') return <Link to={`/firewalls/${e.target_id}`}>{e.details?.firewall || e.details?.name || t("Firewall")}</Link>
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
        <h1>{t("Audit-Log")}</h1>
        <span className="sub">{t("Manipulationssicher durch Hash-Kette – jeder Eintrag enthält den Hash seines Vorgängers")}</span>
        <div className="right row">
          <button onClick={async () => setVerify(await api('/audit/verify'))}>{t("Integrität prüfen")}</button>
          <button onClick={() => download(`/audit/export.csv?${qs}`, 'audit-log.csv')}>{t("CSV-Export")}</button>
        </div>
      </div>
      {verify && <div className={`alert ${verify.ok ? 'ok' : 'error'}`}>{verify.ok
        ? t("Hash-Kette intakt – {0} Einträge geprüft.", verify.checked)
        : t("Hash-Kette unterbrochen bei Eintrag #{0} – Log wurde nachträglich verändert!", verify.broken_at)}</div>}
      <div className="panel panel-pad" style={{ marginBottom: 14 }}>
        <div className="form-grid">
          <select value={filter.action} onChange={set('action')} aria-label={t("Bereich")}>{PREFIXES.map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select>
          <input placeholder={t("Benutzer")} value={filter.actor} onChange={set('actor')} />
          <input placeholder={t("Suche in Details …")} value={filter.q} onChange={set('q')} />
          <input type="date" value={filter.since} onChange={set('since')} aria-label={t("Von")} />
          <input type="date" value={filter.until} onChange={set('until')} aria-label={t("Bis")} />
        </div>
      </div>
      <ErrorBox error={error} />
      {data && (!data.items.length ? <div className="panel"><Empty>{t("Keine Einträge.")}</Empty></div> : (
        <div className="panel table-wrap">
          <table>
            <thead><tr><th>#</th><th>{t("Zeit")}</th><th>{t("Benutzer")}</th><th>{t("Ereignis")}</th><th>{t("Objekt")}</th><th>IP</th></tr></thead>
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
                      <div className="small muted mono" style={{ marginTop: 4 }}>{t("hash")} {e.hash}…</div>
                    </td></tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
          <div className="row" style={{ padding: 12 }}>
            <span className="muted small">{offset + 1}–{offset + data.items.length} {t("von")} {data.total}</span>
            <div className="right row">
              <button className="sm" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - 100))}>{t("Zurück")}</button>
              <button className="sm" disabled={offset + 100 >= data.total} onClick={() => setOffset(offset + 100)}>{t("Weiter")}</button>
            </div>
          </div>
        </div>
      ))}
    </>
  )
}
