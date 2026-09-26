import { useState } from 'react'
import { api } from '../api'
import { ErrorBox, Field } from './ui'
import { t } from '../i18n'

const CONNECTORS = {
  rest: t("SFOS REST-API mit API-Key (empfohlen, ab SFOS 22)"),
  xmlapi: t("Alte XML-API mit Benutzer/Passwort (ältere Firmware)"),
  central: t("Sophos Central – Import/Export (kein Löschen möglich)"),
}

/** Anlegen/Bearbeiten einer Firewall. Die Verbindungseinstellungen sieht und ändert nur ein Superadmin. */
export default function FirewallForm({ fw, groups, onSaved, onCancel }) {
  const connection = !fw || fw.may_edit_connection
  const [form, setForm] = useState({
    name: fw?.name || '', group_id: fw?.group_id || '', connector: fw?.connector || 'rest',
    api_url: fw?.api_url || '', api_username: fw?.api_username || '', api_password: '',
    api_key_expires_at: fw?.api_key_expires_at ? fw.api_key_expires_at.slice(0, 10) : '',
    verify_tls: fw?.verify_tls ?? true,
    xml_username: fw?.xml_username || '', xml_password: '',
  })
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const set = (k) => (e) => setForm({ ...form, [k]: e.target.type === 'checkbox' ? e.target.checked : e.target.value })
  const fromCentral = !!fw?.central_id
  const rest = form.connector === 'rest'
  const switchesFormat = fw?.last_sync_at && fw.connector !== form.connector
    && (fw.connector === 'rest') !== (form.connector === 'rest')

  const save = async () => {
    setBusy(true)
    setError('')
    try {
      const body = connection
        ? { ...form, group_id: form.group_id || null, api_password: form.api_password || null,
          api_key_expires_at: rest && form.api_key_expires_at ? form.api_key_expires_at : null,
          xml_username: rest ? form.xml_username : null, xml_password: rest && form.xml_password ? form.xml_password : null }
        : { name: form.name, group_id: form.group_id || null }
      const saved = await api(fw ? `/firewalls/${fw.id}` : '/firewalls', { method: fw ? 'PUT' : 'POST', body })
      onSaved(saved)
    } catch (e) { setError(e.message) } finally { setBusy(false) }
  }

  return (
    <>
      <div className="stack">
        <div className="form-grid">
          <Field label={t("Anzeigename")}><input value={form.name} onChange={set('name')} /></Field>
          <Field label={t("Gruppe")} hint={t("Bestimmt, wer die Firewall sieht und bearbeiten darf")}>
            <select value={form.group_id} onChange={set('group_id')} disabled={fromCentral && !!fw?.group_id && groups.find((g) => g.id === fw.group_id)?.central}>
              <option value="">{t("– ohne Gruppe –")}</option>
              {groups.map((g) => <option key={g.id} value={g.id}>{g.name}</option>)}
            </select>
          </Field>
        </div>
        {!connection && <div className="alert info small">{t("Anbindung:")} <b>{fw.connector_label}</b>{t(". Adresse, Zugangsdaten und TLS-Einstellungen sieht und ändert nur ein Superadmin.")}</div>}
        {connection && <>
        <Field label={t("Anbindung")}>
          <select value={form.connector} onChange={set('connector')}>
            {Object.entries(CONNECTORS).filter(([k]) => k !== 'central' || fromCentral).map(([k, l]) => <option key={k} value={k}>{l}</option>)}
          </select>
        </Field>
        {switchesFormat && <div className="alert warn small">{t("Wechsel zwischen REST- und XML-Format: die zwischengespeicherte Konfiguration wird neu eingelesen, eigene Entwürfe werden verworfen. Offene Anträge verhindern den Wechsel.")}</div>}
        {rest && <>
          <div className="alert info small">
            {t("Auf der Firewall unter")} <b>{t("Administration › API access")}</b> {t("die IP dieses Servers erlauben und mit einem")}
            <b> {t("eigenen API-Administrator")}</b> {t("(Geräteprofil nur mit den nötigen Rechten) einen API-Key erzeugen. Der Key hat die Rechte dieses Admins.")}
          </div>
          <div className="form-grid">
            <Field label={t("Adresse")} hint={t("z. B. 192.168.1.1 (Port 4444 wird ergänzt) oder https://fw.example.local:4444")}>
              <input value={form.api_url} onChange={set('api_url')} placeholder="https://firewall:4444" />
            </Field>
            <Field label="API-Key" hint={fw?.has_api_password && fw?.connector === 'rest' ? t("leer lassen = unverändert") : t("beginnt mit sfos_ – wird verschlüsselt gespeichert")}>
              <input type="password" value={form.api_password} onChange={set('api_password')} autoComplete="off" placeholder={t("sfos_…")} />
            </Field>
            <Field label={t("Key gültig bis")} hint={t("wird beim Erzeugen angezeigt – für rechtzeitige Warnung")}>
              <input type="date" value={form.api_key_expires_at} onChange={set('api_key_expires_at')} />
            </Field>
          </div>
          <div className="stack" style={{ gap: 8, marginTop: 4 }}>
            <b>{t("Zusätzlich: XML-API für WAF-Regeln")} <span className="muted small" style={{ fontWeight: 400 }}>{t("(optional)")}</span></b>
            <div className="muted small">{t("Die REST-API liefert WAF-Regeln (Webserver-Schutz) nur unvollständig. Mit einem XML-API-Zugang liest und schreibt das Tool sie vollständig (gehosteter Server, Domänen, Pfade, Ausnahmen). Auf der Firewall unter")}
              <b> {t("Sicherung & Firmware › API")}</b> {t("die API aktivieren, die IP dieses Servers erlauben und einen eigenen API-Administrator verwenden.")}</div>
            <div className="form-grid">
              <Field label={t("API-Benutzer (XML)")} hint={t("leer = kein XML-Zugang")}><input value={form.xml_username} onChange={set('xml_username')} autoComplete="off" /></Field>
              <Field label={t("Passwort (XML)")} hint={fw?.has_xml_password ? t("leer lassen = unverändert") : t("wird verschlüsselt gespeichert")}>
                <input type="password" value={form.xml_password} onChange={set('xml_password')} autoComplete="new-password" />
              </Field>
            </div>
            {fw?.xml_status && fw.xml_status !== 'ok' && <div className="alert error small">XML-API: {fw.xml_status}</div>}
            {fw?.xml_status === 'ok' && <div className="alert ok small">{t("XML-API: WAF-Regeln werden gelesen.")}</div>}
          </div>
        </>}
        {form.connector === 'xmlapi' && <>
          <div className="alert info small">
            {t("Auf der Firewall unter")} <b>{t("Backup & firmware › API")}</b> {t("die API aktivieren und die IP dieses Servers erlauben. Nur für Firmware ohne REST-API verwenden.")}
          </div>
          <div className="form-grid">
            <Field label="API-Adresse" hint={t("z. B. 10.0.0.1 oder https://fw.example.local:4444")}>
              <input value={form.api_url} onChange={set('api_url')} placeholder="https://firewall:4444" />
            </Field>
            <Field label="API-Benutzer"><input value={form.api_username} onChange={set('api_username')} autoComplete="off" /></Field>
            <Field label={t("Passwort")} hint={fw?.has_api_password ? t("leer lassen = unverändert") : t("wird verschlüsselt gespeichert")}>
              <input type="password" value={form.api_password} onChange={set('api_password')} autoComplete="new-password" />
            </Field>
          </div>
        </>}
        {form.connector !== 'central' && (
          <label className="check"><input type="checkbox" checked={form.verify_tls} onChange={set('verify_tls')} />
            <span>{t("TLS-Zertifikat prüfen")} <span className="muted small">{t("(bei selbstsignierten Zertifikaten deaktivieren)")}</span></span></label>
        )}
        </>}
        <ErrorBox error={error} />
      </div>
      <div className="modal-foot">
        {onCancel && <button onClick={onCancel}>{t("Abbrechen")}</button>}
        <button className="primary" disabled={busy || !form.name} onClick={save}>{busy ? t("Speichere …") : t("Speichern")}</button>
      </div>
    </>
  )
}
