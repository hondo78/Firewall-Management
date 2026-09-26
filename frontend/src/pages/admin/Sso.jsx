import { useEffect, useState } from 'react'
import { api } from '../../api'
import { ErrorBox, Field, useLoad } from '../../components/ui'
import { t } from '../../i18n'

/** Single Sign-On per OpenID Connect (z. B. Microsoft Entra ID, Authentik, Keycloak). */
export default function Sso() {
  const [cfg, error, reload] = useLoad(() => api('/auth/oidc/config'), [])
  const [roles] = useLoad(() => api('/roles'), [])
  const [groups] = useLoad(() => api('/groups'), [])
  const [form, setForm] = useState(null)
  const [msg, setMsg] = useState(null)
  useEffect(() => { if (cfg) setForm({ ...cfg, client_secret: '' }) }, [cfg])
  if (error) return <ErrorBox error={error} />
  if (!form || !roles || !groups) return null
  const set = (k) => (e) => setForm({ ...form, [k]: e.target.type === 'checkbox' ? e.target.checked : e.target.value })
  const setMap = (i, k, v) => setForm({ ...form, mappings: form.mappings.map((m, j) => (j === i ? { ...m, [k]: v || null } : m)) })
  const save = async (extra) => {
    setMsg(null)
    try {
      const { redirect_uri, client_secret_set, ...body } = { ...form, ...extra }
      await api('/auth/oidc/config', { method: 'PUT', body })
      setMsg({ kind: 'ok', text: t("Gespeichert.") })
      reload()
    } catch (e) { setMsg({ kind: 'error', text: e.message }) }
  }
  return (
    <>
      <div className="page-head"><h1>{t("Anmeldung & SSO")}</h1>
        <span className="sub">{t("Single Sign-On per OpenID Connect – der lokale Login bleibt als Notzugang erhalten")}</span></div>
      <div className="stack" style={{ maxWidth: 860 }}>
        <div className="panel panel-pad stack">
          <label className="check"><input type="checkbox" checked={form.enabled} onChange={set('enabled')} /><b>{t("SSO aktivieren")}</b></label>
          <div className="alert info small">
            {t("Im Identity Provider eine App (Web, vertraulicher Client) mit dieser Weiterleitungs-URL anlegen:")}<br />
            <code>{form.redirect_uri || t("– zuerst unter Benachrichtigungen die Adresse der Oberfläche eintragen –")}</code><br />
            {t("Gruppen im ID-Token bzw. userinfo freigeben, wenn Rollen daraus übernommen werden sollen.")}
          </div>
          <div className="form-grid">
            <Field label={t("Issuer-URL")} hint={t("z. B. https://login.microsoftonline.com/<tenant>/v2.0")}><input value={form.issuer} onChange={set('issuer')} /></Field>
            <Field label={t("Client-ID")}><input value={form.client_id} onChange={set('client_id')} /></Field>
            <Field label={t("Client-Secret")} hint={cfg.client_secret_set ? t("gesetzt – leer lassen = unverändert") : t("wird verschlüsselt gespeichert")}>
              <input type="password" value={form.client_secret} onChange={set('client_secret')} autoComplete="new-password" /></Field>
            <Field label={t("Scopes")}><input value={form.scopes} onChange={set('scopes')} /></Field>
            <Field label={t("Claim für den Benutzernamen")}><input value={form.username_claim} onChange={set('username_claim')} /></Field>
            <Field label={t("Claim für Gruppen")}><input value={form.groups_claim} onChange={set('groups_claim')} /></Field>
            <Field label={t("Beschriftung des Knopfs")}><input value={form.button_label} onChange={set('button_label')} /></Field>
          </div>
          <label className="check"><input type="checkbox" checked={form.auto_create} onChange={set('auto_create')} />
            <span>{t("Unbekannte Benutzer beim ersten Login anlegen")}</span></label>
          <label className="check"><input type="checkbox" checked={form.sync_roles} onChange={set('sync_roles')} />
            <span>{t("Rollen bei jedem Login aus den Gruppen übernehmen")} <span className="muted small">{t("(ersetzt manuell vergebene Rollen von SSO-Benutzern; nur wenn Zuordnungen vorhanden)")}</span></span></label>
        </div>

        <div className="panel panel-pad stack">
          <h3 style={{ margin: 0 }}>{t("Gruppen → Rollen")}</h3>
          <div className="muted small">{t("Wert im Gruppen-Claim (bei Entra ID die Objekt-ID der Gruppe) → Rolle, global oder für eine Firewall-Gruppe.")}</div>
          <table>
            <thead><tr><th>{t("Gruppe (Claim-Wert)")}</th><th>{t("Rolle")}</th><th>{t("Geltungsbereich")}</th><th /></tr></thead>
            <tbody>{form.mappings.map((m, i) => (
              <tr key={i}>
                <td><input value={m.claim} onChange={(e) => setMap(i, 'claim', e.target.value)} /></td>
                <td><select value={m.role_id || ''} onChange={(e) => setMap(i, 'role_id', e.target.value)}>
                  {roles.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}</select></td>
                <td><select value={m.group_id || ''} onChange={(e) => setMap(i, 'group_id', e.target.value)}>
                  <option value="">{t("Alle Firewalls")}</option>
                  {groups.map((g) => <option key={g.id} value={g.id}>{t("Gruppe:")} {g.name}</option>)}</select></td>
                <td><button className="ghost" onClick={() => setForm({ ...form, mappings: form.mappings.filter((_, j) => j !== i) })}>×</button></td>
              </tr>))}
            </tbody>
          </table>
          <div><button className="sm" onClick={() => setForm({ ...form, mappings: [...form.mappings, { claim: '', role_id: roles[0]?.id, group_id: null }] })}>{t("+ Zuordnung")}</button></div>
        </div>
        {msg && <div className={`alert ${msg.kind}`}>{msg.text}</div>}
        <div className="row"><button className="primary" onClick={() => save()}>{t("Speichern")}</button>
          {cfg.client_secret_set && <button onClick={() => save({ clear_client_secret: true })}>{t("Secret entfernen")}</button>}</div>
        <div className="muted small">{t("Zwei-Faktor-Pflicht und Neu-Anmeldung vor dem Genehmigen: Administration › Einstellungen.")}</div>
      </div>
    </>
  )
}
