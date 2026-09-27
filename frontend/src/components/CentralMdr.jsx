import { useState } from 'react'
import { api, download } from '../api'
import { ErrorBox, Modal, useLoad } from './ui'
import { MDR_ACTION, MDR_TYPE } from './columns'
import { Field, Seg } from './ui'
import { t } from '../i18n'

/** MDR-Threat-Feed (Sophos Central): Einstellungen und Indikatoren. Änderungen laufen wie alle über Anträge. */

export const NEW_MDR = { mdrIndicators: { name: '', type: 'ipv4-addr' } }

export function MdrFeedForm({ data, setData }) {
  return (
    <div className="stack">
      <div className="muted small">{t("Der MDR-Threat-Feed nimmt Indikatoren (IoCs) des Sophos-MDR-Teams bzw. eigene Einträge auf und wendet sie auf den Verkehr der Firewall an.")}</div>
      <Field label={t("Status")}><Seg options={[[true, t("aktiv")], [false, t("inaktiv")]]} value={!!data.enabled}
        onChange={(v) => setData({ ...data, enabled: v })} /></Field>
      <Field label={t("Aktion bei Treffern")}><Seg options={Object.entries(MDR_ACTION)} value={data.action || 'logOnly'}
        onChange={(v) => setData({ ...data, action: v })} /></Field>
      <label className="check">
        <input type="checkbox" checked={!!data.clearIndicators}
          onChange={(e) => setData({ ...data, clearIndicators: e.target.checked || undefined })} />
        <span>{t("Beim Ausrollen alle Indikatoren löschen")}</span>
      </label>
      {data.clearIndicators && <div className="alert warn small">{t("Löscht alle Indikatoren im Feed – auch solche, die außerhalb dieses Tools angelegt wurden. Das lässt sich nicht zurücknehmen.")}</div>}
    </div>
  )
}

export function MdrIndicatorForm({ data, setData, isNew }) {
  return (
    <div className="stack">
      <Field label={t("Typ")}><Seg options={Object.entries(MDR_TYPE)} value={data.type || 'ipv4-addr'}
        onChange={(v) => isNew && setData({ ...data, type: v })} /></Field>
      <Field label={t("Wert")} hint={{ 'ipv4-addr': t("z. B. 203.0.113.7 oder 198.51.100.0/24"), 'domain-name': t("z. B. malware.example.com"), url: t("z. B. https://phish.example.net/login") }[data.type || 'ipv4-addr']}>
        <input value={data.name || ''} disabled={!isNew} autoFocus={isNew} onChange={(e) => setData({ ...data, name: e.target.value.trim() })} /></Field>
      {!isNew && <div className="muted small">{t("Indikatoren lassen sich nicht ändern – löschen und neu anlegen.")}</div>}
      <div className="muted small">{t("Die Central-API kann Indikatoren nicht auflisten: angezeigt werden die über dieses Tool angelegten. Beim Synchronisieren wird geprüft, ob sie noch vorhanden sind.")}</div>
    </div>
  )
}

/** Status des Feeds und Suche nach Indikatoren direkt in Sophos Central (auch außerhalb des Tools angelegte). */
export function MdrBar({ fw, entity }) {
  const [q, setQ] = useState('')
  const [busy, setBusy] = useState(false)
  const [res, setRes] = useState(null)
  const [error, setError] = useState('')
  const failed = (fw.mdr_status || '').startsWith('Fehler')
  const search = async () => {
    const values = q.split(/[\s,;]+/).map((x) => x.trim()).filter(Boolean).slice(0, 100)
    if (!values.length) return
    setBusy(true); setError(''); setRes(null)
    try { setRes(await api(`/firewalls/${fw.id}/mdr/search`, { method: 'POST', body: { values } })) } catch (e) { setError(e.message) } finally { setBusy(false) }
  }
  return (
    <div className="stack" style={{ marginBottom: 12 }}>
      {failed && <div className="alert warn small">{t("MDR-Threat-Feed konnte beim letzten Synchronisieren nicht gelesen werden – angezeigt wird der letzte bekannte Stand.")} <span className="muted">{fw.mdr_status}</span></div>}
      {entity === 'mdrIndicators' && <div className="panel panel-pad stack">
        <div className="row" style={{ flexWrap: 'wrap' }}>
          <b className="small">{t("In Sophos Central prüfen")}</b>
          <input style={{ flex: 1, minWidth: 220 }} value={q} placeholder={t("Werte, durch Leerzeichen oder Komma getrennt (max. 100)")}
            onChange={(e) => setQ(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && search()} />
          <button className="sm" disabled={busy || !q.trim()} onClick={search}>{busy ? t("Suche …") : t("Suchen")}</button>
        </div>
        <div className="muted small">{t("Findet auch Indikatoren, die außerhalb dieses Tools angelegt wurden (z. B. vom Sophos-MDR-Team). Die Abfrage läuft über die Firewall und kann einige Sekunden dauern.")}</div>
        {error && <div className="alert error small">{error}</div>}
        {res && (res.found === null
          ? <div className="alert warn small">{t("Antwort von Sophos Central in unbekanntem Format:")} <code>{JSON.stringify(res.response)}</code></div>
          : <div className="small">
            {res.found.length > 0 && <div><span className="badge b-ok">{t("vorhanden")}</span> {res.found.join(', ')}</div>}
            {res.missing.length > 0 && <div><span className="badge">{t("nicht vorhanden")}</span> {res.missing.join(', ')}</div>}
          </div>)}
      </div>}
    </div>
  )
}

/** Live-Export über Sophos Central: vollständig oder ausgewählte Entitäten, optional mit abhängigen Objekten. */
export function CentralExportModal({ fw, onClose }) {
  const [all] = useLoad(() => api('/central/exportable-entities'), [])
  const [full, setFull] = useState(true)
  const [sel, setSel] = useState(new Set())
  const [dep, setDep] = useState(true)
  const [q, setQ] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const toggle = (e) => { const s = new Set(sel); s.has(e) ? s.delete(e) : s.add(e); setSel(s) }
  const run = async () => {
    setBusy(true); setError('')
    try {
      await download(`/firewalls/${fw.id}/central-export`, `Entities-${fw.name}-central.xml`, {
        method: 'POST', body: full ? {} : { entities: [...sel], include_dependency: dep } })
      onClose()
    } catch (e) { setError(e.message) } finally { setBusy(false) }
  }
  const shown = (all || []).filter((e) => e.toLowerCase().includes(q.toLowerCase()))
  return (
    <Modal title={t("Export aus Sophos Central")} onClose={onClose} wide>
      <div className="stack">
        <div className="muted small">{t("Liest die Konfiguration live über Sophos Central (asynchroner Export) und lädt sie als Entities.xml herunter – nicht nur die Objekttypen, die dieses Tool verwaltet. Das kann einige Minuten dauern.")}</div>
        <Seg options={[[true, t("Vollständig")], [false, t("Ausgewählte Objekttypen")]]} value={full} onChange={setFull} />
        {!full && <>
          <label className="check"><input type="checkbox" checked={dep} onChange={(e) => setDep(e.target.checked)} /><span>{t("Abhängige Objekte mitexportieren")}</span></label>
          <input placeholder={t("Objekttyp suchen …")} value={q} onChange={(e) => setQ(e.target.value)} />
          <div style={{ maxHeight: 260, overflowY: 'auto', columns: '3 200px' }}>
            {shown.map((e) => <label key={e} className="check small"><input type="checkbox" checked={sel.has(e)} onChange={() => toggle(e)} /><span>{e}</span></label>)}
          </div>
          <div className="muted small">{t("{0} ausgewählt", sel.size)}</div>
        </>}
        <ErrorBox error={error} />
      </div>
      <div className="modal-foot"><button onClick={onClose}>{t("Abbrechen")}</button>
        <button className="primary" disabled={busy || (!full && !sel.size)} onClick={run}>{busy ? t("Exportiere …") : t("Exportieren")}</button></div>
    </Modal>
  )
}
