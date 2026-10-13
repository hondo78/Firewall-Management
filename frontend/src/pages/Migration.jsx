import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { api, can, download, upload as uploadFile } from '../api'
import { useAuth } from '../App'
import { ErrorBox, Field, Seg, useLoad } from '../components/ui'
import { t } from '../i18n'
import { ImportModal } from './firewall/Editor'

/**
 * Migrationsassistent (wie im Sophos Firewall Config Studio): Konfiguration eines anderen Herstellers einlesen,
 * Bericht prüfen, Quell-Interfaces/-Zonen Sophos-Zonen zuordnen und das Ergebnis als Entwurf einer Firewall
 * (Vier-Augen-Freigabe), als Vorlage oder als Entities.xml übernehmen.
 */

const STATUS = {
  supported: [t("Unterstützt"), 'b-ok'], partial: [t("Teilweise"), 'b-warn'], manual: [t("Manuell"), 'b-info'],
  unsupported: [t("Nicht unterstützt"), 'b-danger'],
}
const SECTION = { concepts: t("Konzepte"), objects: t("Adressen & Dienste"), interfaces: t("Interfaces & Routing"), rules: t("Regeln & NAT"), advanced: t("VPN & Weiteres") }
const NOTE = { manual: [t("Aktion nötig"), 'b-danger'], partial: [t("Prüfen"), 'b-warn'] }
const ZONES = ['LAN', 'WAN', 'DMZ', 'VPN', 'WiFi']
const COUNT_LABEL = { addresses: t("Adressen"), address_groups: t("Adressgruppen"), services: t("Dienste"), service_groups: t("Dienstgruppen"), rules: t("Regeln"), nat: t("NAT-Regeln") }

function Badge({ status, map = STATUS }) {
  const [l, c] = map[status] || [status, '']
  return <span className={`badge ${c}`}>{l}</span>
}

function Matrix({ rows }) {
  return (
    <table className="no-resize"><tbody>{rows.map((r) => (
      <tr key={r.feature}><td className="small muted">{SECTION[r.section] || r.section}</td><td>{r.feature}</td><td><Badge status={r.status} /></td></tr>))}
    </tbody></table>
  )
}

function Report({ report }) {
  const [open, setOpen] = useState(null)
  return (
    <div className="table-wrap"><table className="no-resize">
      <thead><tr><th>{t("Bereich")}</th><th>{t("Funktion")}</th><th>{t("Status")}</th><th>{t("Anzahl")}</th><th>{t("Hinweis")}</th></tr></thead>
      <tbody>{report.map((r, i) => (
        <tr key={i}>
          <td className="small muted">{SECTION[r.section] || r.section}</td>
          <td>{r.feature}</td>
          <td><Badge status={r.status} /></td>
          <td className="num">{r.count || '–'}</td>
          <td className="small">{r.note}
            {r.items.length > 0 && <div>
              <button className="link small" onClick={() => setOpen(open === i ? null : i)}>{open === i ? t("ausblenden") : t("{0} Einträge zeigen", r.items.length)}</button>
              {open === i && <ul className="small" style={{ margin: '4px 0 0', paddingLeft: 18 }}>{r.items.map((x) => <li key={x}>{x}</li>)}</ul>}
            </div>}</td>
        </tr>))}
      </tbody>
    </table></div>
  )
}

export default function Migration() {
  const { me } = useAuth()
  const [vendors, vError] = useLoad(() => api('/migration/vendors'), [])
  const [fws] = useLoad(() => api('/firewalls'), [])
  const [vendor, setVendor] = useState(null)
  const [file, setFile] = useState(null)
  const [parsed, setParsed] = useState(null)
  const [zones, setZones] = useState({})
  const [prefix, setPrefix] = useState('')
  const [preview, setPreview] = useState(null)
  const [target, setTarget] = useState('draft')
  const [fwId, setFwId] = useState('')
  const [tpl, setTpl] = useState({ name: '', format: 'rest' })
  const [review, setReview] = useState(null)
  const [result, setResult] = useState(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const v = vendors?.find((x) => x.id === vendor)
  const targets = useMemo(() => (fws || []).filter((f) => can(me, 'change.create', f) && f.last_sync_at), [fws, me])
  const body = () => ({ token: parsed.token, zone_map: zones, prefix })

  const run = async (fn) => { setBusy(true); setError(''); try { await fn() } catch (e) { setError(e.message) } finally { setBusy(false) } }
  const upload = () => run(async () => {
    const r = await uploadFile('/migration/parse', file, { vendor })
    setParsed(r); setPreview(null); setResult(null)
    setZones(Object.fromEntries(r.interfaces.map((i) => [i.name, i.zone])))
    setTpl({ ...tpl, name: t("Migration {0} – {1}", v.title, r.filename) })
  })
  const loadPreview = () => run(async () => setPreview(await api('/migration/preview', { method: 'POST', body: body() })))
  const toDraft = () => run(async () => setReview(await api('/migration/to-draft', { method: 'POST', body: { ...body(), firewall_id: fwId } })))
  const toTemplate = () => run(async () => setResult({ kind: 'template', ...(await api('/migration/to-template', { method: 'POST', body: { ...body(), ...tpl } })) }))
  const toFile = () => run(async () => download('/migration/download', 'Entities.xml', { method: 'POST', body: body() }))
  const reset = () => { setVendor(null); setFile(null); setParsed(null); setPreview(null); setResult(null); setError('') }

  if (vError) return <ErrorBox error={vError} />
  if (!vendors) return null
  return (
    <>
      <div className="page-head">
        <div><h1>{t("Migration")}</h1>
          <div className="muted small">{t("Konfiguration einer anderen Firewall übernehmen – wie der Migrationsassistent im Sophos Config Studio. Übernommen wird nie direkt: als Entwurf mit Vier-Augen-Freigabe, als Vorlage oder als Entities.xml.")}</div></div>
        {parsed && <button className="right" onClick={reset}>{t("Neue Migration")}</button>}
      </div>
      <ErrorBox error={error} />

      {!parsed && <>
        <h3>{t("1. Quelle wählen")}</h3>
        <div className="mig-vendors">
          {vendors.map((x) => (
            <button key={x.id} className={`mig-vendor ${vendor === x.id ? 'active' : ''}`} onClick={() => { setVendor(x.id); setFile(null) }}>
              <b>{x.title}</b><span className="muted small">{x.file}</span>
            </button>))}
        </div>
        {v && <div className="grid two" style={{ marginTop: 14 }}>
          <div className="panel panel-pad stack">
            <h3 style={{ margin: 0 }}>{t("Datei hochladen")}: {v.title}</h3>
            <div className="small">{v.hint}</div>
            <input type="file" accept={v.ext.join(',')} onChange={(e) => setFile(e.target.files[0] || null)} />
            <div className="alert info small">{t("Die Datei wird nur im Arbeitsspeicher ausgewertet (höchstens eine Stunde) und nicht gespeichert. Verschlüsselte Exporte lassen sich nicht lesen.")}</div>
            <div><button className="primary" disabled={!file || busy} onClick={upload}>{busy ? t("Lese ein …") : t("Einlesen und Bericht erstellen")}</button></div>
          </div>
          <div className="panel panel-pad stack">
            <h3 style={{ margin: 0 }}>{t("Was übernommen wird")}</h3>
            <Matrix rows={v.matrix} />
          </div>
        </div>}
      </>}

      {parsed && <div className="stack">
        <div className="panel panel-pad stack">
          <div className="row" style={{ flexWrap: 'wrap', gap: 8 }}>
            <h3 style={{ margin: 0 }}>{t("2. Migrationsbericht")}</h3>
            <span className="badge b-info">{vendors.find((x) => x.id === parsed.vendor)?.title}</span>
            <span className="muted small">{parsed.filename}{parsed.source?.hostname ? ` · ${parsed.source.hostname}` : ''}</span>
          </div>
          <div className="row small" style={{ flexWrap: 'wrap', gap: 8 }}>
            {Object.entries(parsed.counts).map(([k, n]) => <span key={k} className="badge">{COUNT_LABEL[k] || k}: {n}</span>)}
          </div>
          {parsed.warnings.map((w) => <div key={w} className="alert warn small">{w}</div>)}
          <Report report={parsed.report} />
        </div>

        {parsed.needs_zones && <div className="panel panel-pad stack">
          <h3 style={{ margin: 0 }}>{t("3. Zonen zuordnen")}</h3>
          <div className="muted small">{t("Sophos-Regeln arbeiten mit Zonen statt Interfaces. Ordnen Sie jedes Quell-Interface bzw. jede Quell-Zone einer Sophos-Zone zu; „beliebig“ lässt die Zone in den Regeln offen.")}</div>
          <div className="table-wrap"><table className="no-resize">
            <thead><tr><th>{t("Quelle")}</th><th>{t("Art")}</th><th>{t("Details")}</th><th>{t("Sophos-Zone")}</th></tr></thead>
            <tbody>{parsed.interfaces.map((i) => (
              <tr key={i.name}>
                <td><b>{i.name}</b></td>
                <td className="small muted">{i.kind || '–'}</td>
                <td className="small">{[i.ip, i.note].filter(Boolean).join(' · ') || '–'}</td>
                <td><input list="mig-zones" value={zones[i.name] ?? ''} placeholder={t("beliebig")} style={{ maxWidth: 180 }}
                  onChange={(e) => { setZones({ ...zones, [i.name]: e.target.value }); setPreview(null) }} /></td>
              </tr>))}
            </tbody>
          </table></div>
          <datalist id="mig-zones">{ZONES.map((z) => <option key={z} value={z} />)}</datalist>
          <Field label={t("Präfix für alle Namen (optional)")} hint={t("z. B. FGT_ – vermeidet Namenskonflikte mit vorhandenen Objekten")}>
            <input value={prefix} maxLength={20} onChange={(e) => { setPrefix(e.target.value); setPreview(null) }} style={{ maxWidth: 200 }} /></Field>
        </div>}

        <div className="panel panel-pad stack">
          <div className="row"><h3 style={{ margin: 0 }}>{t("Ergebnis prüfen")}</h3>
            <button className="right sm" disabled={busy} onClick={loadPreview}>{preview ? t("Aktualisieren") : t("Umwandlung anzeigen")}</button></div>
          {preview && <>
            <div className="row small" style={{ flexWrap: 'wrap', gap: 8 }}>
              {Object.entries(preview.counts).map(([k, n]) => <span key={k} className="badge b-ok">{k}: {n}</span>)}
            </div>
            {preview.notes.length > 0 && <div className="table-wrap" style={{ maxHeight: 320, overflowY: 'auto' }}><table className="no-resize">
              <thead><tr><th>{t("Objekt")}</th><th>{t("Status")}</th><th>{t("Hinweis")}</th></tr></thead>
              <tbody>{preview.notes.map((n, i) => (
                <tr key={i}><td><span className="muted small">{n.kind}</span> <b>{n.name}</b></td><td><Badge status={n.status} map={NOTE} /></td><td className="small">{n.note}</td></tr>))}
              </tbody></table></div>}
            {preview.rules.length > 0 && <details><summary className="small">{t("{0} Regeln mit Zonen", preview.rules.length)}</summary>
              <table className="no-resize small"><tbody>{preview.rules.map((r) => (
                <tr key={r.name}><td>{r.name}</td><td>{r.action}</td><td>{r.src_zones.join(', ') || t("beliebig")} → {r.dst_zones.join(', ') || t("beliebig")}</td>
                  <td>{r.enabled ? '' : <span className="badge">{t("deaktiviert")}</span>}</td></tr>))}</tbody></table></details>}
          </>}
        </div>

        <div className="panel panel-pad stack">
          <h3 style={{ margin: 0 }}>{t("4. Übernehmen")}</h3>
          <Seg options={[['draft', t("Entwurf einer Firewall")], ['template', t("Vorlage")], ['file', t("Entities.xml herunterladen")]]} value={target} onChange={setTarget} />
          {target === 'draft' && <div className="stack">
            <div className="muted small">{t("Vergleich mit der gewählten Firewall (neu / geändert / identisch); ausgewählte Objekte landen in Ihrem Entwurf und werden erst nach Vier-Augen-Freigabe ausgerollt.")}</div>
            <div className="row" style={{ gap: 8 }}>
              <select value={fwId} onChange={(e) => setFwId(e.target.value)} style={{ maxWidth: 320 }}>
                <option value="">{t("– Firewall wählen –")}</option>
                {targets.map((f) => <option key={f.id} value={f.id}>{f.name}</option>)}
              </select>
              <button className="primary" disabled={!fwId || busy} onClick={toDraft}>{t("Vergleichen und auswählen …")}</button>
            </div>
          </div>}
          {target === 'template' && <div className="stack">
            <div className="muted small">{t("Soll-Zustand für beliebige Firewalls – ausgerollt wird über einen Antrag mit Vier-Augen-Freigabe.")}</div>
            <div className="form-grid">
              <Field label={t("Name der Vorlage")}><input value={tpl.name} onChange={(e) => setTpl({ ...tpl, name: e.target.value })} /></Field>
              <Field label={t("Format")} hint={t("Vorlagen passen nur auf Firewalls mit gleicher Anbindung")}>
                <select value={tpl.format} onChange={(e) => setTpl({ ...tpl, format: e.target.value })}>
                  <option value="rest">{t("SFOS REST-API")}</option><option value="xml">{t("XML-API / Sophos Central (Entities.xml)")}</option>
                </select></Field>
            </div>
            <div><button className="primary" disabled={!tpl.name.trim() || busy} onClick={toTemplate}>{t("Vorlage anlegen")}</button></div>
            {result?.kind === 'template' && <div className="alert ok small">{t("Vorlage „{0}“ mit {1} Einträgen angelegt.", result.name, result.items)}{' '}
              <Link to={`/templates/${result.id}`}>{t("Öffnen")}</Link>
              {result.skipped.length > 0 && <div className="text-warn">{t("Nicht übernommen: {0}", result.skipped.slice(0, 8).join('; '))}{result.skipped.length > 8 ? ' …' : ''}</div>}</div>}
          </div>}
          {target === 'file' && <div className="stack">
            <div className="muted small">{t("Wie im Config Studio: Entities.xml zum Import auf einer (neuen) Sophos Firewall über Backup & firmware › Import export. Ohne Antrag und ohne Freigabe.")}</div>
            <div><button className="primary" disabled={busy} onClick={toFile}>{t("Entities.xml herunterladen")}</button></div>
          </div>}
        </div>
      </div>}
      {review && <ImportModal fw={targets.find((f) => f.id === fwId)} review={review} onClose={() => setReview(null)}
        onApplied={(r) => { setReview(null); setResult({ kind: 'draft', ...r }); setError('') }} />}
      {result?.kind === 'draft' && <div className="alert ok">{t("{0} Objekte in den Entwurf übernommen.", result.added)}{' '}
        <Link to={`/firewalls/${fwId}`}>{t("Zur Firewall und einreichen")}</Link>
        {result.skipped.length > 0 && <div className="small text-warn">{t("Übersprungen: {0}", result.skipped.slice(0, 8).join('; '))}</div>}</div>}
    </>
  )
}
