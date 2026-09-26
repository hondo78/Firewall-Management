import { useMemo, useState } from 'react'
import { EditorShell } from './Editors'
import { asList, restRefOptions } from './entities'
import { Check, Heading, Label, PositionSelect, Select, SfList, Toggle } from './SophosRules'
import { Field, Seg } from './ui'
import { t } from '../i18n'

/**
 * WAF-Regel (Webserver-Schutz) im Aufbau von SFOS „Edit firewall rule“: Gehosteter Server, Traffic Routing,
 * Ausnahmen, Erweitert. Daten im XML-Format (FirewallRule mit PolicyType HTTPBased) – gelesen/geschrieben über
 * den zusätzlichen XML-API-Zugang einer REST-Firewall. Unbekannte Felder bleiben unverändert erhalten.
 */

const list = (v) => asList(v).filter((x) => x !== '' && x != null)
const one = (arr) => (arr.length === 1 ? arr[0] : arr)
// Ja/Nein-Werte kommen als Enable/Disable oder 1/0 – beim Setzen die vorhandene Schreibweise beibehalten
const on = (v) => ['enable', '1', 'yes', 'true'].includes(String(v ?? '').toLowerCase())
const flag = (old, value) => (['0', '1'].includes(String(old)) ? (value ? '1' : '0') : value ? 'Enable' : 'Disable')

const THREATS = [['application_attacks', t("Anwendungsangriffe")], ['sql_injection_attacks', 'SQL-Injection'], ['xss_attacks', 'XSS-Angriffe'],
  ['protocol_enforcement', t("Protokolldurchsetzung")], ['scanner_detection', t("Scanner-Erkennung")], ['data_leakages', t("Datenlecks")]]
const SKIPS = [['skipav', t("Antivirus")], ['skipbadclients', t("Clients mit schlechtem Ruf blockieren")], ['skipcookie', t("Cookie-Signierung")],
  ['skipform', t("Formular-Härtung")], ['skipform_missingtoken', t("Formular-Härtung: fehlendes Token")], ['skipurl', t("Static-URL-Härtung")],
  ['skiphtmlrewrite', 'HTML-Umschreibung']]

export function newWafRule() {
  return {
    Name: '', Description: '', IPFamily: 'IPv4', Status: 'Enable', PolicyType: 'HTTPBased',
    HTTPBasedPolicy: {
      HostedAddress: '', HTTPS: 'Enable', ListenPort: '443', Domains: { Domain: [] },
      AccessPaths: { AccessPath: [{ path: '/', backend: '', be_path: '', allowed_networks: 'Any IPv4', auth_profile: '',
        block_unknown_country: '0', hot_standby: '0', stickysession_status: '0', websocket_passthrough: '0' }] },
      Exceptions: { Exception: [] }, ProtocolSecurity: '', CompressionSupport: 'Disable', RewriteHTML: '0',
      PassHostHeader: 'Enable', RewriteCookies: 'Enable', IntrusionPrevention: 'None', TrafficShapingPolicy: 'None',
      Certificate: '', RedirectHTTP: 'Enable', InterfaceUnavailable: '0', BackendsUnavailable: '0', ResponseFieldSize: '8192',
    },
  }
}

/** Freie Einträge (Domänen, Pfade) wie in SFOS: Liste mit ⊖ und Eingabefeld „Suchen / Hinzufügen“ */
function FreeList({ value, onChange, placeholder, label }) {
  const [txt, setTxt] = useState('')
  const add = () => { const v = txt.trim(); if (v && !value.includes(v)) onChange([...value, v]); setTxt('') }
  return (
    <div className="sf-list">
      <div className="sf-list-items">
        {!value.length && <div className="sf-list-item any"><span>{t("keine")}</span></div>}
        {value.map((v) => (
          <div key={v} className="sf-list-item"><span>{v}</span>
            <button type="button" className="sf-remove" aria-label={`${v} entfernen`} onClick={() => onChange(value.filter((x) => x !== v))}>−</button></div>
        ))}
      </div>
      <div className="sf-free-add">
        <input value={txt} placeholder={placeholder} aria-label={label} onChange={(e) => setTxt(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); add() } }} />
        <button type="button" onClick={add} aria-label={t("Hinzufügen")}>+</button>
      </div>
    </div>
  )
}

function PathEditor({ path, opts, onSave, onCancel }) {
  const [p, setP] = useState(() => structuredClone(path))
  const set = (patch) => setP({ ...p, ...patch })
  return (
    <div className="sf-inline-edit">
      <div className="sf-grid3">
        <div><Label required>{t("Pfad")}</Label><input value={p.path || ''} onChange={(e) => set({ path: e.target.value })} placeholder="/" aria-label={t("Pfad")} /></div>
        <div><Label required>{t("Webserver (Ziel)")}</Label>
          <SfList label={t("Webserver")} emptyLabel="keiner" value={list(p.backend)} options={opts.wafServers} onChange={(v) => set({ backend: one(v) })} /></div>
        <div className="stack">
          <div><Label>{t("Pfad auf dem Webserver")}</Label><input value={p.be_path || ''} onChange={(e) => set({ be_path: e.target.value })} placeholder={t("(wie Pfad)")} aria-label={t("Pfad auf dem Webserver")} /></div>
          <div><Label>{t("Authentifizierung")}</Label>
            <Select value={p.auth_profile || ''} none={t("Keine")} options={opts.wafAuth} onChange={(v) => set({ auth_profile: v })} /></div>
        </div>
        <div><Label>{t("Erlaubte Clients (Netzwerke)")}</Label>
          <SfList label={t("Erlaubte Clients")} emptyLabel="Any IPv4" value={list(p.allowed_networks).filter((n) => n !== 'Any IPv4')} options={opts.networks}
            onChange={(v) => set({ allowed_networks: v.length ? one(v) : 'Any IPv4' })} /></div>
        <div className="stack">
          <Check checked={on(p.block_unknown_country)} label={t("Unbekannte Länder blockieren (GeoIP)")} onChange={(v) => set({ block_unknown_country: flag(p.block_unknown_country ?? '0', v) })} />
          <Check checked={on(p.stickysession_status)} label={t("Sticky Sessions")} onChange={(v) => set({ stickysession_status: flag(p.stickysession_status ?? '0', v) })} />
          <Check checked={on(p.hot_standby)} label={t("Hot-Standby-Modus")} onChange={(v) => set({ hot_standby: flag(p.hot_standby ?? '0', v) })} />
          <Check checked={on(p.websocket_passthrough)} label="WebSocket-Durchleitung" onChange={(v) => set({ websocket_passthrough: flag(p.websocket_passthrough ?? '0', v) })} />
        </div>
      </div>
      <div className="row"><button className="primary sm" disabled={!p.path || !list(p.backend).length} onClick={() => onSave(p)}>{t("Pfad übernehmen")}</button>
        <button className="sm" onClick={onCancel}>{t("Abbrechen")}</button></div>
    </div>
  )
}

function ExceptionEditor({ ex, opts, onSave, onCancel }) {
  const [x, setX] = useState(() => structuredClone(ex))
  const set = (patch) => setX({ ...x, ...patch })
  const cats = list(x.skip_threats_filter_categories)
  return (
    <div className="sf-inline-edit">
      <div className="sf-grid3">
        <div><Label>{t("Pfade")}</Label><FreeList label={t("Pfad hinzufügen")} placeholder={t("z. B. /api/*")} value={list(x.path)} onChange={(v) => set({ path: one(v) })} /></div>
        <div className="stack">
          <div><Label>{t("Quellen (Netzwerke)")}</Label>
            <SfList label={t("Quellen")} emptyLabel="Any IPv4" value={list(x.source).filter((n) => n !== 'Any IPv4')} options={opts.networks}
              onChange={(v) => set({ source: v.length ? one(v) : 'Any IPv4' })} /></div>
          <div><Label>{t("Pfade und Quellen verknüpfen mit")}</Label>
            <Seg options={[['and', 'UND'], ['or', 'ODER']]} value={x.op || 'and'} onChange={(v) => set({ op: v })} /></div>
        </div>
        <div className="stack">
          <Label>{t("Diese Prüfungen überspringen")}</Label>
          {SKIPS.map(([k, l]) => <Check key={k} checked={on(x[k])} label={l} onChange={(v) => set({ [k]: flag(x[k] ?? '0', v) })} />)}
        </div>
      </div>
      <div><Label>{t("Kategorien des Bedrohungsfilters überspringen")}</Label>
        <div className="sf-checks">{THREATS.map(([k, l]) => (
          <Check key={k} checked={cats.includes(k)} label={l} onChange={(v) => set({ skip_threats_filter_categories: v ? [...cats, k] : cats.filter((c) => c !== k) })} />))}</div></div>
      <div className="row"><button className="primary sm" onClick={() => onSave(x)}>{t("Ausnahme übernehmen")}</button><button className="sm" onClick={onCancel}>{t("Abbrechen")}</button></div>
    </div>
  )
}

const NEW_PATH = { path: '/', backend: '', be_path: '', allowed_networks: 'Any IPv4', auth_profile: '', block_unknown_country: '0',
  hot_standby: '0', stickysession_status: '0', websocket_passthrough: '0' }
const NEW_EXCEPTION = { path: [], source: 'Any IPv4', op: 'and', skipav: '0', skipbadclients: '0', skipcookie: '0', skipform: '0',
  skipform_missingtoken: '0', skipurl: '0', skiphtmlrewrite: '0', skip_threats_filter_categories: [] }

const X = () => <span className="sf-x" aria-label={t("nein")}>✕</span>
const Yes = () => <span className="sf-yes" aria-label={t("ja")}>✓</span>

export function WafRuleEditor({ config, rule, onClose, onSubmit, page }) {
  const entity = 'wafRules'
  const isNew = !rule
  const opts = useMemo(() => {
    const o = restRefOptions(config)
    const certs = [...new Set((config.wafRules || []).map((r) => r.HTTPBasedPolicy?.Certificate).filter(Boolean))]
    const hosts = [...new Set([...(config.interfaces || []).map((i) => `#${i.name}`), ...(config.wafRules || []).map((r) => r.HTTPBasedPolicy?.HostedAddress).filter(Boolean)])]
    return { ...o, certs, hosts }
  }, [config])
  const rules = [...(config.firewallRulesIpv4 || []).map((r) => r.name)]
  const [d, setD] = useState(() => structuredClone(rule || newWafRule()))
  const [position, setPosition] = useState(isNew ? { type: 'bottom' } : { type: 'keep' })
  const [editPath, setEditPath] = useState(null)   // {index|-1, value}
  const [editEx, setEditEx] = useState(null)
  const p = d.HTTPBasedPolicy || {}
  const setP = (patch) => setD((cur) => ({ ...cur, HTTPBasedPolicy: { ...(cur.HTTPBasedPolicy || {}), ...patch } }))
  const paths = asList(p.AccessPaths?.AccessPath)
  const setPaths = (v) => setP({ AccessPaths: { AccessPath: v } })
  const exs = asList(p.Exceptions?.Exception)
  const setExs = (v) => setP({ Exceptions: { Exception: v } })
  const domains = list(p.Domains?.Domain)
  const pol = (v) => (v && v !== 'None' ? v : '')

  const form = (
    <div className="sf-rule">
      <Toggle checked={on(d.Status)} onChange={(v) => setD({ ...d, Status: v ? 'Enable' : 'Disable' })} label={t("Regelstatus")} />
      <div className="sf-grid3">
        <div><Label required>{t("Regelname")}</Label>
          <input value={d.Name} disabled={!isNew} maxLength={60} autoFocus={isNew} onChange={(e) => setD({ ...d, Name: e.target.value })} aria-label={t("Regelname")} /></div>
        <div className="sf-span2row"><Label>{t("Beschreibung")}</Label>
          <textarea rows={3} value={d.Description || ''} placeholder={t("Beschreibung")} aria-label={t("Beschreibung")} onChange={(e) => setD({ ...d, Description: e.target.value })} /></div>
        <div><Label>{t("Position in der Regelliste")}</Label>
          <PositionSelect position={position} setPosition={setPosition} rules={rules} name={d.Name} isNew={isNew} /></div>
      </div>

      <hr />
      <Heading title={t("Gehosteter Server")} />
      <div className="sf-grid3">
        <div className="stack">
          <div><Label required>{t("Gehostete Adresse")}</Label>
            <input list="waf-hosts" value={p.HostedAddress || ''} onChange={(e) => setP({ HostedAddress: e.target.value })} placeholder="#Port2" aria-label={t("Gehostete Adresse")} />
            <datalist id="waf-hosts">{opts.hosts.map((h) => <option key={h} value={h} />)}</datalist>
            <small className="sf-hint">{t("Schnittstelle als „#PortN“ oder Alias/IP-Host")}</small></div>
          <Check checked={on(p.RedirectHTTP)} label={t("Umleitungs-HTTP")} hint={t("HTTP-Anfragen auf HTTPS umleiten")} onChange={(v) => setP({ RedirectHTTP: flag(p.RedirectHTTP ?? 'Enable', v) })} />
        </div>
        <div className="stack">
          <div><Label required>{t("Lausch-Port")}</Label>
            <input type="number" min={1} max={65535} value={p.ListenPort || ''} onChange={(e) => setP({ ListenPort: e.target.value })} aria-label={t("Lausch-Port")} /></div>
          <Check checked={on(p.HTTPS)} label="HTTPS" onChange={(v) => setP({ HTTPS: flag(p.HTTPS ?? 'Enable', v), ListenPort: p.ListenPort || (v ? '443' : '80') })} />
          {on(p.HTTPS) && <div><Label required>{t("HTTPS-Zertifikat")}</Label>
            <input list="waf-certs" value={p.Certificate || ''} onChange={(e) => setP({ Certificate: e.target.value })} aria-label="HTTPS-Zertifikat" />
            <datalist id="waf-certs">{opts.certs.map((c) => <option key={c} value={c} />)}</datalist>
            <small className="sf-hint">{t("Name des Zertifikats auf der Firewall")}</small></div>}
        </div>
        <div><Label required>{t("Domänen")}</Label>
          <FreeList label={t("Domäne hinzufügen")} placeholder={t("Suchen / Hinzufügen")} value={domains} onChange={(v) => setP({ Domains: { Domain: v } })} /></div>
      </div>

      <hr />
      <div className="row between"><Heading title={t("Traffic routing")} />
        <button className="primary" onClick={() => setEditPath({ index: -1, value: NEW_PATH })}>{t("Neuen Pfad hinzufügen")}</button></div>
      {editPath && <PathEditor key={editPath.index} path={editPath.value} opts={opts} onCancel={() => setEditPath(null)}
        onSave={(v) => { setPaths(editPath.index < 0 ? [...paths, v] : paths.map((x, i) => (i === editPath.index ? v : x))); setEditPath(null) }} />}
      <div className="table-wrap">
        <table className="cs-grid">
          <thead><tr><th>{t("Pfad")}</th><th>{t("Ziel")}</th><th>{t("Access control")}</th><th>{t("Sticky Sessions")}</th><th>{t("Hot-Standby-Modus")}</th><th className="actions">{t("Verwalten")}</th></tr></thead>
          <tbody>
            {!paths.length && <tr><td colSpan={6} className="muted">{t("Keine Einträge gefunden")}</td></tr>}
            {paths.map((ap, i) => (
              <tr key={i}>
                <td><code>{ap.path}</code>{ap.be_path && <div className="small muted">→ {ap.be_path}</div>}</td>
                <td>{list(ap.backend).join(', ') || <span className="muted">–</span>}</td>
                <td><span className="chips">
                  {ap.auth_profile && <span className="feat" title={t("Authentifizierung: {0}", ap.auth_profile)}>RA</span>}
                  {list(ap.allowed_networks).some((n) => n !== 'Any IPv4') && <span className="feat" title={t("Erlaubt: {0}", list(ap.allowed_networks).join(', '))}>SRC</span>}
                  {on(ap.block_unknown_country) && <span className="feat" title={t("Unbekannte Länder blockiert")}>{t("GeoIP")}</span>}
                  {on(ap.websocket_passthrough) && <span className="feat" title="WebSocket-Durchleitung">WS</span>}
                </span></td>
                <td>{on(ap.stickysession_status) ? <Yes /> : <X />}</td>
                <td>{on(ap.hot_standby) ? <Yes /> : <X />}</td>
                <td className="actions nowrap">
                  <button className="ghost sm" onClick={() => setEditPath({ index: i, value: ap })}>{t("Bearbeiten")}</button>
                  <button className="ghost sm" disabled={paths.length === 1} title={paths.length === 1 ? t("Mindestens ein Pfad nötig") : t("Pfad entfernen")}
                    onClick={() => setPaths(paths.filter((_, j) => j !== i))}>{t("Entfernen")}</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <hr />
      <div className="row between"><Heading title={t("Ausnahmen")} />
        <button className="primary" onClick={() => setEditEx({ index: -1, value: NEW_EXCEPTION })}>{t("Neue Ausnahme hinzufügen")}</button></div>
      {editEx && <ExceptionEditor key={editEx.index} ex={editEx.value} opts={opts} onCancel={() => setEditEx(null)}
        onSave={(v) => { setExs(editEx.index < 0 ? [...exs, v] : exs.map((x, i) => (i === editEx.index ? v : x))); setEditEx(null) }} />}
      <div className="table-wrap">
        <table className="cs-grid">
          <thead><tr><th>{t("Pfade")}</th><th>{t("Quellen")}</th><th>{t("Prüfungen")}</th><th>{t("Kategorien")}</th><th className="actions">{t("Verwalten")}</th></tr></thead>
          <tbody>
            {!exs.length && <tr><td colSpan={5} className="muted">{t("Keine Einträge gefunden")}</td></tr>}
            {exs.map((x, i) => (
              <tr key={i}>
                <td className="small">{list(x.path).join(', ') || t("alle")}</td>
                <td className="small">{list(x.source).join(', ') || 'Any IPv4'} <span className="muted">({x.op === 'or' ? 'ODER' : 'UND'})</span></td>
                <td className="small">{SKIPS.filter(([k]) => on(x[k])).map(([, l]) => l).join(', ') || '–'}</td>
                <td className="small">{THREATS.filter(([k]) => list(x.skip_threats_filter_categories).includes(k)).map(([, l]) => l).join(', ') || '–'}</td>
                <td className="actions nowrap">
                  <button className="ghost sm" onClick={() => setEditEx({ index: i, value: x })}>{t("Bearbeiten")}</button>
                  <button className="ghost sm" onClick={() => setExs(exs.filter((_, j) => j !== i))}>{t("Entfernen")}</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <hr />
      <Heading title={t("Erweitert")} />
      <div className="sf-grid3">
        <div><Label>{t("Schutz")}</Label><Select value={p.ProtocolSecurity || ''} none={t("Keiner")} options={opts.wafProtection} onChange={(v) => setP({ ProtocolSecurity: v })} /></div>
        <div><Label>{t("Angriffsvorbeugung")}</Label><Select value={pol(p.IntrusionPrevention)} none={t("Keine")} options={opts.ipsPolicies} onChange={(v) => setP({ IntrusionPrevention: v || 'None' })} /></div>
        <div><Label>{t("Traffic-Shaping")}</Label><Select value={pol(p.TrafficShapingPolicy)} none={t("Keine")} options={opts.tsPolicies} onChange={(v) => setP({ TrafficShapingPolicy: v || 'None' })} /></div>
      </div>
      <div className="stack">
        <Label>{t("Zusätzliche Optionen")}</Label>
        <Check checked={!on(p.CompressionSupport)} label={t("Komprimierungsunterstützung deaktivieren")} onChange={(v) => setP({ CompressionSupport: flag(p.CompressionSupport ?? 'Enable', !v) })} />
        <Check checked={on(p.RewriteHTML)} label={t("HTML umschreiben")} onChange={(v) => setP({ RewriteHTML: flag(p.RewriteHTML ?? '0', v) })} />
        {on(p.RewriteHTML) && <div className="sf-indent"><Check checked={on(p.RewriteCookies)} label={t("Cookies umschreiben")} onChange={(v) => setP({ RewriteCookies: flag(p.RewriteCookies ?? 'Enable', v) })} /></div>}
        <Check checked={on(p.PassHostHeader)} label={t("Host-Header durchreichen")} onChange={(v) => setP({ PassHostHeader: flag(p.PassHostHeader ?? 'Enable', v) })} />
      </div>
    </div>
  )
  return (
    <EditorShell page={page} title={isNew ? t("WAF-Regel hinzufügen") : t("WAF-Regel bearbeiten")} entity={entity} data={d} setData={setD} isNew={isNew}
      form={form} onClose={onClose}
      onSubmit={(payload) => {
        const hp = payload.HTTPBasedPolicy || {}
        if (!payload.Name) throw new Error(t('Regelname fehlt'))
        if (!hp.HostedAddress || !hp.ListenPort || !list(hp.Domains?.Domain).length) throw new Error(t('Gehostete Adresse, Lausch-Port und mindestens eine Domäne sind nötig'))
        if (on(hp.HTTPS) && !hp.Certificate) throw new Error(t('Für HTTPS ist ein Zertifikat nötig'))
        if (!asList(hp.AccessPaths?.AccessPath).length) throw new Error(t('Mindestens ein Pfad (Traffic routing) ist nötig'))
        return onSubmit({ entity, action: isNew ? 'add' : 'update', name: payload.Name, data: payload,
          position: position.type === 'keep' ? null : position })
      }} />
  )
}

// --- Webserver & Schutzrichtlinie (REST) --------------------------------------------------------------------

export const NEW_WAF = {
  wafServers: { name: '', description: '', protocol: 'http', port: 80, keepAlive: true, timeout: 300, disableConnectionPooling: false },
  wafProtectionPolicies: {
    name: '', description: '', action: 'reject', bypassMicrosoftOutlook: false, cookieSigning: false, formHardening: false,
    staticUrlHardening: { enabled: false, urls: [] }, httpStrictTransportSecurity: false, mimeTypeSniffingProtection: false, requestSizeLimit: 10,
    antivirus: { enabled: true, scanEngine: 'sophos', direction: 'uploadsAndDownloads', blockUnscannableContent: false },
    blockClientsWithBadReputation: { enabled: true, skipRemoteLookups: false },
    threatFilter: { enabled: true, filterStrength: 'level2', skipOwaspCrsRuleIds: [], applicationAttacks: true, sqlInjectionAttacks: true,
      xssAttacks: true, protocolEnforcement: true, scannerDetection: true, dataLeakage: false },
  },
}

export function WafServerForm({ data, setData, isNew, config }) {
  const opts = useMemo(() => restRefOptions(config || {}), [config])
  const kind = data.server?.fqdn ? 'fqdn' : 'ipv4Address'
  const ref = data.server?.[kind]?.name || ''
  const set = (k) => (e) => setData({ ...data, [k]: e.target.type === 'number' ? Number(e.target.value) : e.target.value })
  return (
    <div className="stack">
      <div className="form-grid">
        <Field label={t("Name")}><input value={data.name || ''} disabled={!isNew} onChange={set('name')} /></Field>
        <Field label={t("Beschreibung")}><input value={data.description || ''} onChange={set('description')} /></Field>
      </div>
      <Field label={t("Adresse des Webservers")}><Seg options={[['ipv4Address', 'IP-Host'], ['fqdn', 'FQDN-Host']]} value={kind}
        onChange={(k) => setData({ ...data, server: { [k]: { name: '' } } })} /></Field>
      <div className="form-grid">
        <Field label={kind === 'fqdn' ? 'FQDN-Host' : 'IP-Host'}>
          <select value={ref} onChange={(e) => setData({ ...data, server: { [kind]: { name: e.target.value } } })}>
            <option value="">{t("– wählen –")}</option>
            {(kind === 'fqdn' ? opts.fqdn : opts.ipv4).map((o) => <option key={o.value}>{o.value}</option>)}
            {ref && !(kind === 'fqdn' ? opts.fqdn : opts.ipv4).some((o) => o.value === ref) && <option>{ref}</option>}
          </select>
        </Field>
        <Field label={t("Protokoll")}><Seg options={[['http', 'HTTP'], ['https', 'HTTPS']]} value={data.protocol || 'http'} onChange={(v) => setData({ ...data, protocol: v })} /></Field>
        <Field label={t("Port")}><input type="number" min={1} max={65535} value={data.port ?? ''} onChange={set('port')} /></Field>
      </div>
      <div className="sf-toggles">
        <Check checked={data.keepAlive} label={t("Keep-Alive")} onChange={(v) => setData({ ...data, keepAlive: v })} />
        <Check checked={data.disableConnectionPooling} label={t("Connection-Pooling deaktivieren")} onChange={(v) => setData({ ...data, disableConnectionPooling: v })} />
      </div>
      {data.keepAlive && <Field label={t("Timeout (Sekunden)")}><input type="number" min={1} max={65535} value={data.timeout ?? ''} onChange={set('timeout')} style={{ maxWidth: 200 }} /></Field>}
    </div>
  )
}

export function WafProtectionForm({ data, setData, isNew }) {
  const sub = (k, patch) => setData({ ...data, [k]: { ...(data[k] || {}), ...patch } })
  const av = data.antivirus || {}
  const tf = data.threatFilter || {}
  const br = data.blockClientsWithBadReputation || {}
  const su = data.staticUrlHardening || {}
  return (
    <div className="stack">
      <div className="form-grid">
        <Field label={t("Name")}><input value={data.name || ''} disabled={!isNew} onChange={(e) => setData({ ...data, name: e.target.value })} /></Field>
        <Field label={t("Beschreibung")}><input value={data.description || ''} onChange={(e) => setData({ ...data, description: e.target.value })} /></Field>
      </div>
      <Field label={t("Modus")}><Seg options={[['reject', t("Ablehnen")], ['monitor', t("Nur überwachen")]]} value={data.action || 'reject'} onChange={(v) => setData({ ...data, action: v })} /></Field>
      <div className="sf-toggles">
        <Check checked={data.bypassMicrosoftOutlook} label={t("Microsoft Outlook umgehen")} onChange={(v) => setData({ ...data, bypassMicrosoftOutlook: v })} />
        <Check checked={data.cookieSigning} label={t("Cookie-Signierung")} onChange={(v) => setData({ ...data, cookieSigning: v })} />
        <Check checked={data.formHardening} label={t("Formular-Härtung")} onChange={(v) => setData({ ...data, formHardening: v })} />
        <Check checked={data.httpStrictTransportSecurity} label={t("HTTP Strict Transport Security")} onChange={(v) => setData({ ...data, httpStrictTransportSecurity: v })} />
        <Check checked={data.mimeTypeSniffingProtection} label={t("Schutz vor MIME-Type-Sniffing")} onChange={(v) => setData({ ...data, mimeTypeSniffingProtection: v })} />
        <Check checked={br.enabled} label={t("Clients mit schlechtem Ruf blockieren")} onChange={(v) => sub('blockClientsWithBadReputation', { enabled: v })} />
      </div>
      <div className="form-grid">
        <Field label={t("Größenlimit der Anfrage (MB)")}><input type="number" min={1} max={1024} value={data.requestSizeLimit ?? ''} onChange={(e) => setData({ ...data, requestSizeLimit: Number(e.target.value) })} /></Field>
      </div>
      <div><Check checked={su.enabled} label={t("Static-URL-Härtung")} onChange={(v) => sub('staticUrlHardening', { enabled: v, urls: v && !asList(su.urls).length ? ['/'] : asList(su.urls) })} /></div>
      {su.enabled && <Field label={t("Einstiegs-URLs")}><FreeList label={t("URL hinzufügen")} placeholder="/login" value={asList(su.urls)} onChange={(v) => sub('staticUrlHardening', { urls: v })} /></Field>}
      <div><Check checked={av.enabled} label={t("Antivirus")} onChange={(v) => sub('antivirus', { enabled: v })} /></div>
      {av.enabled && <div className="form-grid">
        <Field label={t("Scan-Engine")}><select value={av.scanEngine || 'sophos'} onChange={(e) => sub('antivirus', { scanEngine: e.target.value })}>
          <option value="sophos">{t("Sophos")}</option><option value="avira">{t("Avira")}</option><option value="dual">{t("Dual")}</option></select></Field>
        <Field label={t("Richtung")}><select value={av.direction || 'uploadsAndDownloads'} onChange={(e) => sub('antivirus', { direction: e.target.value })}>
          <option value="uploads">{t("Uploads")}</option><option value="downloads">{t("Downloads")}</option><option value="uploadsAndDownloads">{t("Uploads und Downloads")}</option></select></Field>
      </div>}
      <div><Check checked={tf.enabled} label={t("Bedrohungsfilter (OWASP Core Rule Set)")} onChange={(v) => sub('threatFilter', { enabled: v })} /></div>
      {tf.enabled && <>
        <Field label={t("Filterstärke")}><Seg options={[['level1', t("Stufe 1")], ['level2', t("Stufe 2")], ['level3', t("Stufe 3")], ['level4', t("Stufe 4")]]}
          value={tf.filterStrength || 'level2'} onChange={(v) => sub('threatFilter', { filterStrength: v })} /></Field>
        <div className="sf-toggles">
          {[['applicationAttacks', t("Anwendungsangriffe")], ['sqlInjectionAttacks', 'SQL-Injection'], ['xssAttacks', 'XSS-Angriffe'],
            ['protocolEnforcement', t("Protokolldurchsetzung")], ['scannerDetection', t("Scanner-Erkennung")], ['dataLeakage', t("Datenlecks")]].map(([k, l]) => (
            <Check key={k} checked={tf[k]} label={l} onChange={(v) => sub('threatFilter', { [k]: v })} />))}
        </div>
        <Field label={t("Übersprungene OWASP-Regel-IDs")} hint={t("Kommagetrennt")}>
          <input value={asList(tf.skipOwaspCrsRuleIds).join(', ')} onChange={(e) => sub('threatFilter', { skipOwaspCrsRuleIds: e.target.value.split(/[,\s]+/).filter(Boolean).map(Number).filter((n) => !Number.isNaN(n)) })} />
        </Field>
      </>}
    </div>
  )
}
