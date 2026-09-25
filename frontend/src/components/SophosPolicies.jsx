import { asList } from './entities'
import { Box, Section, Toggle } from './SophosRules'
import { Field, Seg } from './ui'

/**
 * Richtlinien im Aufbau der SFOS-Weboberfläche: Web-, Anwendungs-, IPS- und Traffic-Shaping-Richtlinien.
 * Einstellungen und Regel-Aktionen sind per Formular editierbar; neue Richtlinien-Regeln (Kategorien,
 * Signatur-Filter …) legt man über den JSON-Expertenmodus an.
 */

const refName = (v) => (v && typeof v === 'object' ? v.name : '') || ''
const refNames = (items) => asList(items).map((i) => i?.name ?? i).filter(Boolean)

export const WEB_ACTION = { allow: 'Zulassen', deny: 'Blockieren', warn: 'Warnen', log: 'Protokollieren', quota: 'Kontingent' }
export const APP_ACTION = { allow: 'Zulassen', deny: 'Blockieren' }
export const IPS_ACTION = {
  recommended: 'Empfohlen', allowPacket: 'Paket zulassen', dropPacket: 'Paket verwerfen', disable: 'Deaktivieren',
  dropSession: 'Sitzung verwerfen', reset: 'Zurücksetzen', bypassSession: 'Sitzung umgehen',
}
const ACTIVITY_KEYS = [['categories', 'Kategorien'], ['urlGroups', 'URL-Gruppen'], ['fileTypes', 'Dateitypen'],
  ['dynamicCategories', 'Dynamische Kategorien'], ['userActivities', 'Benutzeraktivitäten']]

const actCls = (a) => (['allow', 'allowPacket', 'recommended', 'bypassSession'].includes(a) ? 'st-Accept' : a === 'warn' || a === 'log' || a === 'quota' ? 'b-info' : 'st-Drop')

function ActionBadge({ value, labels }) {
  return <span className={`badge ${actCls(value)}`}>{labels[value] || value || '–'}</span>
}

function ActionSelect({ value, labels, onChange }) {
  return (
    <select value={value || ''} onChange={(e) => onChange(e.target.value)} style={{ minWidth: 130 }}>
      {Object.entries(labels).map(([k, l]) => <option key={k} value={k}>{l}</option>)}
      {value && !labels[value] && <option value={value}>{value}</option>}
    </select>
  )
}

const who = (u) => (!u || u.any ? 'Alle' : [...refNames(u.users), ...refNames(u.userGroups)].join(', ') || 'Alle')
const activities = (a) => ACTIVITY_KEYS.flatMap(([k]) => refNames(a?.[k])).join(', ') || '–'
const filterText = (rows) => asList(rows).map((f) => `${f.attribute}: ${asList(f.values).join(', ')}`).join(' · ')
const appWhat = (r) => (r.selectionMode === 'applicationFilter' ? filterText(r.applicationFilters) || 'Filter'
  : r.selectionMode === 'smartFilter' ? `Smart-Filter: ${filterText(r.applicationFilters)}` : refNames(r.applicationList).join(', ') || '–')
const ipsWhat = (r) => (r.selectionMode === 'signatureList' ? refNames(r.signatureList).join(', ') || '–' : filterText(r.signatureFilters) || 'Alle Signaturen')
const kbps = (b) => {
  if (!b) return '–'
  const one = (x) => (x == null ? '' : x.aggregatedKbps != null ? `${x.aggregatedKbps} kbps` : `↑ ${x.uploadKbps ?? '?'} / ↓ ${x.downloadKbps ?? '?'} kbps`)
  return b.guaranteed ? `min ${one(b.guaranteed.min)} · max ${one(b.guaranteed.max)}` : one(b.bestEffort) || '–'
}

/** Regeltabelle einer Richtlinie; mit setRules editierbar (Aktion, aktiv, Reihenfolge, entfernen) */
function PolicyRules({ entity, rules, setRules }) {
  const edit = !!setRules
  const upd = (i, patch) => setRules(rules.map((r, j) => (j === i ? { ...r, ...patch } : r)))
  const move = (i, d) => { const n = [...rules]; [n[i], n[i + d]] = [n[i + d], n[i]]; setRules(n) }
  if (!rules.length) return <div className="muted small">Keine Regeln – es gilt die Standardaktion.</div>
  const web = entity === 'webPolicies'
  const labels = web ? WEB_ACTION : entity === 'ipsPolicies' ? IPS_ACTION : APP_ACTION
  return (
    <div className="table-wrap">
      <table className="cs-grid sf-policy">
        <thead><tr>
          <th style={{ width: 30 }}>#</th>
          {web ? <><th>Benutzer</th><th>Aktivitäten</th><th>HTTP</th><th>HTTPS</th><th>Zeitplan</th><th>Aktiv</th></>
            : <><th>Name</th><th>{entity === 'ipsPolicies' ? 'Signaturen' : 'Anwendungen'}</th><th>Aktion</th>{entity === 'applicationPolicies' && <th>Zeitplan</th>}</>}
          {edit && <th className="actions" />}
        </tr></thead>
        <tbody>
          {rules.map((r, i) => (
            <tr key={i} className={web && r.enabled === false ? 'row-disabled' : ''}>
              <td className="muted small">{i + 1}</td>
              {web ? <>
                <td className="small">{who(r.usersOrGroups)}</td>
                <td className="small">{activities(r.activities)}</td>
                <td>{edit ? <ActionSelect value={r.httpAction} labels={WEB_ACTION} onChange={(v) => upd(i, { httpAction: v })} /> : <ActionBadge value={r.httpAction} labels={WEB_ACTION} />}</td>
                <td>{r.followHttpAction ? <span className="muted small">wie HTTP</span>
                  : edit ? <ActionSelect value={r.httpsAction} labels={WEB_ACTION} onChange={(v) => upd(i, { httpsAction: v })} /> : <ActionBadge value={r.httpsAction} labels={WEB_ACTION} />}</td>
                <td className="small">{refName(r.schedule) || 'Immer'}</td>
                <td>{edit ? <Toggle checked={r.enabled !== false} onChange={(v) => upd(i, { enabled: v })} label="" /> : r.enabled === false ? 'nein' : 'ja'}</td>
              </> : <>
                <td className="small"><b>{r.name}</b></td>
                <td className="small">{entity === 'ipsPolicies' ? ipsWhat(r) : appWhat(r)}</td>
                <td>{edit ? <ActionSelect value={r.action} labels={labels} onChange={(v) => upd(i, { action: v })} /> : <ActionBadge value={r.action} labels={labels} />}</td>
                {entity === 'applicationPolicies' && <td className="small">{refName(r.schedule) || 'Immer'}</td>}
              </>}
              {edit && <td className="actions nowrap">
                <button className="ghost sm" disabled={i === 0} onClick={() => move(i, -1)} title="Nach oben">↑</button>
                <button className="ghost sm" disabled={i === rules.length - 1} onClick={() => move(i, 1)} title="Nach unten">↓</button>
                <button className="ghost sm" onClick={() => setRules(rules.filter((_, j) => j !== i))} title="Regel entfernen">×</button>
              </td>}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function NameDesc({ data, setData, isNew }) {
  return (
    <div className="form-grid">
      <Field label="Name"><input value={data.name || ''} disabled={!isNew} onChange={(e) => setData({ ...data, name: e.target.value })} /></Field>
      <Field label="Beschreibung"><input value={data.description || ''} onChange={(e) => setData({ ...data, description: e.target.value })} /></Field>
    </div>
  )
}

const RULE_HINT = <div className="muted small" style={{ marginTop: 6 }}>Neue Regeln (Kategorien, Filter, Signaturen) im JSON-Expertenmodus ergänzen.</div>

export function WebPolicyForm({ data, setData, isNew }) {
  const set = (k) => (v) => setData({ ...data, [k]: v })
  return (
    <div className="sf-form">
      <Section title="Allgemein"><NameDesc data={data} setData={setData} isNew={isNew} />
        <div className="form-grid">
          <Box label="Standardaktion (wenn keine Regel greift)"><Seg options={[['allow', 'Zulassen'], ['deny', 'Blockieren']]} value={data.defaultAction} onChange={set('defaultAction')} /></Box>
          <Field label="Max. Dateigröße (MB)"><input type="number" min={1} value={data.maxFileSize ?? ''} onChange={(e) => set('maxFileSize')(Number(e.target.value))} /></Field>
        </div>
      </Section>
      <Section title={`Regeln (${asList(data.rules).length})`}>
        <PolicyRules entity="webPolicies" rules={asList(data.rules)} setRules={set('rules')} />{RULE_HINT}
      </Section>
      <Section title="Erweitert" collapsible open={false}>
        <div className="sf-toggles">
          <Toggle checked={data.enforceSafeSearch} onChange={set('enforceSafeSearch')} label="SafeSearch erzwingen" />
          <Toggle checked={data.restrictFileSize} onChange={set('restrictFileSize')} label="Download-Größe begrenzen" />
          <Toggle checked={data.filterByImageLicense} onChange={set('filterByImageLicense')} label="Bildlizenz-Filter (Creative Commons)" />
          <Toggle checked={data.reporting} onChange={set('reporting')} label="Reporting" />
          <Toggle checked={data.propagateXForwardedFor} onChange={set('propagateXForwardedFor')} label="X-Forwarded-For weitergeben" />
          <Toggle checked={data.restrictGoogleAppDomains} onChange={set('restrictGoogleAppDomains')} label="Google-App-Domains einschränken" />
          <Toggle checked={data.restrictOffice365Tenants} onChange={set('restrictOffice365Tenants')} label="Microsoft-365-Tenants einschränken" />
        </div>
        <div className="form-grid">
          <Box label="YouTube-Filter"><Seg options={[['off', 'Aus'], ['moderate', 'Moderat'], ['strict', 'Streng']]} value={data.youtubeFilter || 'off'} onChange={set('youtubeFilter')} /></Box>
          <Field label="Kontingent (Minuten)"><input type="number" min={0} value={data.quotaLimit ?? ''} onChange={(e) => set('quotaLimit')(Number(e.target.value))} /></Field>
          {data.restrictGoogleAppDomains && <Field label="Erlaubte Google-Domains (kommagetrennt)">
            <input value={asList(data.googleAppDomainFilter).join(', ')} onChange={(e) => set('googleAppDomainFilter')(e.target.value.split(',').map((x) => x.trim()).filter(Boolean))} /></Field>}
          {data.restrictOffice365Tenants && <Field label="Erlaubte M365-Tenants (kommagetrennt)">
            <input value={asList(data.office365FilterTenants).join(', ')} onChange={(e) => set('office365FilterTenants')(e.target.value.split(',').map((x) => x.trim()).filter(Boolean))} /></Field>}
        </div>
      </Section>
    </div>
  )
}

export function RulePolicyForm({ entity, data, setData, isNew }) {
  return (
    <div className="sf-form">
      <Section title="Allgemein"><NameDesc data={data} setData={setData} isNew={isNew} /></Section>
      <Section title={`Regeln (${asList(data.rules).length})`}>
        <PolicyRules entity={entity} rules={asList(data.rules)} setRules={(rules) => setData({ ...data, rules })} />{RULE_HINT}
      </Section>
    </div>
  )
}

function Rate({ label, value, onChange }) {
  const v = value || {}
  const split = v.aggregatedKbps == null && (v.uploadKbps != null || v.downloadKbps != null)
  const num = (k) => (e) => onChange({ ...v, [k]: e.target.value === '' ? undefined : Number(e.target.value) })
  return (
    <Box label={label} hint="kbps, Vielfaches von 8">
      <div className="row">
        <Seg options={[['agg', 'Gesamt'], ['split', '↑/↓ getrennt']]} value={split ? 'split' : 'agg'}
          onChange={(m) => onChange(m === 'agg' ? { aggregatedKbps: v.uploadKbps || 1024 } : { uploadKbps: v.aggregatedKbps || 1024, downloadKbps: v.aggregatedKbps || 1024 })} />
        {split ? <>
          <input type="number" step={8} value={v.uploadKbps ?? ''} onChange={num('uploadKbps')} placeholder="Upload" style={{ width: 110 }} />
          <input type="number" step={8} value={v.downloadKbps ?? ''} onChange={num('downloadKbps')} placeholder="Download" style={{ width: 110 }} />
        </> : <input type="number" step={8} value={v.aggregatedKbps ?? ''} onChange={num('aggregatedKbps')} style={{ width: 130 }} />}
      </div>
    </Box>
  )
}

export function TrafficShapingForm({ data, setData, isNew }) {
  const set = (k) => (v) => setData({ ...data, [k]: v })
  const bw = data.bandwidth || {}
  const setType = (t) => setData({ ...data, type: t, bandwidth: t === 'guaranteed'
    ? { guaranteed: { min: bw.bestEffort || { aggregatedKbps: 1024 }, max: bw.bestEffort || { aggregatedKbps: 2048 } } }
    : { bestEffort: bw.guaranteed?.max || { aggregatedKbps: 1024 } } })
  return (
    <div className="sf-form">
      <Section title="Allgemein"><NameDesc data={data} setData={setData} isNew={isNew} />
        <div className="form-grid">
          <Box label="Gilt für"><Seg options={[['rules', 'Regeln'], ['users', 'Benutzer'], ['webCategories', 'Web-Kategorien'], ['applications', 'Anwendungen']]}
            value={data.associatesWith} onChange={set('associatesWith')} /></Box>
          <Box label="Zuweisung"><Seg options={[['true', 'Geteilt'], ['false', 'Pro Ziel']]} value={String(!!data.isShared)} onChange={(v) => set('isShared')(v === 'true')} /></Box>
        </div>
      </Section>
      <Section title="Bandbreite">
        <Box label="Typ"><Seg options={[['guaranteed', 'Garantiert + Limit'], ['bestEffort', 'Limit (Best Effort)']]} value={data.type} onChange={setType} /></Box>
        {data.type === 'guaranteed' ? <>
          <Rate label="Garantiert (min)" value={bw.guaranteed?.min} onChange={(m) => set('bandwidth')({ guaranteed: { ...bw.guaranteed, min: m } })} />
          <Rate label="Limit (max)" value={bw.guaranteed?.max} onChange={(m) => set('bandwidth')({ guaranteed: { ...bw.guaranteed, max: m } })} />
        </> : <Rate label="Limit" value={bw.bestEffort} onChange={(m) => set('bandwidth')({ bestEffort: m })} />}
        {asList(data.scheduledOverrides).length > 0 && <div className="muted small">
          Zeitplan-Ausnahmen: {asList(data.scheduledOverrides).map((o) => `${refName(o.schedule)} (${kbps(o.bandwidth)})`).join(', ')} – im JSON-Modus bearbeiten.</div>}
      </Section>
    </div>
  )
}

export const NEW_POLICY = {
  webPolicies: { name: '', description: '', defaultAction: 'allow', maxFileSize: 300, enforceSafeSearch: false, youtubeFilter: 'off', rules: [] },
  applicationPolicies: { name: '', description: '', rules: [] },
  ipsPolicies: { name: '', description: '', rules: [] },
  trafficShapingPolicies: { name: '', description: '', associatesWith: 'rules', isShared: true, type: 'bestEffort', bandwidth: { bestEffort: { aggregatedKbps: 1024 } } },
}

export function policyForm(entity, props) {
  if (entity === 'webPolicies') return <WebPolicyForm {...props} />
  if (entity === 'applicationPolicies' || entity === 'ipsPolicies') return <RulePolicyForm entity={entity} {...props} />
  if (entity === 'trafficShapingPolicies') return <TrafficShapingForm {...props} />
  return null
}

// --- Leseansicht (Detail-Dialog) ----------------------------------------------------------------------------

function Line({ label, children }) {
  return <div className="sf-line"><span>{label}</span><div>{children}</div></div>
}

/** Strukturierte Leseansicht für Objekte mit verschachteltem Aufbau; null = nur JSON anzeigen */
export function ObjectView({ entity, obj }) {
  if (entity === 'webPolicies') return (
    <div className="stack">
      <div className="sf-details">
        <div><Line label="Standardaktion"><ActionBadge value={obj.defaultAction} labels={WEB_ACTION} /></Line>
          <Line label="Max. Dateigröße">{obj.maxFileSize ? `${obj.maxFileSize} MB` : '–'}</Line></div>
        <div><Line label="SafeSearch">{obj.enforceSafeSearch ? 'an' : 'aus'}</Line>
          <Line label="YouTube">{{ off: 'aus', moderate: 'moderat', strict: 'streng' }[obj.youtubeFilter] || obj.youtubeFilter || 'aus'}</Line></div>
      </div>
      <PolicyRules entity={entity} rules={asList(obj.rules)} />
    </div>
  )
  if (entity === 'applicationPolicies' || entity === 'ipsPolicies') return <PolicyRules entity={entity} rules={asList(obj.rules)} />
  if (entity === 'trafficShapingPolicies') return (
    <div className="sf-details">
      <div><Line label="Gilt für">{obj.associatesWith}</Line><Line label="Zuweisung">{obj.isShared ? 'geteilt' : 'pro Ziel'}</Line></div>
      <div><Line label="Typ">{obj.type === 'guaranteed' ? 'garantiert' : 'Best Effort'}</Line><Line label="Bandbreite">{kbps(obj.bandwidth)}</Line></div>
    </div>
  )
  if (entity === 'userGroups') return (
    <div className="sf-details"><div><Line label="Typ">{obj.type || '–'}</Line>
      <Line label="Richtlinien">{[refName(obj.surfingQuota), refName(obj.accessTime), refName(obj.networkTraffic), refName(obj.trafficShapingPolicy)].filter(Boolean).join(', ') || '–'}</Line></div></div>
  )
  return null
}
