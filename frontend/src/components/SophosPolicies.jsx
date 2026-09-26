import { asList } from './entities'
import { Box, Section, Toggle } from './SophosRules'
import { Field, Seg } from './ui'
import { t } from '../i18n'

/**
 * Richtlinien im Aufbau der SFOS-Weboberfläche: Web-, Anwendungs-, IPS- und Traffic-Shaping-Richtlinien.
 * Einstellungen und Regel-Aktionen sind per Formular editierbar; neue Richtlinien-Regeln (Kategorien,
 * Signatur-Filter …) legt man über den JSON-Expertenmodus an.
 */

const refName = (v) => (v && typeof v === 'object' ? v.name : '') || ''
const refNames = (items) => asList(items).map((i) => i?.name ?? i).filter(Boolean)

export const WEB_ACTION = { allow: t("Zulassen"), deny: t("Blockieren"), warn: t("Warnen"), log: t("Protokollieren"), quota: t("Kontingent") }
export const APP_ACTION = { allow: t("Zulassen"), deny: t("Blockieren") }
export const IPS_ACTION = {
  recommended: t("Empfohlen"), allowPacket: t("Paket zulassen"), dropPacket: t("Paket verwerfen"), disable: t("Deaktivieren"),
  dropSession: t("Sitzung verwerfen"), reset: t("Zurücksetzen"), bypassSession: t("Sitzung umgehen"),
}
const ACTIVITY_KEYS = [['categories', t("Kategorien")], ['urlGroups', 'URL-Gruppen'], ['fileTypes', t("Dateitypen")],
  ['dynamicCategories', t("Dynamische Kategorien")], ['userActivities', t("Benutzeraktivitäten")]]

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

const who = (u) => (!u || u.any ? t("Alle") : [...refNames(u.users), ...refNames(u.userGroups)].join(', ') || t("Alle"))
const activities = (a) => ACTIVITY_KEYS.flatMap(([k]) => refNames(a?.[k])).join(', ') || '–'
const filterText = (rows) => asList(rows).map((f) => `${f.attribute}: ${asList(f.values).join(', ')}`).join(' · ')
const appWhat = (r) => (r.selectionMode === 'applicationFilter' ? filterText(r.applicationFilters) || t("Filter")
  : r.selectionMode === 'smartFilter' ? t("Smart-Filter: {0}", filterText(r.applicationFilters)) : refNames(r.applicationList).join(', ') || '–')
const ipsWhat = (r) => (r.selectionMode === 'signatureList' ? refNames(r.signatureList).join(', ') || '–' : filterText(r.signatureFilters) || t("Alle Signaturen"))
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
  if (!rules.length) return <div className="muted small">{t("Keine Regeln – es gilt die Standardaktion.")}</div>
  const web = entity === 'webPolicies'
  const labels = web ? WEB_ACTION : entity === 'ipsPolicies' ? IPS_ACTION : APP_ACTION
  return (
    <div className="table-wrap">
      <table className="cs-grid sf-policy">
        <thead><tr>
          <th style={{ width: 30 }}>#</th>
          {web ? <><th>{t("Benutzer")}</th><th>{t("Aktivitäten")}</th><th>HTTP</th><th>HTTPS</th><th>{t("Zeitplan")}</th><th>{t("Aktiv")}</th></>
            : <><th>{t("Name")}</th><th>{entity === 'ipsPolicies' ? t("Signaturen") : t("Anwendungen")}</th><th>{t("Aktion")}</th>{entity === 'applicationPolicies' && <th>{t("Zeitplan")}</th>}</>}
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
                <td>{r.followHttpAction ? <span className="muted small">{t("wie HTTP")}</span>
                  : edit ? <ActionSelect value={r.httpsAction} labels={WEB_ACTION} onChange={(v) => upd(i, { httpsAction: v })} /> : <ActionBadge value={r.httpsAction} labels={WEB_ACTION} />}</td>
                <td className="small">{refName(r.schedule) || t("Immer")}</td>
                <td>{edit ? <Toggle checked={r.enabled !== false} onChange={(v) => upd(i, { enabled: v })} label="" /> : r.enabled === false ? t("nein") : t("ja")}</td>
              </> : <>
                <td className="small"><b>{r.name}</b></td>
                <td className="small">{entity === 'ipsPolicies' ? ipsWhat(r) : appWhat(r)}</td>
                <td>{edit ? <ActionSelect value={r.action} labels={labels} onChange={(v) => upd(i, { action: v })} /> : <ActionBadge value={r.action} labels={labels} />}</td>
                {entity === 'applicationPolicies' && <td className="small">{refName(r.schedule) || t("Immer")}</td>}
              </>}
              {edit && <td className="actions nowrap">
                <button className="ghost sm" disabled={i === 0} onClick={() => move(i, -1)} title={t("Nach oben")}>↑</button>
                <button className="ghost sm" disabled={i === rules.length - 1} onClick={() => move(i, 1)} title={t("Nach unten")}>↓</button>
                <button className="ghost sm" onClick={() => setRules(rules.filter((_, j) => j !== i))} title={t("Regel entfernen")}>×</button>
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
      <Field label={t("Name")}><input value={data.name || ''} disabled={!isNew} onChange={(e) => setData({ ...data, name: e.target.value })} /></Field>
      <Field label={t("Beschreibung")}><input value={data.description || ''} onChange={(e) => setData({ ...data, description: e.target.value })} /></Field>
    </div>
  )
}

const RULE_HINT = <div className="muted small" style={{ marginTop: 6 }}>{t("Neue Regeln (Kategorien, Filter, Signaturen) im JSON-Expertenmodus ergänzen.")}</div>

export function WebPolicyForm({ data, setData, isNew }) {
  const set = (k) => (v) => setData({ ...data, [k]: v })
  return (
    <div className="sf-form">
      <Section title={t("Allgemein")}><NameDesc data={data} setData={setData} isNew={isNew} />
        <div className="form-grid">
          <Box label={t("Standardaktion (wenn keine Regel greift)")}><Seg options={[['allow', t("Zulassen")], ['deny', t("Blockieren")]]} value={data.defaultAction} onChange={set('defaultAction')} /></Box>
          <Field label={t("Max. Dateigröße (MB)")}><input type="number" min={1} value={data.maxFileSize ?? ''} onChange={(e) => set('maxFileSize')(Number(e.target.value))} /></Field>
        </div>
      </Section>
      <Section title={t("Regeln ({0})", asList(data.rules).length)}>
        <PolicyRules entity="webPolicies" rules={asList(data.rules)} setRules={set('rules')} />{RULE_HINT}
      </Section>
      <Section title={t("Erweitert")} collapsible open={false}>
        <div className="sf-toggles">
          <Toggle checked={data.enforceSafeSearch} onChange={set('enforceSafeSearch')} label={t("SafeSearch erzwingen")} />
          <Toggle checked={data.restrictFileSize} onChange={set('restrictFileSize')} label={t("Download-Größe begrenzen")} />
          <Toggle checked={data.filterByImageLicense} onChange={set('filterByImageLicense')} label={t("Bildlizenz-Filter (Creative Commons)")} />
          <Toggle checked={data.reporting} onChange={set('reporting')} label={t("Reporting")} />
          <Toggle checked={data.propagateXForwardedFor} onChange={set('propagateXForwardedFor')} label={t("X-Forwarded-For weitergeben")} />
          <Toggle checked={data.restrictGoogleAppDomains} onChange={set('restrictGoogleAppDomains')} label={t("Google-App-Domains einschränken")} />
          <Toggle checked={data.restrictOffice365Tenants} onChange={set('restrictOffice365Tenants')} label={t("Microsoft-365-Tenants einschränken")} />
        </div>
        <div className="form-grid">
          <Box label="YouTube-Filter"><Seg options={[['off', t("Aus")], ['moderate', t("Moderat")], ['strict', t("Streng")]]} value={data.youtubeFilter || 'off'} onChange={set('youtubeFilter')} /></Box>
          <Field label={t("Kontingent (Minuten)")}><input type="number" min={0} value={data.quotaLimit ?? ''} onChange={(e) => set('quotaLimit')(Number(e.target.value))} /></Field>
          {data.restrictGoogleAppDomains && <Field label={t("Erlaubte Google-Domains (kommagetrennt)")}>
            <input value={asList(data.googleAppDomainFilter).join(', ')} onChange={(e) => set('googleAppDomainFilter')(e.target.value.split(',').map((x) => x.trim()).filter(Boolean))} /></Field>}
          {data.restrictOffice365Tenants && <Field label={t("Erlaubte M365-Tenants (kommagetrennt)")}>
            <input value={asList(data.office365FilterTenants).join(', ')} onChange={(e) => set('office365FilterTenants')(e.target.value.split(',').map((x) => x.trim()).filter(Boolean))} /></Field>}
        </div>
      </Section>
    </div>
  )
}

export function RulePolicyForm({ entity, data, setData, isNew }) {
  return (
    <div className="sf-form">
      <Section title={t("Allgemein")}><NameDesc data={data} setData={setData} isNew={isNew} /></Section>
      <Section title={t("Regeln ({0})", asList(data.rules).length)}>
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
    <Box label={label} hint={t("kbps, Vielfaches von 8")}>
      <div className="row">
        <Seg options={[['agg', t("Gesamt")], ['split', '↑/↓ getrennt']]} value={split ? 'split' : 'agg'}
          onChange={(m) => onChange(m === 'agg' ? { aggregatedKbps: v.uploadKbps || 1024 } : { uploadKbps: v.aggregatedKbps || 1024, downloadKbps: v.aggregatedKbps || 1024 })} />
        {split ? <>
          <input type="number" step={8} value={v.uploadKbps ?? ''} onChange={num('uploadKbps')} placeholder={t("Upload")} style={{ width: 110 }} />
          <input type="number" step={8} value={v.downloadKbps ?? ''} onChange={num('downloadKbps')} placeholder={t("Download")} style={{ width: 110 }} />
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
      <Section title={t("Allgemein")}><NameDesc data={data} setData={setData} isNew={isNew} />
        <div className="form-grid">
          <Box label={t("Gilt für")}><Seg options={[['rules', t("Regeln")], ['users', t("Benutzer")], ['webCategories', t("Web-Kategorien")], ['applications', t("Anwendungen")]]}
            value={data.associatesWith} onChange={set('associatesWith')} /></Box>
          <Box label={t("Zuweisung")}><Seg options={[['true', t("Geteilt")], ['false', t("Pro Ziel")]]} value={String(!!data.isShared)} onChange={(v) => set('isShared')(v === 'true')} /></Box>
        </div>
      </Section>
      <Section title={t("Bandbreite")}>
        <Box label={t("Typ")}><Seg options={[['guaranteed', t("Garantiert + Limit")], ['bestEffort', t("Limit (Best Effort)")]]} value={data.type} onChange={setType} /></Box>
        {data.type === 'guaranteed' ? <>
          <Rate label={t("Garantiert (min)")} value={bw.guaranteed?.min} onChange={(m) => set('bandwidth')({ guaranteed: { ...bw.guaranteed, min: m } })} />
          <Rate label={t("Limit (max)")} value={bw.guaranteed?.max} onChange={(m) => set('bandwidth')({ guaranteed: { ...bw.guaranteed, max: m } })} />
        </> : <Rate label={t("Limit")} value={bw.bestEffort} onChange={(m) => set('bandwidth')({ bestEffort: m })} />}
        {asList(data.scheduledOverrides).length > 0 && <div className="muted small">
          {t("Zeitplan-Ausnahmen:")} {asList(data.scheduledOverrides).map((o) => `${refName(o.schedule)} (${kbps(o.bandwidth)})`).join(', ')} {t("– im JSON-Modus bearbeiten.")}</div>}
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
        <div><Line label={t("Standardaktion")}><ActionBadge value={obj.defaultAction} labels={WEB_ACTION} /></Line>
          <Line label={t("Max. Dateigröße")}>{obj.maxFileSize ? `${obj.maxFileSize} MB` : '–'}</Line></div>
        <div><Line label="SafeSearch">{obj.enforceSafeSearch ? 'an' : t("aus")}</Line>
          <Line label="YouTube">{{ off: t("aus"), moderate: t("moderat"), strict: t("streng") }[obj.youtubeFilter] || obj.youtubeFilter || t("aus")}</Line></div>
      </div>
      <PolicyRules entity={entity} rules={asList(obj.rules)} />
    </div>
  )
  if (entity === 'applicationPolicies' || entity === 'ipsPolicies') return <PolicyRules entity={entity} rules={asList(obj.rules)} />
  if (entity === 'trafficShapingPolicies') return (
    <div className="sf-details">
      <div><Line label={t("Gilt für")}>{obj.associatesWith}</Line><Line label={t("Zuweisung")}>{obj.isShared ? t("geteilt") : t("pro Ziel")}</Line></div>
      <div><Line label={t("Typ")}>{obj.type === 'guaranteed' ? t("garantiert") : t("Best Effort")}</Line><Line label={t("Bandbreite")}>{kbps(obj.bandwidth)}</Line></div>
    </div>
  )
  if (entity === 'userGroups') return (
    <div className="sf-details"><div><Line label={t("Typ")}>{obj.type || '–'}</Line>
      <Line label={t("Richtlinien")}>{[refName(obj.surfingQuota), refName(obj.accessTime), refName(obj.networkTraffic), refName(obj.trafficShapingPolicy)].filter(Boolean).join(', ') || '–'}</Line></div></div>
  )
  return null
}
