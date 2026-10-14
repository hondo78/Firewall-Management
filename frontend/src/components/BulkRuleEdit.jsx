import { useMemo, useState } from 'react'
import { api } from '../api'
import { canonical, oname, restRefOptions } from './entities'
import { ErrorBox, Modal } from './ui'
import { t } from '../i18n'

// Mehrfachbearbeitung von Firewall-Regeln wie im Config Studio: je Feld „unverändert“ oder ein neuer Wert für alle
// ausgewählten Regeln. Ergebnis landet im Entwurf (Vier-Augen-Freigabe wie immer).

const KEEP = ''
const NONE = '\u0000none'   // „Keine“ Richtlinie bzw. „Jederzeit“
const OTHER = '\u0000other'

// Sicherheitsfunktionen gelten nur für Regeln mit Aktion „Annehmen“
const SECURITY = new Set(['ips', 'app', 'web', 'av', 'zeroday', 'ndr'])

const FIELDS = [
  { key: 'enabled', label: t("Status"), type: 'onoff', on: t("Eingeschaltet"), off: t("Ausgeschaltet") },
  { key: 'action', label: t("Aktion"), type: 'action' },
  { key: 'log', label: t("Firewallverkehr protokollieren"), type: 'onoff' },
  { key: 'schedule', label: t("Zeitplan"), type: 'policy', none: t("Jederzeit"), opt: 'schedules' },
  { key: 'ips', label: t("IPS (Angriffsvorbeugung)"), type: 'policy', none: t("Keine"), opt: 'ipsPolicies' },
  { key: 'app', label: t("Anwendungskontrolle"), type: 'policy', none: t("Keine"), opt: 'appPolicies' },
  { key: 'web', label: t("Internetrichtlinie (Webfilter)"), type: 'policy', none: t("Keine"), opt: 'webPolicies' },
  { key: 'ts', label: t("Traffic-Shaping"), type: 'policy', none: t("Keine"), opt: 'tsPolicies' },
  { key: 'av', label: t("Malware-Scan (HTTP/HTTPS und FTP)"), type: 'onoff' },
  { key: 'zeroday', label: t("Zero-Day-Schutz"), type: 'onoff' },
  { key: 'ndr', label: t("Mit NDR Active Threat Intelligence scannen"), type: 'onoff' },
]

// --- Werte setzen je Format ----------------------------------------------------------------------------------

const ref = (v) => (v === NONE ? null : { name: v })

export function patchRest(obj, ch) {
  const r = structuredClone(obj)
  const waf = r.ruleType === 'waf'
  // WAF-Regeln (REST) kennen nur Status, IPS, Traffic-Shaping und NDR
  const allowed = waf ? new Set(['enabled', 'ips', 'ts', 'ndr']) : null
  const ignored = []
  const sec = { ...(r.securityFeatures || {}) }
  const action = ch.action || r.action
  // „Keine“ bei einem Feld, das es noch gar nicht gibt, ist keine Änderung
  const current = { schedule: r.schedule, ips: sec.ipsPolicy, app: sec.applicationPolicy, web: sec.webPolicy,
    ts: r.qos?.trafficShapingPolicy }
  for (const [k, v] of Object.entries(ch)) {
    if (allowed && !allowed.has(k)) { ignored.push(k); continue }
    if (!waf && SECURITY.has(k) && action !== 'accept') { ignored.push(k); continue }
    if (v === NONE && k in current && !current[k]) continue
    if (k === 'enabled') r.enabled = v === 'on'
    else if (k === 'action') r.action = v
    else if (k === 'log') r.logTraffic = v === 'on'
    else if (k === 'schedule') r.schedule = ref(v)
    else if (k === 'ips') sec.ipsPolicy = ref(v)
    else if (k === 'app') sec.applicationPolicy = ref(v)
    else if (k === 'web') sec.webPolicy = ref(v)
    else if (k === 'av') { sec.scanHttpAndDecryptedHttps = v === 'on'; sec.scanFtp = v === 'on' }
    else if (k === 'zeroday') sec.zeroDayProtection = v === 'on'
    else if (k === 'ndr') sec.scanWithNdrActiveThreatIntelligence = v === 'on'
    else if (k === 'ts') r.qos = { ...(r.qos || {}), trafficShapingPolicy: ref(v) }
  }
  if (Object.keys(sec).length || r.securityFeatures) r.securityFeatures = sec
  return { data: r, ignored }
}

const XML_ACTION = { accept: 'Accept', drop: 'Drop', reject: 'Reject' }
const onOff = (v) => (v === 'on' ? 'Enable' : 'Disable')

export function patchXml(obj, ch) {
  const r = structuredClone(obj)
  const polKey = r.NetworkPolicy ? 'NetworkPolicy' : r.UserPolicy ? 'UserPolicy' : null
  const ignored = []
  if (!polKey) {   // WAF (HTTPBased) u. Ä.: nur der Status
    for (const [k, v] of Object.entries(ch)) {
      if (k === 'enabled') r.Status = onOff(v)
      else ignored.push(k)
    }
    return { data: r, ignored }
  }
  const p = { ...r[polKey] }
  const action = ch.action ? XML_ACTION[ch.action] : p.Action
  const pol = (v) => (v === NONE ? 'None' : v)
  for (const [k, v] of Object.entries(ch)) {
    if (SECURITY.has(k) && action !== 'Accept') { ignored.push(k); continue }
    if (k === 'enabled') r.Status = onOff(v)
    else if (k === 'action') p.Action = XML_ACTION[v]
    else if (k === 'log') p.LogTraffic = onOff(v)
    else if (k === 'schedule') p.Schedule = v === NONE ? 'All The Time' : v
    else if (k === 'ips') p.IntrusionPrevention = pol(v)
    else if (k === 'app') p.ApplicationControl = pol(v)
    else if (k === 'web') p.WebFilter = pol(v)
    else if (k === 'ts') p.TrafficShappingPolicy = pol(v)
    else if (k === 'av') { p.ScanVirus = onOff(v); p.ScanFTP = onOff(v) }
    else if (k === 'zeroday') p.ZeroDayProtection = onOff(v)
    else if (k === 'ndr') p.NDRActiveThreatIntelligence = onOff(v)
  }
  r[polKey] = p
  return { data: r, ignored }
}

// XML-Firewalls: Richtlinien sind nicht im Cache – Auswahl aus den Werten, die Regeln bereits verwenden (+ Freitext)
function xmlOptions(config) {
  const used = (field) => [...new Set((config.FirewallRule || []).map((r) => (r.NetworkPolicy || r.UserPolicy || {})[field])
    .filter((v) => v && v !== 'None'))].sort()
  return {
    schedules: (config.Schedule || []).map((s) => s.Name).filter((n) => n !== 'All The Time'),
    ipsPolicies: used('IntrusionPrevention'), appPolicies: used('ApplicationControl'),
    webPolicies: used('WebFilter'), tsPolicies: used('TrafficShappingPolicy'),
  }
}

export default function BulkRuleEdit({ fw, entity, rules, config, rest, onClose, onDone }) {
  const [ch, setCh] = useState({})
  const [custom, setCustom] = useState(new Set())
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const opts = useMemo(() => (rest ? restRefOptions(config) : xmlOptions(config)), [config, rest])
  const set = (k, v) => setCh((c) => { const n = { ...c }; if (v === KEEP) delete n[k]; else n[k] = v; return n })

  // Vorschau: was sich je Regel ändert
  const plan = useMemo(() => rules.map((obj) => {
    const { data, ignored } = (rest ? patchRest : patchXml)(obj, ch)
    return { obj, data, ignored, changed: canonical(data) !== canonical(obj) }
  }), [rules, ch, rest])
  const changed = plan.filter((p) => p.changed)
  const partly = plan.filter((p) => p.ignored.length)
  const nothing = !Object.keys(ch).length

  const apply = async () => {
    setBusy(true)
    setError('')
    try {
      const r = await api(`/firewalls/${fw.id}/draft/operations/bulk`, { method: 'POST',
        body: { operations: changed.map((p) => ({ entity, action: 'update', name: oname(p.obj), data: p.data })) } })
      onDone(r)
    } catch (e) { setError(e.message) }
    setBusy(false)
  }

  const control = (f) => {
    const v = ch[f.key] ?? KEEP
    if (f.type === 'onoff') {
      return <select value={v} onChange={(e) => set(f.key, e.target.value)}>
        <option value={KEEP}>{t("– unverändert –")}</option>
        <option value="on">{f.on || t("An")}</option><option value="off">{f.off || t("Aus")}</option></select>
    }
    if (f.type === 'action') {
      return <select value={v} onChange={(e) => set(f.key, e.target.value)}>
        <option value={KEEP}>{t("– unverändert –")}</option>
        <option value="accept">{t("Annehmen")}</option><option value="drop">{t("Verwerfen")}</option><option value="reject">{t("Ablehnen")}</option></select>
    }
    const list = opts[f.opt] || []
    // XML: Richtlinien liegen nicht im Cache – bekannte Namen plus „Andere …“ mit Eingabe
    if (!rest && f.key !== 'schedule') {
      const isCustom = custom.has(f.key)
      return <div className="row" style={{ gap: 6 }}>
        <select value={isCustom ? OTHER : v} onChange={(e) => {
          const nc = new Set(custom)
          if (e.target.value === OTHER) { nc.add(f.key); set(f.key, KEEP) } else { nc.delete(f.key); set(f.key, e.target.value) }
          setCustom(nc)
        }}>
          <option value={KEEP}>{t("– unverändert –")}</option><option value={NONE}>{f.none}</option>
          {list.map((n) => <option key={n} value={n}>{n}</option>)}
          <option value={OTHER}>{t("Andere …")}</option></select>
        {isCustom && <input value={v === KEEP ? '' : v} placeholder={t("Name der Richtlinie")} onChange={(e) => set(f.key, e.target.value.trim() ? e.target.value : KEEP)} />}
      </div>
    }
    return <select value={v} onChange={(e) => set(f.key, e.target.value)}>
      <option value={KEEP}>{t("– unverändert –")}</option><option value={NONE}>{f.none}</option>
      {list.map((n) => <option key={n} value={n}>{n}</option>)}</select>
  }

  return (
    <Modal title={t("{0} Regeln bearbeiten", rules.length)} onClose={onClose} wide>
      <div className="stack">
        <div className="muted small">{t("Felder auf „unverändert“ bleiben je Regel wie sie sind. Die Änderungen landen in Ihrem Entwurf und werden erst nach Freigabe ausgerollt.")}</div>
        <div className="form-grid">
          {FIELDS.map((f) => (
            <label key={f.key} className="field"><span>{f.label}{SECURITY.has(f.key) && <span className="muted small"> · {t("nur bei „Annehmen“")}</span>}</span>{control(f)}</label>
          ))}
        </div>
        {!nothing && <div className={`alert ${changed.length ? 'info' : 'warn'} small`}>
          {t("{0} von {1} Regeln werden geändert", changed.length, rules.length)}
          {rules.length - changed.length > 0 && t(" · {0} sind bereits so", rules.length - changed.length)}
          {partly.length > 0 && <div style={{ marginTop: 4 }}>{t("Teilweise nicht anwendbar (Aktion ist nicht „Annehmen“ bzw. WAF-Regel): {0}", partly.slice(0, 8).map((p) => oname(p.obj)).join(', ') + (partly.length > 8 ? ' …' : ''))}</div>}
        </div>}
        <ErrorBox error={error} />
      </div>
      <div className="modal-foot">
        <button onClick={onClose}>{t("Abbrechen")}</button>
        <button className="primary" disabled={busy || !changed.length} onClick={apply}>
          {busy ? t("Übernehme …") : t("{0} Regeln in den Entwurf", changed.length)}</button>
      </div>
    </Modal>
  )
}
