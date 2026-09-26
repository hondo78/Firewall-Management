import { useEffect, useMemo, useRef, useState } from 'react'
import { EditorShell, PositionField } from './Editors'
import { asList, restNetNames, restRefOptions } from './entities'
import { Field } from './ui'

/**
 * Regel-Editoren und -Ansichten im Aufbau der Sophos-Firewall-Weboberfläche (SFOS):
 * Firewall-Regel (IPv4/IPv6) mit Quelle, Ziel & Diensten, Ausnahmen, Benutzern und Sicherheitsfunktionen,
 * NAT-Regel mit Original/Übersetzt und Schnittstellen. JSON bleibt als Experten-Option im EditorShell.
 */

const refNames = (items) => asList(items).map((i) => i?.name).filter(Boolean)
const toRefs = (names) => names.map((name) => ({ name }))
const refName = (v) => (v && typeof v === 'object' ? v.name : '') || ''

export const DSCP = ['0-Best Effort', '8-Class 1(CS1)', '10-Class 1,Gold(AF11)', '12-Class1,Silver(AF12)', '14-Class 1,Bronze(AF13)',
  '16-Class 2(CS2)', '18-Class 2,Gold(AF21)', '20-Class 2,Silver(AF22)', '22-Class 2,Bronze(AF23)', '24-Class 3(CS3)',
  '26-Class 3,Gold(AF31)', '28-Class 3,Silver(AF32)', '30-Class 3,Bronze(AF33)', '32-Class 4(CS4)', '34-Class 4,Gold(AF41)',
  '36-Class 4,Silver(AF42)', '38-Class 4,Bronze(AF43)', '40-Class 5(CS5)', '46-Expedited Forwarding(EF)', '48-Class 6(CS6)', '56-Class 7(CS7)']
const HB = [['noRestriction', 'Keine Einschränkung'], ['green', 'Grün'], ['yellow', 'Gelb']]

/** Feld ohne <label>-Hülle (für Schalter, Auswahllisten, Segmente – vermeidet verschachtelte Labels) */
export function Box({ label, hint, children }) {
  return <div className="field"><span>{label}</span>{children}{hint && <small>{hint}</small>}</div>
}

/** Schalter wie in SFOS (An/Aus) */
export function Toggle({ checked, onChange, label, hint }) {
  return (
    <label className="sf-toggle">
      <input type="checkbox" checked={!!checked} onChange={(e) => onChange(e.target.checked)} />
      <span className="track" aria-hidden="true"><span className="thumb" /></span>
      <span>{label}{hint && <small className="muted"> – {hint}</small>}</span>
    </label>
  )
}

/** Abschnitt mit grauem Kopf wie in SFOS; optional einklappbar */
export function Section({ title, children, open: initial = true, extra, collapsible }) {
  const [open, setOpen] = useState(initial)
  return (
    <section className="sf-section">
      <header onClick={collapsible ? () => setOpen(!open) : undefined} className={collapsible ? 'clickable' : ''}>
        <h4>{title}</h4>{extra}{collapsible && <span className="muted small">{open ? '▾' : '▸'}</span>}
      </header>
      {open && <div className="sf-body">{children}</div>}
    </section>
  )
}

// Netz-/Dienst-Mengen ⇄ API-Strukturen -------------------------------------------------------------------------

function zonesValue(names) { return names.length ? { zones: toRefs(names) } : { any: true } }

function keyed(names, options, fallback) {
  const keyOf = Object.fromEntries(options.map((o) => [o.value, o.key]))
  const out = {}
  for (const n of names) (out[keyOf[n] || fallback] ||= []).push({ name: n })
  return out
}
const netsValue = (names, options, fb) => (names.length ? keyed(names, options, fb) : { any: true })
const svcValue = (names, options) => (names.length ? keyed(names, options, 'services') : { any: true })
const svcNames = (v) => (v?.any ? [] : [...refNames(v?.services), ...refNames(v?.serviceGroups)])

// --- Firewall-Regel ------------------------------------------------------------------------------------------

function newRule(opts) {
  const find = (want) => opts.zones.find((z) => z.value.toLowerCase() === want)?.value
  const lan = find('lan')
  const wan = find('wan')
  return {
    name: '', description: '', ruleType: 'firewall', enabled: true, action: 'accept', logTraffic: true,
    sourceZones: lan ? { zones: [{ name: lan }] } : { any: true },
    destinationZones: wan ? { zones: [{ name: wan }] } : { any: true },
    sourceNetworks: { any: true }, destinationNetworks: { any: true }, servicesOrGroups: { any: true },
  }
}

// --- Bausteine im SFOS-Stil ----------------------------------------------------------------------------------

/** Auswahlliste wie in SFOS: gewählte Einträge mit ⊖, darunter „Neues Element hinzufügen …“ mit Suche */
export function SfList({ value, options, onChange, emptyLabel = 'Beliebig', label }) {
  const [open, setOpen] = useState(false)
  const [q, setQ] = useState('')
  const ref = useRef(null)
  const [up, setUp] = useState(false)
  useEffect(() => {
    if (!open) return undefined
    const onDoc = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false) }
    document.addEventListener('mousedown', onDoc)
    return () => document.removeEventListener('mousedown', onDoc)
  }, [open])
  const selected = new Set(value)
  const f = q.toLowerCase()
  const shown = options.filter((o) => !selected.has(o.value) && o.value.toLowerCase().includes(f)).slice(0, 150)
  return (
    <div className="sf-list" ref={ref}>
      <div className="sf-list-items">
        {!value.length && <div className="sf-list-item any"><span>{emptyLabel}</span></div>}
        {value.map((v) => (
          <div key={v} className="sf-list-item">
            <span>{v}</span>
            <button type="button" className="sf-remove" title="Entfernen" aria-label={`${v} entfernen`}
              onClick={() => onChange(value.filter((x) => x !== v))}>−</button>
          </div>
        ))}
      </div>
      <button type="button" className="sf-list-add" onClick={() => {
        // Unten zu wenig Platz (fester Speichern-Fuß) → Liste nach oben aufklappen
        setUp(window.innerHeight - ref.current.getBoundingClientRect().bottom < 420)
        setOpen(!open); setQ('')
      }} aria-expanded={open}
        aria-label={`${label || ''} – neues Element hinzufügen`}>Neues Element hinzufügen …</button>
      {open && (
        <div className={`sf-list-pop ${up ? 'up' : ''}`} onKeyDown={(e) => { if (e.key === 'Escape') { e.stopPropagation(); setOpen(false) } }}>
          <input autoFocus placeholder="Suchen …" value={q} onChange={(e) => setQ(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter' && shown[0]) { e.preventDefault(); onChange([...value, shown[0].value]); setQ('') } }} />
          <div className="sf-list-options">
            {!shown.length && <div className="muted small" style={{ padding: 8 }}>Keine weiteren Einträge.</div>}
            {shown.map((o) => (
              <button type="button" key={`${o.kind}:${o.value}`} onClick={() => onChange([...value, o.value])}>
                <span>{o.value}</span>{o.kind && <span className="kind">{o.kind}</span>}
              </button>
            ))}
          </div>
          <div className="sf-list-pop-foot"><button type="button" className="sm" onClick={() => setOpen(false)}>Fertig</button></div>
        </div>
      )}
    </div>
  )
}

/** Checkbox mit Hilfetext darunter (SFOS-Formulare verwenden Checkboxen statt Schalter) */
export function Check({ checked, onChange, label, hint, disabled }) {
  return (
    <label className={`sf-check ${disabled ? 'disabled' : ''}`}>
      <input type="checkbox" checked={!!checked} disabled={disabled} onChange={(e) => onChange(e.target.checked)} />
      <span>{label}{hint && <small>{hint}</small>}</span>
    </label>
  )
}

/** Aufklappbarer Bereich mit Pfeil („› Ausschluss hinzufügen“) */
export function Fold({ title, open: initial, children, badge }) {
  const [open, setOpen] = useState(!!initial)
  return (
    <div className="sf-fold">
      <button type="button" className={`sf-fold-head ${open ? 'open' : ''}`} onClick={() => setOpen(!open)} aria-expanded={open}>
        <span className="chev" aria-hidden="true">›</span>{title}{badge}
      </button>
      {open && <div className="sf-fold-body">{children}</div>}
    </div>
  )
}

export function Heading({ title, desc }) {
  return <div className="sf-heading"><h3>{title}</h3>{desc && <p>{desc}</p>}</div>
}

export function Label({ children, required }) {
  return <div className="sf-label">{children}{required && <span className="req"> *</span>}</div>
}

export function Select({ value, onChange, options, none, disabled }) {
  return (
    <select value={value || ''} disabled={disabled} onChange={(e) => onChange(e.target.value)}>
      {none !== undefined && <option value="">{none}</option>}
      {options.map((o) => (Array.isArray(o) ? <option key={o[0]} value={o[0]}>{o[1]}</option> : <option key={o}>{o}</option>))}
      {value && !options.some((o) => (Array.isArray(o) ? o[0] : o) === value) && <option>{value}</option>}
    </select>
  )
}

export function PositionSelect({ position, setPosition, rules, name, isNew }) {
  const others = rules.filter((r) => r !== name)
  return (
    <div className="stack" style={{ gap: 6 }}>
      <Select value={position.type} onChange={(t) => setPosition({ type: t, ref: position.ref || others[0] })}
        options={[...(isNew ? [] : [['keep', 'Unverändert']]), ['top', 'Ganz oben'], ['bottom', 'Ganz unten'], ['after', 'Nach Regel …'], ['before', 'Vor Regel …']]} />
      {['after', 'before'].includes(position.type) && <Select value={position.ref} onChange={(r) => setPosition({ ...position, ref: r })} options={others} />}
    </div>
  )
}

const ACTIONS = [['accept', 'Annehmen'], ['drop', 'Verwerfen'], ['reject', 'Ablehnen']]

export function SophosRuleEditor({ entity, config, rule, onClose, onSubmit, page, wafXml, mayConfigure }) {
  const isNew = !rule
  const v6 = entity === 'firewallRulesIpv6'
  const opts = useMemo(() => restRefOptions(config), [config])
  const nets = v6 ? opts.networks6 : opts.networks
  const netFallback = v6 ? 'ipv6Addresses' : 'ipv4Addresses'
  const rules = (config[entity] || []).map((r) => r.name)
  const [d, setD] = useState(() => structuredClone(rule || newRule(opts)))
  const [position, setPosition] = useState(isNew ? { type: 'top' } : { type: 'keep' })
  const set = (patch) => setD((cur) => ({ ...cur, ...patch }))
  const sub = (key, patch) => setD((cur) => ({ ...cur, [key]: { ...(cur[key] || {}), ...patch } }))
  const sec = d.securityFeatures || {}
  const setSec = (patch) => sub('securityFeatures', patch)
  const polRef = (name) => (name ? { name } : null)
  const ex = d.exclusions || {}
  const setEx = (patch) => sub('exclusions', patch)
  const ua = d.userAuthentication
  const accept = d.action === 'accept'
  const isWaf = d.ruleType === 'waf'
  const hasExclusions = Object.values(ex).some((x) => x && Object.values(x).some((l) => asList(l).length))
  const hbOn = ['source', 'destination'].some((k) => d.synchronizedSecurityHeartbeat?.[k]?.minimumLevel && d.synchronizedSecurityHeartbeat[k].minimumLevel !== 'noRestriction')
  const mailOn = Object.values(d.emailScanning || {}).some(Boolean)
  const linkedNat = (config.natRulesIpv4 || []).filter((n) => d.name && refName(n.linkedFirewallRule) === d.name).map((n) => n.name)

  const posField = <div style={{ marginTop: 12, maxWidth: 360 }}><Label>Position in der Regelliste</Label>
    <PositionSelect position={position} setPosition={setPosition} rules={rules} name={d.name} isNew={isNew} /></div>
  const zoneList = (key, label, required) => (
    <div><Label required={required}>{label}</Label>
      <SfList label={label} value={d[key]?.any ? [] : refNames(d[key]?.zones)} options={opts.zones} onChange={(z) => set({ [key]: zonesValue(z) })} /></div>
  )
  const netList = (key, label) => (
    <div><Label required>{label}</Label>
      <SfList label={label} value={restNetNames(d[key])} options={nets} onChange={(n) => set({ [key]: netsValue(n, nets, netFallback) })} /></div>
  )

  const head = <>
      <Toggle checked={d.enabled !== false} onChange={(v) => set({ enabled: v })} label="Regelstatus" />
      <div className="sf-grid3">
        <div><Label required>Regelname</Label>
          <input value={d.name} disabled={!isNew} maxLength={60} autoFocus={isNew} onChange={(e) => set({ name: e.target.value })} aria-label="Regelname" /></div>
        <div className="sf-span2row"><Label>Beschreibung</Label>
          <textarea rows={3} value={d.description || ''} maxLength={255} placeholder="Eingabe Beschreibung" aria-label="Beschreibung"
            onChange={(e) => set({ description: e.target.value })} /></div>
        <div><Label>Position in der Regelliste</Label>
          <PositionSelect position={position} setPosition={setPosition} rules={rules} name={d.name} isNew={isNew} /></div>
        {!isWaf && <div><Label>Maßnahme</Label><Select value={d.action} onChange={(a) => set({ action: a })} options={ACTIONS} /></div>}
      </div>
      {!isWaf && <Check checked={d.logTraffic} onChange={(v) => set({ logTraffic: v })} label="Firewallverkehr protokollieren"
        hint="Protokolliert Verkehr, auf den diese Firewallregel zutrifft, auf dem Gerät (standardmäßig) oder auf dem konfigurierten Syslog-Server." />}

      <hr />
      <Heading title="Quelle" desc={<>Wählen Sie die Quellzonen, Netzwerke und Geräte aus.<br />Die Regel gilt für den Verkehr aus diesen Quellen{isWaf ? '' : ' während des geplanten Zeitraums'}.</>} />
      <div className="sf-grid3">
        {zoneList('sourceZones', 'Quellzonen', true)}
        {netList('sourceNetworks', 'Quellnetzwerke und Geräte')}
        {!isWaf && <div><Label>Im geplanten Zeitraum</Label>
          <Select value={refName(d.schedule)} none="Jederzeit" options={opts.schedules} onChange={(n) => set({ schedule: n ? { name: n } : null })} />
          <small className="sf-hint">Auswählen, um die Regel in einem bestimmten Zeitraum und Wochentag anzuwenden.</small></div>}
      </div>
  </>

  // WAF-Regel (Webserver-Schutz): die REST-API liefert nur den Verweis auf die WAF-Regel – deren Inhalt pflegt die Firewall
  const wafForm = (
    <div className="sf-rule">
      {head}
      <hr />
      <Heading title="Webserver-Schutz" desc="Diese Firewall-Regel veröffentlicht einen Webserver über die Web Application Firewall (WAF)." />
      <div className={`alert ${wafXml ? 'warn' : 'info'} small`}>
        {wafXml ? 'Diese WAF-Regel fehlt in den Daten der XML-API – nach der nächsten Synchronisation erneut öffnen.'
          : <>Gehosteter Server, Domänen, Traffic Routing und Ausnahmen liefert die REST-API nicht. Für die vollständige Bearbeitung
            {mayConfigure ? ' unter Einstellungen › Anbindung einen XML-API-Zugang hinterlegen.' : ' muss ein Superadmin einen XML-API-Zugang hinterlegen.'}</>}
      </div>
      <hr />
      <Heading title="Erweitert" />
      <div className="sf-grid3">
        <div><Label>Angriffsvorbeugung</Label>
          <Select value={refName(sec.ipsPolicy)} none="Keine" options={opts.ipsPolicies} onChange={(n) => setSec({ ipsPolicy: polRef(n) })} /></div>
        <div><Label>Traffic-Shaping</Label>
          <Select value={refName(d.qos?.trafficShapingPolicy)} none="Keine" options={opts.tsPolicies} onChange={(n) => sub('qos', { trafficShapingPolicy: polRef(n) })} /></div>
        <div style={{ alignSelf: 'end' }}><Check checked={sec.scanWithNdrActiveThreatIntelligence} label="Mit NDR Active Threat Intelligence scannen"
          onChange={(v) => setSec({ scanWithNdrActiveThreatIntelligence: v })} /></div>
      </div>
    </div>
  )

  const form = isWaf ? wafForm : (
    <div className="sf-rule">
      {head}

      <hr />
      <Heading title="Ziel und Dienste" desc={<>Wählen Sie die Zielzonen, Netzwerke, Geräte und Dienste aus.<br />Die Regel gilt für den Verkehr zu diesen Zielen.</>} />
      <div className="sf-grid3">
        {zoneList('destinationZones', 'Zielzonen', true)}
        {netList('destinationNetworks', 'Zielnetzwerke')}
        <div><Label required>Dienste</Label>
          <SfList label="Dienste" value={svcNames(d.servicesOrGroups)} options={opts.services} onChange={(n) => set({ servicesOrGroups: svcValue(n, opts.services) })} />
          <small className="sf-hint">Dienste sind Verkehrsarten, die auf einer Kombination von Protokollen und Ports basieren.</small></div>
      </div>

      <hr />
      <Check checked={!!ua} label="Übereinstimmung mit bekannten Benutzern"
        onChange={(on) => set({ userAuthentication: on ? { usersOrGroups: { any: true }, excludeUsersFromAccounting: false, webAuthenticationForUnknownUsers: false } : null })} />
      {ua && <div className="sf-grid3 sf-indent">
        <div><Label>Benutzer oder Gruppen</Label>
          <SfList label="Benutzer oder Gruppen" emptyLabel="Alle bekannten Benutzer"
            value={ua.usersOrGroups?.any ? [] : [...refNames(ua.usersOrGroups?.users), ...refNames(ua.usersOrGroups?.userGroups)]}
            options={opts.usersAndGroups} onChange={(n) => sub('userAuthentication', { usersOrGroups: n.length ? keyed(n, opts.usersAndGroups, 'userGroups') : { any: true } })} /></div>
        <div className="stack">
          <Check checked={ua.excludeUsersFromAccounting} label="Diese Benutzeraktivität von der Datenerfassung ausnehmen" onChange={(v) => sub('userAuthentication', { excludeUsersFromAccounting: v })} />
          <Check checked={ua.webAuthenticationForUnknownUsers} label="Web-Authentifizierung für unbekannte Benutzer verwenden" onChange={(v) => sub('userAuthentication', { webAuthenticationForUnknownUsers: v })} />
        </div>
      </div>}

      <hr />
      <Fold title="Ausschluss hinzufügen" open={hasExclusions} badge={hasExclusions && <span className="badge b-warn" style={{ marginLeft: 8 }}>aktiv</span>}>
        <p className="sf-hint" style={{ marginTop: 0 }}>Verkehr, der auf einen Ausschluss passt, ist von dieser Regel ausgenommen.</p>
        <div className="sf-grid3">
          <div className="stack">
            <div><Label>Quellzonen</Label><SfList label="Ausschluss Quellzonen" emptyLabel="Keine" value={refNames(ex.sourceZones?.zones)} options={opts.zones} onChange={(z) => setEx({ sourceZones: { zones: toRefs(z) } })} /></div>
            <div><Label>Quellnetzwerke</Label><SfList label="Ausschluss Quellnetzwerke" emptyLabel="Keine" value={restNetNames(ex.sourceNetworks)} options={nets} onChange={(n) => setEx({ sourceNetworks: keyed(n, nets, netFallback) })} /></div>
          </div>
          <div className="stack">
            <div><Label>Zielzonen</Label><SfList label="Ausschluss Zielzonen" emptyLabel="Keine" value={refNames(ex.destinationZones?.zones)} options={opts.zones} onChange={(z) => setEx({ destinationZones: { zones: toRefs(z) } })} /></div>
            <div><Label>Zielnetzwerke</Label><SfList label="Ausschluss Zielnetzwerke" emptyLabel="Keine" value={restNetNames(ex.destinationNetworks)} options={nets} onChange={(n) => setEx({ destinationNetworks: keyed(n, nets, netFallback) })} /></div>
          </div>
          <div><Label>Dienste</Label><SfList label="Ausschluss Dienste" emptyLabel="Keine" value={svcNames(ex.servicesOrGroups)} options={opts.services} onChange={(n) => setEx({ servicesOrGroups: keyed(n, opts.services, 'services') })} /></div>
        </div>
      </Fold>

      {!v6 && <>
        <hr />
        <div className="sf-hint">{linkedNat.length
          ? <>Verknüpfte NAT-Regel: <b>{linkedNat.join(', ')}</b></>
          : 'Keine verknüpfte NAT-Regel – verknüpfte NAT-Regeln legen Sie unter „NAT-Regeln“ an.'}</div>
      </>}

      <hr />
      {!accept ? <div className="sf-hint">Bei „{ACTIONS.find((a) => a[0] === d.action)?.[1]}“ gelten keine Sicherheitsfunktionen, QoS, Heartbeat oder E-Mail-Scan.</div> : <>
        <Heading title="Sicherheitsfunktionen" />
        <Fold title="Webfilterung" open>
          <div className="sf-grid3">
            <div className="stack">
              <div><Label>Internetrichtlinie</Label><Select value={refName(sec.webPolicy)} none="Keine" options={opts.webPolicies} onChange={(n) => setSec({ webPolicy: polRef(n) })} /></div>
              <Check checked={sec.webCategoryBasedQosPolicy} label="Webkategorie-basiertes Traffic-Shaping anwenden" onChange={(v) => setSec({ webCategoryBasedQosPolicy: v })} />
              <Check checked={sec.blockQuicProtocol} label="QUIC-Protokoll blockieren" onChange={(v) => setSec({ blockQuicProtocol: v })} />
            </div>
            <div className="stack">
              <Label>Schadprogramm- und Inhaltsscans</Label>
              <Check checked={sec.scanHttpAndDecryptedHttps} label="HTTP und entschlüsseltes HTTPS scannen" onChange={(v) => setSec({ scanHttpAndDecryptedHttps: v })} />
              <Check checked={sec.zeroDayProtection} label="Zero-Day-Schutz verwenden" onChange={(v) => setSec({ zeroDayProtection: v })} />
              <Check checked={sec.scanFtp} label="FTP auf Schadprogramm scannen" onChange={(v) => setSec({ scanFtp: v })} />
            </div>
            <div className="stack">
              <Label>Gängige Internetports filtern</Label>
              <Check checked={sec.webProxy} label="Web-Proxy anstelle des DPI-Moduls verwenden" onChange={(v) => setSec({ webProxy: v, ...(v ? {} : { decryptHTTPSWebProxyMode: false }) })} />
              <Label>Web-Proxy-Optionen</Label>
              <Check checked={sec.decryptHTTPSWebProxyMode} disabled={!sec.webProxy} label="HTTPS während der Web-Proxy-Filterung entschlüsseln" onChange={(v) => setSec({ decryptHTTPSWebProxyMode: v })} />
            </div>
          </div>
        </Fold>

        <hr />
        <Fold title="Synchronized Security Heartbeat konfigurieren" open={hbOn}>
          <div className="sf-grid3">
            {[['source', 'Quelle'], ['destination', 'Ziel']].map(([k, label]) => {
              const hb = d.synchronizedSecurityHeartbeat?.[k] || {}
              const setHb = (patch) => sub('synchronizedSecurityHeartbeat', { [k]: { minimumLevel: 'noRestriction', blockClientsWithNoHeartbeat: false, ...hb, ...patch } })
              return (
                <div key={k} className="stack">
                  <div><Label>Minimaler Heartbeat-Status ({label})</Label>
                    <Select value={hb.minimumLevel || 'noRestriction'} options={HB} onChange={(v) => setHb({ minimumLevel: v })} /></div>
                  <Check checked={hb.blockClientsWithNoHeartbeat} label={`${label}: Clients ohne Heartbeat blockieren`} onChange={(v) => setHb({ blockClientsWithNoHeartbeat: v })} />
                </div>
              )
            })}
          </div>
        </Fold>

        <hr />
        <Heading title="Andere Sicherheitsfunktionen" />
        <div className="sf-grid3">
          <div className="stack">
            <div><Label>Anwendungen identifizieren und kontrollieren (App Control)</Label>
              <Select value={refName(sec.applicationPolicy)} none="Keine" options={opts.appPolicies} onChange={(n) => setSec({ applicationPolicy: polRef(n) })} /></div>
            <Check checked={sec.applicationBasedQosPolicy} label="Anwendungsbasierte Traffic-Shaping-Richtlinie übernehmen" onChange={(v) => setSec({ applicationBasedQosPolicy: v })} />
            <div><Label>Exploits erkennen und verhindern (IPS)</Label>
              <Select value={refName(sec.ipsPolicy)} none="Keine" options={opts.ipsPolicies} onChange={(n) => setSec({ ipsPolicy: polRef(n) })} /></div>
          </div>
          <div className="stack">
            <div><Label>Datenverkehr regeln</Label>
              <Select value={refName(d.qos?.trafficShapingPolicy)} none="Keine" options={opts.tsPolicies} onChange={(n) => sub('qos', { trafficShapingPolicy: polRef(n) })} /></div>
            <Check checked={sec.scanWithNdrActiveThreatIntelligence} label="Mit NDR Active Threat Intelligence scannen" onChange={(v) => setSec({ scanWithNdrActiveThreatIntelligence: v })} />
          </div>
          <div><Label>DSCP-Markierung</Label>
            <Select value={d.qos?.dscpMarking || ''} none="DSCP-Markierung wählen" options={DSCP} onChange={(n) => sub('qos', { dscpMarking: n || null })} /></div>
        </div>

        <hr />
        <Fold title="E-Mail-Inhalt scannen" open={mailOn}>
          <div className="sf-grid3">
            {['smtp', 'smtps', 'imap', 'imaps', 'pop3', 'pop3s'].map((p) => (
              <Check key={p} checked={d.emailScanning?.[p]} label={`${p.toUpperCase()} scannen`} onChange={(v) => sub('emailScanning', { [p]: v })} />
            ))}
          </div>
        </Fold>
      </>}
    </div>
  )
  return (
    <EditorShell page={page} title={isNew ? `Firewall-Regel ${v6 ? '(IPv6) ' : ''}hinzufügen` : 'Firewall-Regel bearbeiten'} entity={entity}
      data={d} setData={setD} isNew={isNew} form={form} onClose={onClose} positionField={posField}
      onSubmit={(payload) => onSubmit({ entity, action: isNew ? 'add' : 'update', name: payload.name, data: payload,
        position: position.type === 'keep' ? null : position })} />
  )
}

// --- NAT-Regel -----------------------------------------------------------------------------------------------

function newNat() {
  return {
    name: '', description: '', enabled: true,
    originalSourceNetworks: { any: true }, originalDestinationNetworks: { any: true }, originalServicesOrGroups: { any: true },
    translatedSource: null, translatedDestination: null, translatedService: null,
    inboundInterfaces: { any: true }, outboundInterfaces: { any: true },
  }
}

export function SophosNatEditor({ entity, config, rule, onClose, onSubmit, page }) {
  const isNew = !rule
  const opts = useMemo(() => restRefOptions(config), [config])
  const rules = (config[entity] || []).map((r) => r.name)
  const [d, setD] = useState(() => structuredClone(rule || newNat()))
  const [position, setPosition] = useState(isNew ? { type: 'top' } : { type: 'keep' })
  const set = (patch) => setD((cur) => ({ ...cur, ...patch }))
  const tsrc = d.translatedSource?.masq ? 'masq' : d.translatedSource?.ipv4Address ? 'host' : 'original'
  const tdst = d.translatedDestination?.ipv4Address ? 'host' : d.translatedDestination?.fqdnAddress ? 'fqdn' : 'original'
  const ifaces = (v) => (v?.any ? [] : refNames(v?.interfaces))
  const ifaceValue = (n) => (n.length ? { interfaces: toRefs(n) } : { any: true })
  const posField = <PositionField position={position} setPosition={setPosition} rules={rules} name={d.name} isNew={isNew} />
  const form = (
    <div className="sf-form">
      <Section title="NAT-Regel">
        <div className="form-grid">
          <Field label="Regelname"><input value={d.name} disabled={!isNew} maxLength={60} autoFocus={isNew} onChange={(e) => set({ name: e.target.value })} /></Field>
          <Field label="Beschreibung"><input value={d.description || ''} onChange={(e) => set({ description: e.target.value })} /></Field>
          <Box label="Status"><Toggle checked={d.enabled !== false} onChange={(v) => set({ enabled: v })} label={d.enabled !== false ? 'Aktiv' : 'Inaktiv'} /></Box>
          <Field label="Verknüpfte Firewall-Regel" hint="Leer = eigenständige NAT-Regel">
            <select value={refName(d.linkedFirewallRule)} onChange={(e) => set({ linkedFirewallRule: e.target.value ? { name: e.target.value } : null })}>
              <option value="">Keine</option>{opts.rules.map((r) => <option key={r}>{r}</option>)}
            </select>
          </Field>
        </div>
        {posField}
      </Section>
      <div className="sf-nat">
        <div className="sf-nat-head"><span /><b>Original</b><b>Übersetzt</b></div>
        <div className="sf-nat-row">
          <span className="sf-nat-label">Quelle</span>
          <SfList label="Original-Quelle" value={restNetNames(d.originalSourceNetworks)} options={opts.networks} onChange={(n) => set({ originalSourceNetworks: netsValue(n, opts.networks, 'ipv4Addresses') })} />
          <div className="stack">
            <select value={tsrc} onChange={(e) => set({ translatedSource: e.target.value === 'masq' ? { masq: true } : e.target.value === 'host' ? { ipv4Address: { name: opts.ipv4[0]?.value || '' } } : null })}>
              <option value="original">Original</option><option value="masq">MASQ (Adresse der Schnittstelle)</option><option value="host">IP-Host …</option>
            </select>
            {tsrc === 'host' && <select value={d.translatedSource.ipv4Address.name} onChange={(e) => set({ translatedSource: { ipv4Address: { name: e.target.value } } })}>
              {opts.ipv4.map((o) => <option key={o.value}>{o.value}</option>)}</select>}
          </div>
        </div>
        <div className="sf-nat-row">
          <span className="sf-nat-label">Ziel</span>
          <SfList label="Original-Ziel" value={restNetNames(d.originalDestinationNetworks)} options={opts.networks} onChange={(n) => set({ originalDestinationNetworks: netsValue(n, opts.networks, 'ipv4Addresses') })} />
          <div className="stack">
            <select value={tdst} onChange={(e) => set({ translatedDestination: e.target.value === 'host' ? { ipv4Address: { name: opts.ipv4[0]?.value || '' } } : e.target.value === 'fqdn' ? { fqdnAddress: { name: opts.fqdn[0]?.value || '' } } : null })}>
              <option value="original">Original</option><option value="host">IP-Host …</option><option value="fqdn">FQDN-Host …</option>
            </select>
            {tdst === 'host' && <select value={d.translatedDestination.ipv4Address.name} onChange={(e) => set({ translatedDestination: { ipv4Address: { name: e.target.value } } })}>
              {opts.ipv4.map((o) => <option key={o.value}>{o.value}</option>)}</select>}
            {tdst === 'fqdn' && <select value={d.translatedDestination.fqdnAddress.name} onChange={(e) => set({ translatedDestination: { fqdnAddress: { name: e.target.value } } })}>
              {opts.fqdn.map((o) => <option key={o.value}>{o.value}</option>)}</select>}
          </div>
        </div>
        <div className="sf-nat-row">
          <span className="sf-nat-label">Dienste</span>
          <SfList label="Original-Dienste" value={svcNames(d.originalServicesOrGroups)} options={opts.services} onChange={(s) => set({ originalServicesOrGroups: svcValue(s, opts.services) })} />
          <select value={refName(d.translatedService)} onChange={(e) => set({ translatedService: e.target.value ? { name: e.target.value } : null })}>
            <option value="">Original</option>{opts.serviceItems.map((o) => <option key={o.value}>{o.value}</option>)}
          </select>
        </div>
      </div>
      <Section title="Schnittstellen">
        <div className="grid two">
          <Box label="Eingehende Schnittstellen"><SfList label="Eingehende Schnittstellen" value={ifaces(d.inboundInterfaces)} options={opts.interfaces} onChange={(n) => set({ inboundInterfaces: ifaceValue(n) })} /></Box>
          <Box label="Ausgehende Schnittstellen"><SfList label="Ausgehende Schnittstellen" value={ifaces(d.outboundInterfaces)} options={opts.interfaces} onChange={(n) => set({ outboundInterfaces: ifaceValue(n) })} /></Box>
        </div>
        <div className="muted small">Lastverteilung, Health-Check und SNAT-Überschreibungen je Schnittstelle: im JSON-Modus.</div>
      </Section>
    </div>
  )
  return (
    <EditorShell page={page} title={isNew ? 'NAT-Regel hinzufügen' : `NAT-Regel „${rule.name}“ bearbeiten`} entity={entity}
      data={d} setData={setD} isNew={isNew} form={form} onClose={onClose} positionField={posField}
      onSubmit={(payload) => onSubmit({ entity, action: isNew ? 'add' : 'update', name: payload.name, data: payload,
        position: position.type === 'keep' ? null : position })} />
  )
}

// --- Ansicht: Sicherheitsfunktionen & Details (Tabelle) ------------------------------------------------------

/** Kurzsymbole wie die Feature-Spalte in SFOS */
export function ruleFeatures(r) {
  const s = r.securityFeatures || {}
  const out = []
  if (refName(s.webPolicy)) out.push(['Web', `Web-Richtlinie: ${refName(s.webPolicy)}`])
  if (refName(s.applicationPolicy)) out.push(['App', `Anwendungskontrolle: ${refName(s.applicationPolicy)}`])
  if (refName(s.ipsPolicy)) out.push(['IPS', `IPS: ${refName(s.ipsPolicy)}`])
  if (s.scanHttpAndDecryptedHttps || s.scanFtp) out.push(['AV', 'Malware-Scan'])
  if (s.zeroDayProtection) out.push(['0-Day', 'Zero-Day-Schutz'])
  if (s.scanWithNdrActiveThreatIntelligence) out.push(['NDR', 'NDR Active Threat Intelligence'])
  if (refName(r.qos?.trafficShapingPolicy)) out.push(['QoS', `Traffic Shaping: ${refName(r.qos.trafficShapingPolicy)}`])
  const hb = r.synchronizedSecurityHeartbeat || {}
  if (['source', 'destination'].some((k) => hb[k]?.minimumLevel && hb[k].minimumLevel !== 'noRestriction')) out.push(['HB', 'Heartbeat-Anforderung'])
  if (r.userAuthentication) out.push(['User', 'Benutzer-Abgleich'])
  if (Object.values(r.emailScanning || {}).some(Boolean)) out.push(['Mail', 'E-Mail-Scan'])
  return out
}

export function FeatureBadges({ rule }) {
  const f = ruleFeatures(rule)
  if (!f.length) return <span className="muted small">–</span>
  return <span className="chips">{f.map(([k, t]) => <span key={k} className="feat" title={t}>{k}</span>)}</span>
}

function Line({ label, children }) {
  return <div className="sf-line"><span>{label}</span><div>{children}</div></div>
}

const list = (names) => (names.length ? names.join(', ') : 'Beliebig')

export function RuleDetails({ rule }) {
  const s = rule.securityFeatures || {}
  const ex = rule.exclusions || {}
  const exItems = [...refNames(ex.sourceZones?.zones), ...restNetNames(ex.sourceNetworks), ...refNames(ex.destinationZones?.zones),
    ...restNetNames(ex.destinationNetworks), ...svcNames(ex.servicesOrGroups)]
  const ua = rule.userAuthentication
  return (
    <div className="sf-details">
      <div>
        <h5>Quelle</h5>
        <Line label="Zonen">{rule.sourceZones?.any ? 'Beliebig' : list(refNames(rule.sourceZones?.zones))}</Line>
        <Line label="Netzwerke">{list(restNetNames(rule.sourceNetworks))}</Line>
        <Line label="Zeitplan">{refName(rule.schedule) || 'Immer'}</Line>
      </div>
      <div>
        <h5>Ziel & Dienste</h5>
        <Line label="Zonen">{rule.destinationZones?.any ? 'Beliebig' : list(refNames(rule.destinationZones?.zones))}</Line>
        <Line label="Netzwerke">{list(restNetNames(rule.destinationNetworks))}</Line>
        <Line label="Dienste">{list(svcNames(rule.servicesOrGroups))}</Line>
      </div>
      <div>
        <h5>Sicherheit</h5>
        <Line label="Web">{refName(s.webPolicy) || 'Keine'}</Line>
        <Line label="Anwendungen">{refName(s.applicationPolicy) || 'Keine'}</Line>
        <Line label="IPS">{refName(s.ipsPolicy) || 'Keine'}</Line>
        <Line label="Traffic Shaping">{refName(rule.qos?.trafficShapingPolicy) || 'Keine'}{rule.qos?.dscpMarking ? ` · DSCP ${rule.qos.dscpMarking}` : ''}</Line>
      </div>
      <div>
        <h5>Weitere</h5>
        <Line label="Benutzer">{ua ? (ua.usersOrGroups?.any ? 'alle bekannten' : list([...refNames(ua.usersOrGroups?.users), ...refNames(ua.usersOrGroups?.userGroups)])) : 'nicht abgeglichen'}</Line>
        <Line label="Ausnahmen">{exItems.length ? exItems.join(', ') : 'keine'}</Line>
        <Line label="Protokoll">{rule.logTraffic ? 'an' : 'aus'}</Line>
      </div>
    </div>
  )
}

/** NAT-Zeile: Original → Übersetzt, wie die NAT-Tabelle in SFOS */
export function natView(n) {
  const ts = n.translatedSource?.masq ? 'MASQ' : refName(n.translatedSource?.ipv4Address) || 'Original'
  const td = refName(n.translatedDestination?.ipv4Address) || refName(n.translatedDestination?.fqdnAddress) || 'Original'
  const ifs = (v) => (v?.any ? 'Beliebig' : refNames(v?.interfaces).join(', '))
  return {
    enabled: n.enabled !== false,
    oSrc: restNetNames(n.originalSourceNetworks), oDst: restNetNames(n.originalDestinationNetworks),
    oSvc: svcNames(n.originalServicesOrGroups), tSrc: ts, tDst: td, tSvc: refName(n.translatedService) || 'Original',
    inIf: ifs(n.inboundInterfaces), outIf: ifs(n.outboundInterfaces), linked: refName(n.linkedFirewallRule),
  }
}
