import { useMemo, useState } from 'react'
import { EditorShell, PositionField } from './Editors'
import { asList, restNetNames, restRefOptions } from './entities'
import { Field, Picker, Seg } from './ui'

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

function PolicySelect({ label, value, options, onChange, none = 'Keine' }) {
  return (
    <Field label={label}>
      <select value={value || ''} onChange={(e) => onChange(e.target.value)}>
        <option value="">{none}</option>
        {options.map((o) => <option key={o}>{o}</option>)}
        {value && !options.includes(value) && <option>{value}</option>}
      </select>
    </Field>
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

export function SophosRuleEditor({ entity, config, rule, onClose, onSubmit }) {
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

  const posField = <PositionField position={position} setPosition={setPosition} rules={rules} name={d.name} isNew={isNew} />
  const form = isWaf ? null : (
    <div className="sf-form">
      <Section title="Regel">
        <div className="form-grid">
          <Field label="Regelname"><input value={d.name} disabled={!isNew} maxLength={60} autoFocus={isNew} onChange={(e) => set({ name: e.target.value })} /></Field>
          <Field label="Beschreibung"><input value={d.description || ''} maxLength={255} onChange={(e) => set({ description: e.target.value })} /></Field>
        </div>
        <div className="form-grid">
          <Box label="Aktion"><Seg options={[['accept', 'Zulassen'], ['drop', 'Verwerfen'], ['reject', 'Ablehnen']]} value={d.action} onChange={(a) => set({ action: a })} /></Box>
          <Box label="Status"><Toggle checked={d.enabled !== false} onChange={(v) => set({ enabled: v })} label={d.enabled !== false ? 'Aktiv' : 'Inaktiv'} /></Box>
          <Box label="Protokollierung"><Toggle checked={d.logTraffic} onChange={(v) => set({ logTraffic: v })} label="Firewall-Traffic protokollieren" /></Box>
        </div>
        {posField}
        {!accept && <div className="muted small">Bei „Verwerfen“/„Ablehnen“ speichert die Firewall keine Sicherheitsfunktionen, QoS, Heartbeat oder E-Mail-Scan.</div>}
      </Section>

      <div className="grid two">
        <Section title="Quelle">
          <Box label="Quell-Zonen"><Picker value={d.sourceZones?.any ? [] : refNames(d.sourceZones?.zones)} options={opts.zones} onChange={(z) => set({ sourceZones: zonesValue(z) })} /></Box>
          <Box label="Quell-Netzwerke und -Geräte"><Picker value={restNetNames(d.sourceNetworks)} options={nets} onChange={(n) => set({ sourceNetworks: netsValue(n, nets, netFallback) })} /></Box>
          <Field label="Während der geplanten Zeit">
            <select value={refName(d.schedule)} onChange={(e) => set({ schedule: e.target.value ? { name: e.target.value } : null })}>
              <option value="">Immer</option>{opts.schedules.map((s) => <option key={s}>{s}</option>)}
            </select>
          </Field>
        </Section>
        <Section title="Ziel und Dienste">
          <Box label="Ziel-Zonen"><Picker value={d.destinationZones?.any ? [] : refNames(d.destinationZones?.zones)} options={opts.zones} onChange={(z) => set({ destinationZones: zonesValue(z) })} /></Box>
          <Box label="Ziel-Netzwerke"><Picker value={restNetNames(d.destinationNetworks)} options={nets} onChange={(n) => set({ destinationNetworks: netsValue(n, nets, netFallback) })} /></Box>
          <Box label="Dienste"><Picker value={svcNames(d.servicesOrGroups)} options={opts.services} onChange={(s) => set({ servicesOrGroups: svcValue(s, opts.services) })} /></Box>
        </Section>
      </div>

      <Section title="Ausnahmen" collapsible open={hasExclusions} extra={hasExclusions && <span className="badge b-warn">aktiv</span>}>
        <div className="muted small">Verkehr, der hierauf passt, ist von der Regel ausgenommen.</div>
        <div className="grid two">
          <div className="stack">
            <Box label="Quell-Zonen"><Picker emptyLabel="keine" value={refNames(ex.sourceZones?.zones)} options={opts.zones} onChange={(z) => setEx({ sourceZones: { zones: toRefs(z) } })} /></Box>
            <Box label="Quell-Netzwerke"><Picker emptyLabel="keine" value={restNetNames(ex.sourceNetworks)} options={nets} onChange={(n) => setEx({ sourceNetworks: keyed(n, nets, netFallback) })} /></Box>
          </div>
          <div className="stack">
            <Box label="Ziel-Zonen"><Picker emptyLabel="keine" value={refNames(ex.destinationZones?.zones)} options={opts.zones} onChange={(z) => setEx({ destinationZones: { zones: toRefs(z) } })} /></Box>
            <Box label="Ziel-Netzwerke"><Picker emptyLabel="keine" value={restNetNames(ex.destinationNetworks)} options={nets} onChange={(n) => setEx({ destinationNetworks: keyed(n, nets, netFallback) })} /></Box>
            <Box label="Dienste"><Picker emptyLabel="keine" value={svcNames(ex.servicesOrGroups)} options={opts.services} onChange={(s) => setEx({ servicesOrGroups: keyed(s, opts.services, 'services') })} /></Box>
          </div>
        </div>
      </Section>

      <Section title="Benutzer identifizieren" collapsible open={!!ua}>
        <Toggle checked={!!ua} label="Bekannte Benutzer abgleichen" onChange={(on) => set({ userAuthentication: on ? { usersOrGroups: { any: true }, excludeUsersFromAccounting: false, webAuthenticationForUnknownUsers: false } : null })} />
        {ua && <>
          <Box label="Benutzer oder Gruppen"><Picker value={ua.usersOrGroups?.any ? [] : [...refNames(ua.usersOrGroups?.users), ...refNames(ua.usersOrGroups?.userGroups)]}
            options={opts.usersAndGroups} onChange={(n) => sub('userAuthentication', { usersOrGroups: n.length ? keyed(n, opts.usersAndGroups, 'userGroups') : { any: true } })} /></Box>
          <Toggle checked={ua.excludeUsersFromAccounting} label="Benutzeraktivität von der Datenerfassung ausnehmen" onChange={(v) => sub('userAuthentication', { excludeUsersFromAccounting: v })} />
          <Toggle checked={ua.webAuthenticationForUnknownUsers} label="Web-Authentifizierung für unbekannte Benutzer" onChange={(v) => sub('userAuthentication', { webAuthenticationForUnknownUsers: v })} />
        </>}
      </Section>

      {accept && <>
        <Section title="Web-Filterung">
          <div className="form-grid">
            <PolicySelect label="Web-Richtlinie" value={refName(sec.webPolicy)} options={opts.webPolicies} onChange={(n) => setSec({ webPolicy: polRef(n) })} />
          </div>
          <div className="sf-toggles">
            <Toggle checked={sec.webCategoryBasedQosPolicy} label="Web-kategoriebasiertes Traffic Shaping" onChange={(v) => setSec({ webCategoryBasedQosPolicy: v })} />
            <Toggle checked={sec.blockQuicProtocol} label="QUIC-Protokoll blockieren" onChange={(v) => setSec({ blockQuicProtocol: v })} />
            <Toggle checked={sec.scanHttpAndDecryptedHttps} label="HTTP und entschlüsseltes HTTPS auf Malware scannen" onChange={(v) => setSec({ scanHttpAndDecryptedHttps: v })} />
            <Toggle checked={sec.zeroDayProtection} label="Zero-Day-Schutz verwenden" onChange={(v) => setSec({ zeroDayProtection: v })} />
            <Toggle checked={sec.webProxy} label="Web-Proxy statt DPI-Engine" onChange={(v) => setSec({ webProxy: v })} />
            <Toggle checked={sec.decryptHTTPSWebProxyMode} label="HTTPS im Web-Proxy entschlüsseln" onChange={(v) => setSec({ decryptHTTPSWebProxyMode: v })} />
            <Toggle checked={sec.scanFtp} label="FTP auf Malware scannen" onChange={(v) => setSec({ scanFtp: v })} />
          </div>
        </Section>
        <Section title="Weitere Sicherheitsfunktionen">
          <div className="form-grid">
            <PolicySelect label="Anwendungskontrolle" value={refName(sec.applicationPolicy)} options={opts.appPolicies} onChange={(n) => setSec({ applicationPolicy: polRef(n) })} />
            <PolicySelect label="Intrusion Prevention (IPS)" value={refName(sec.ipsPolicy)} options={opts.ipsPolicies} onChange={(n) => setSec({ ipsPolicy: polRef(n) })} />
          </div>
          <div className="sf-toggles">
            <Toggle checked={sec.applicationBasedQosPolicy} label="Anwendungsbasiertes Traffic Shaping" onChange={(v) => setSec({ applicationBasedQosPolicy: v })} />
            <Toggle checked={sec.scanWithNdrActiveThreatIntelligence} label="Mit NDR Active Threat Intelligence scannen" onChange={(v) => setSec({ scanWithNdrActiveThreatIntelligence: v })} />
          </div>
        </Section>
        <div className="grid two">
          <Section title="E-Mail-Scan" collapsible open={Object.values(d.emailScanning || {}).some(Boolean)}>
            <div className="sf-checks">
              {['smtp', 'smtps', 'imap', 'imaps', 'pop3', 'pop3s'].map((p) => (
                <label key={p} className="check"><input type="checkbox" checked={!!d.emailScanning?.[p]} onChange={(e) => sub('emailScanning', { [p]: e.target.checked })} />{p.toUpperCase()} scannen</label>
              ))}
            </div>
          </Section>
          <Section title="Traffic Shaping & QoS" collapsible open={!!(d.qos?.trafficShapingPolicy || d.qos?.dscpMarking)}>
            <PolicySelect label="Traffic-Shaping-Richtlinie" value={refName(d.qos?.trafficShapingPolicy)} options={opts.tsPolicies} onChange={(n) => sub('qos', { trafficShapingPolicy: polRef(n) })} />
            <PolicySelect label="DSCP-Markierung" none="Keine Markierung" value={d.qos?.dscpMarking || ''} options={DSCP} onChange={(n) => sub('qos', { dscpMarking: n || null })} />
          </Section>
        </div>
        <Section title="Synchronized Security Heartbeat" collapsible
          open={['source', 'destination'].some((k) => d.synchronizedSecurityHeartbeat?.[k]?.minimumLevel && d.synchronizedSecurityHeartbeat[k].minimumLevel !== 'noRestriction')}>
          <div className="grid two">
            {[['source', 'Quelle'], ['destination', 'Ziel']].map(([k, label]) => {
              const hb = d.synchronizedSecurityHeartbeat?.[k] || {}
              const setHb = (patch) => sub('synchronizedSecurityHeartbeat', { [k]: { minimumLevel: 'noRestriction', blockClientsWithNoHeartbeat: false, ...hb, ...patch } })
              return (
                <div key={k} className="stack">
                  <Field label={`Minimaler Heartbeat (${label})`}>
                    <select value={hb.minimumLevel || 'noRestriction'} onChange={(e) => setHb({ minimumLevel: e.target.value })}>
                      {HB.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
                    </select>
                  </Field>
                  <Toggle checked={hb.blockClientsWithNoHeartbeat} label="Clients ohne Heartbeat blockieren" onChange={(v) => setHb({ blockClientsWithNoHeartbeat: v })} />
                </div>
              )
            })}
          </div>
        </Section>
      </>}
    </div>
  )
  return (
    <EditorShell title={isNew ? `Firewall-Regel ${v6 ? '(IPv6) ' : ''}hinzufügen` : `Firewall-Regel „${rule.name}“ bearbeiten`} entity={entity}
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

export function SophosNatEditor({ entity, config, rule, onClose, onSubmit }) {
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
          <Picker value={restNetNames(d.originalSourceNetworks)} options={opts.networks} onChange={(n) => set({ originalSourceNetworks: netsValue(n, opts.networks, 'ipv4Addresses') })} />
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
          <Picker value={restNetNames(d.originalDestinationNetworks)} options={opts.networks} onChange={(n) => set({ originalDestinationNetworks: netsValue(n, opts.networks, 'ipv4Addresses') })} />
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
          <Picker value={svcNames(d.originalServicesOrGroups)} options={opts.services} onChange={(s) => set({ originalServicesOrGroups: svcValue(s, opts.services) })} />
          <select value={refName(d.translatedService)} onChange={(e) => set({ translatedService: e.target.value ? { name: e.target.value } : null })}>
            <option value="">Original</option>{opts.serviceItems.map((o) => <option key={o.value}>{o.value}</option>)}
          </select>
        </div>
      </div>
      <Section title="Schnittstellen">
        <div className="grid two">
          <Box label="Eingehende Schnittstellen"><Picker value={ifaces(d.inboundInterfaces)} options={opts.interfaces} onChange={(n) => set({ inboundInterfaces: ifaceValue(n) })} /></Box>
          <Box label="Ausgehende Schnittstellen"><Picker value={ifaces(d.outboundInterfaces)} options={opts.interfaces} onChange={(n) => set({ outboundInterfaces: ifaceValue(n) })} /></Box>
        </div>
        <div className="muted small">Lastverteilung, Health-Check und SNAT-Überschreibungen je Schnittstelle: im JSON-Modus.</div>
      </Section>
    </div>
  )
  return (
    <EditorShell title={isNew ? 'NAT-Regel hinzufügen' : `NAT-Regel „${rule.name}“ bearbeiten`} entity={entity}
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
