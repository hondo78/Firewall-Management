/** Hilfen für Sophos-Objekte (Datenstruktur wie XML-API: Listen-Container = { Tag: [...] }). */

export const asList = (v) => (Array.isArray(v) ? v : v == null || v === '' ? [] : [v])
export const listOf = (container, key) => asList(container?.[key])

export function policy(rule) {
  return rule.NetworkPolicy || rule.UserPolicy || {}
}

export function ruleView(rule) {
  const p = policy(rule)
  return {
    action: p.Action || '–',
    log: p.LogTraffic === 'Enable',
    srcZones: listOf(p.SourceZones, 'Zone'),
    dstZones: listOf(p.DestinationZones, 'Zone'),
    srcNets: listOf(p.SourceNetworks, 'Network'),
    dstNets: listOf(p.DestinationNetworks, 'Network'),
    services: listOf(p.Services, 'Service'),
    schedule: p.Schedule || '',
    type: rule.PolicyType || 'Network',
    enabled: rule.Status !== 'Disable',
  }
}

/** Kurzbeschreibung eines Objekts für die Tabellenspalte „Details“. */
export function summary(entity, o) {
  switch (entity) {
    case 'IPHost':
      if (o.HostType === 'Network') return `Netz ${o.IPAddress}/${o.Subnet}`
      if (o.HostType === 'IPRange') return `Bereich ${o.StartIPAddress} – ${o.EndIPAddress}`
      if (o.HostType === 'IPList') return `Liste ${o.ListOfIPAddresses || ''}`
      return `Host ${o.IPAddress || ''}`
    case 'IPHostGroup': return listOf(o.HostList, 'Host').join(', ') || 'leer'
    case 'FQDNHost': return o.FQDN || ''
    case 'FQDNHostGroup': return listOf(o.FQDNHostList, 'FQDNHost').join(', ')
    case 'MACHost': return o.MACAddress || listOf(o.MACList, 'MACAddress').join(', ')
    case 'Services': {
      const d = listOf(o.ServiceDetails, 'ServiceDetail')
      if (o.Type === 'TCPorUDP') return d.map((x) => `${x.Protocol} ${x.DestinationPort}`).join(', ')
      if (o.Type === 'IP') return d.map((x) => `IP-Protokoll ${x.ProtocolName || ''}`).join(', ')
      return `${o.Type || ''} ${d.map((x) => x.ICMPType || '').join(', ')}`
    }
    case 'ServiceGroup': return listOf(o.ServiceList, 'Service').join(', ')
    case 'Zone': return o.Type || ''
    case 'NATRule': return `${o.Status || ''} ${o.LinkedFirewallrule ? `· verknüpft mit ${o.LinkedFirewallrule}` : ''}`
    case 'FirewallRuleGroup': return listOf(o.SecurityPolicyList, 'SecurityPolicy').join(', ')
    case 'Schedule': return o.Type || ''
    default: return ''
  }
}

/** Auswahllisten für Regel-Editor & Gruppen. */
export function refOptions(config) {
  const opt = (entity, kind) => (config[entity] || []).map((o) => ({ value: o.Name, kind }))
  return {
    zones: opt('Zone', 'Zone'),
    networks: [...opt('IPHost', 'IP-Host'), ...opt('IPHostGroup', 'Gruppe'), ...opt('FQDNHost', 'FQDN'),
      ...opt('FQDNHostGroup', 'FQDN-Gruppe'), ...opt('MACHost', 'MAC')],
    services: [...opt('Services', 'Dienst'), ...opt('ServiceGroup', 'Gruppe')],
    schedules: (config.Schedule || []).map((o) => o.Name),
    hosts: opt('IPHost', 'IP-Host'),
    serviceItems: opt('Services', 'Dienst'),
    fqdnHosts: opt('FQDNHost', 'FQDN'),
    rules: (config.FirewallRule || []).map((o) => o.Name),
  }
}

/** Container setzen oder – bei leerer Liste – entfernen (Sophos: fehlt = „Any“). */
export function setList(obj, container, key, values) {
  const out = { ...obj }
  if (values.length) out[container] = { [key]: values }
  else delete out[container]
  return out
}

export function canonical(v) {
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`
  if (v && typeof v === 'object') return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`).join(',')}}`
  return JSON.stringify(v)
}

/** Einfache XML-Darstellung eines Objekts (Anzeige/Experten-Editor). */
export function toXml(tag, value, indent = '') {
  const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    const inner = Object.entries(value).flatMap(([k, v]) => asList(v).map((item) => toXml(k, item, `${indent}  `)))
    if (!inner.length) return `${indent}<${tag}/>`
    return `${indent}<${tag}>\n${inner.join('\n')}\n${indent}</${tag}>`
  }
  return `${indent}<${tag}>${esc(value ?? '')}</${tag}>`
}

// --- SFOS REST-API (Format "rest") ---------------------------------------------------------------------------

export const REST_ENTITIES = new Set(['firewallRulesIpv4', 'firewallRulesIpv6', 'natRulesIpv4', 'addressesIpv4',
  'addressGroupsIpv4', 'addressesIpv6', 'addressGroupsIpv6', 'addressesFqdn', 'addressGroupsFqdn', 'addressesMac',
  'countryGroups', 'services', 'serviceGroups', 'zones', 'schedules', 'webPolicies', 'applicationPolicies', 'ipsPolicies',
  'trafficShapingPolicies', 'userGroups', 'users', 'interfaces', 'backupSettings'])
/** Nur lesend (werden auf der Firewall gepflegt) */
export const READ_ONLY_ENTITIES = new Set(['users', 'interfaces'])
// Einstellungsobjekte: genau ein Eintrag, nur ändern (kein Anlegen/Löschen)
export const SINGLETON_ENTITIES = new Set(['backupSettings'])
export const isRestEntity = (entity) => REST_ENTITIES.has(entity)
/** Regeln mit Reihenfolge und Regeltabelle (NAT läuft als Objektliste). */
export const RULE_TABLE_ENTITIES = new Set(['FirewallRule', 'firewallRulesIpv4', 'firewallRulesIpv6'])
export const PRIMARY_RULES = { xml: 'FirewallRule', rest: 'firewallRulesIpv4' }
export const oname = (o) => (o && ('Name' in o ? o.Name : o.name)) || ''

const refNames = (items) => asList(items).map((i) => i?.name).filter(Boolean)
// Schlüssel in source/destinationNetworks → Entität der Objekte
export const REST_NET_KEYS = {
  ipv4Addresses: 'addressesIpv4', ipv4Groups: 'addressGroupsIpv4', ipv6Addresses: 'addressesIpv6',
  ipv6Groups: 'addressGroupsIpv6', fqdnAddresses: 'addressesFqdn', fqdnGroups: 'addressGroupsFqdn',
  macAddresses: 'addressesMac', countryGroups: 'countryGroups',
}

export function restNetNames(nets) {
  if (!nets || nets.any) return []
  return Object.keys(REST_NET_KEYS).flatMap((k) => refNames(nets[k])).concat(refNames(nets.countries))
}

export function restRuleView(rule) {
  const svc = rule.servicesOrGroups || {}
  return {
    action: { accept: 'Accept', drop: 'Drop', reject: 'Reject' }[rule.action] || rule.action || '–',
    log: !!rule.logTraffic,
    srcZones: rule.sourceZones?.any ? [] : refNames(rule.sourceZones?.zones),
    dstZones: rule.destinationZones?.any ? [] : refNames(rule.destinationZones?.zones),
    srcNets: restNetNames(rule.sourceNetworks),
    dstNets: restNetNames(rule.destinationNetworks),
    services: svc.any ? [] : [...refNames(svc.services), ...refNames(svc.serviceGroups)],
    schedule: rule.schedule?.name || '',
    type: rule.ruleType || 'firewall',
    enabled: rule.enabled !== false,
  }
}

export const anyRuleView = (entity, rule) => (isRestEntity(entity) ? restRuleView(rule) : ruleView(rule))

// Ports: echte SFOS liefert Text („443“, „1:65535“), die Spezifikation {from, to}
const port = (p) => {
  if (p == null || p === '') return 'alle'
  if (typeof p !== 'object') return String(p).replace(':', '–')
  return p.from === p.to || p.to == null ? `${p.from}` : `${p.from}–${p.to}`
}

export function restSummary(entity, o) {
  switch (entity) {
    case 'addressesIpv4':
    case 'addressesIpv6':
      if (o.type?.endsWith('Network')) return `Netz ${o.ipv4NetworkAddress || o.ipv6NetworkAddress || ''}/${o.cidr ?? o.prefix ?? ''}`
      if (o.type?.endsWith('Range')) return `Bereich ${o.ipv4AddressStart || o.ipv6AddressStart} – ${o.ipv4AddressEnd || o.ipv6AddressEnd}`
      if (o.type?.endsWith('List')) return `Liste ${asList(o.ipv4Addresses || o.ipv6Addresses).map((x) => x?.name || x).join(', ')}`
      return `Host ${o.ipv4Address || o.ipv6Address || ''}`
    case 'addressGroupsIpv4': return refNames(o.ipv4Addresses).join(', ') || 'leer'
    case 'addressGroupsIpv6': return refNames(o.ipv6Addresses).join(', ') || 'leer'
    case 'addressesFqdn': return o.fqdn || ''
    case 'addressGroupsFqdn': return refNames(o.fqdns).join(', ') || 'leer'
    case 'addressesMac': return o.macAddress || asList(o.macAddresses).join(', ')
    case 'countryGroups': return refNames(o.countries).join(', ')
    case 'services':
      if (o.type === 'tcpOrUdp') return asList(o.services).map((d) => `${(d.protocol || '').toUpperCase()} ${port(d.destinationPort)}`).join(', ')
      return `${o.type}: ${asList(o.services).map((d) => d.ipProtocol || d.icmpType || d.icmpv6Type).join(', ')}`
    case 'serviceGroups': return refNames(o.services).join(', ')
    case 'zones': return `${o.type || ''}${o.services?.length ? ` · ${refNames(o.services).join(', ')}` : ''}`
    case 'schedules': return `${o.type === 'oneTime' ? 'einmalig' : 'wiederkehrend'} · ${asList(o.timeSlots).map((t) => `${t.dayOfWeek} ${t.startTime}–${t.endTime}`).join(', ')}`
    case 'natRulesIpv4': return `${o.enabled === false ? 'inaktiv · ' : ''}${o.linkedFirewallRule?.name ? `verknüpft mit ${o.linkedFirewallRule.name}` : ''}`
    case 'webPolicies': return `Standard: ${o.defaultAction === 'deny' ? 'blockieren' : o.defaultAction === 'allow' ? 'zulassen' : o.defaultAction || '–'}${asList(o.rules).length ? ` · ${asList(o.rules).length} Regeln` : ''}`
    case 'applicationPolicies':
    case 'ipsPolicies': return `${asList(o.rules).length} Regeln`
    case 'trafficShapingPolicies': return [o.type, o.associatesWith].filter(Boolean).join(' · ')
    case 'userGroups': return o.type || ''
    case 'users': return [o.displayName, o.group?.name && `Gruppe ${o.group.name}`].filter(Boolean).join(' · ')
    case 'interfaces': return [o.hardwareName, o.zone?.name && `Zone ${o.zone.name}`, o.ipv4?.address || o.ipv4?.ipAddress].filter(Boolean).join(' · ')
    default: return ''
  }
}

export const anySummary = (entity, o) => (isRestEntity(entity) ? restSummary(entity, o) : summary(entity, o))

/** Auswahllisten für den REST-Regeleditor; networks tragen den Schlüssel, unter dem sie in der Regel stehen. */
export function restRefOptions(config) {
  const opt = (entity, kind, key) => (config[entity] || []).map((o) => ({ value: o.name, kind, key }))
  return {
    zones: opt('zones', 'Zone'),
    networks: [...opt('addressesIpv4', 'IPv4', 'ipv4Addresses'), ...opt('addressGroupsIpv4', 'IPv4-Gruppe', 'ipv4Groups'),
      ...opt('addressesFqdn', 'FQDN', 'fqdnAddresses'), ...opt('addressGroupsFqdn', 'FQDN-Gruppe', 'fqdnGroups'),
      ...opt('addressesMac', 'MAC', 'macAddresses'), ...opt('countryGroups', 'Ländergruppe', 'countryGroups')],
    services: [...opt('services', 'Dienst', 'services'), ...opt('serviceGroups', 'Gruppe', 'serviceGroups')],
    schedules: (config.schedules || []).map((o) => o.name),
    networks6: [...opt('addressesIpv6', 'IPv6', 'ipv6Addresses'), ...opt('addressGroupsIpv6', 'IPv6-Gruppe', 'ipv6Groups'),
      ...opt('addressesMac', 'MAC', 'macAddresses')],
    webPolicies: (config.webPolicies || []).map((o) => o.name),
    appPolicies: (config.applicationPolicies || []).map((o) => o.name),
    ipsPolicies: (config.ipsPolicies || []).map((o) => o.name),
    tsPolicies: (config.trafficShapingPolicies || []).map((o) => o.name),
    usersAndGroups: [...opt('userGroups', 'Gruppe', 'userGroups'), ...opt('users', 'Benutzer', 'users')],
    interfaces: opt('interfaces', 'Schnittstelle'),
    ipv6: opt('addressesIpv6', 'IPv6'),
    ipv4: opt('addressesIpv4', 'IPv4'),
    fqdn: opt('addressesFqdn', 'FQDN'),
    serviceItems: opt('services', 'Dienst'),
    rules: (config.firewallRulesIpv4 || []).map((o) => o.name),
  }
}
