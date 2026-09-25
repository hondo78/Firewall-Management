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
