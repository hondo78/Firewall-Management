/** Spalten je Objekttyp (wie die Tabellen im Config-Studio-Editor) – für REST- und XML-Format. */
import { anyRuleView, anySummary, asList, listOf } from './entities'

const names = (items) => asList(items).map((i) => i?.name ?? i).filter(Boolean).join(', ')
const port = (p) => (p == null || p === '' ? '' : typeof p === 'object' ? (p.from === p.to ? `${p.from}` : `${p.from}:${p.to}`) : String(p))

const col = (key, label, get, opts = {}) => ({ key, label, get, ...opts })

const REST_ADDR = [
  col('type', 'Typ', (o) => ({ ipv4Address: 'Host', ipv4Network: 'Netzwerk', ipv4Range: 'Bereich', ipv4List: 'Liste', ipv6Address: 'Host', ipv6Network: 'Netzwerk', ipv6Range: 'Bereich', ipv6List: 'Liste' }[o.type] || o.type)),
  col('addr', 'Adresse', (o) => anySummary('addressesIpv4', o).replace(/^(Host|Netz|Bereich|Liste) /, '')),
  col('internal', 'System', (o) => (o.isInternal ? 'ja' : ''), { hidden: true }),
]

export const COLUMNS = {
  // REST
  addressesIpv4: REST_ADDR,
  addressesIpv6: REST_ADDR,
  addressGroupsIpv4: [col('members', 'Mitglieder', (o) => names(o.ipv4Addresses)), col('n', 'Anzahl', (o) => asList(o.ipv4Addresses).length)],
  addressGroupsIpv6: [col('members', 'Mitglieder', (o) => names(o.ipv6Addresses))],
  addressesFqdn: [col('fqdn', 'FQDN', (o) => o.fqdn)],
  addressGroupsFqdn: [col('members', 'Mitglieder', (o) => names(o.fqdns)), col('n', 'Anzahl', (o) => asList(o.fqdns).length)],
  addressesMac: [col('mac', 'MAC-Adresse', (o) => o.macAddress || asList(o.macAddresses).join(', '))],
  countryGroups: [col('countries', 'Länder', (o) => names(o.countries))],
  services: [
    col('type', 'Typ', (o) => ({ tcpOrUdp: 'TCP/UDP', ip: 'IP', icmp: 'ICMP', icmpv6: 'ICMPv6' }[o.type] || o.type)),
    col('proto', 'Protokoll', (o) => [...new Set(asList(o.services).map((d) => (d.protocol || d.ipProtocol || d.icmpType || d.icmpv6Type || '').toUpperCase()))].join(', ')),
    col('dport', 'Ziel-Port', (o) => asList(o.services).map((d) => port(d.destinationPort)).filter(Boolean).join(', ')),
    col('sport', 'Quell-Port', (o) => asList(o.services).map((d) => port(d.sourcePort)).filter(Boolean).join(', '), { hidden: true }),
  ],
  serviceGroups: [col('members', 'Mitglieder', (o) => names(o.services))],
  zones: [col('type', 'Typ', (o) => o.type), col('services', 'Gerätezugriff', (o) => names(o.services), { hidden: true })],
  schedules: [col('type', 'Typ', (o) => (o.type === 'oneTime' ? 'einmalig' : 'wiederkehrend')),
    col('slots', 'Zeiten', (o) => asList(o.timeSlots).map((t) => `${t.dayOfWeek} ${t.startTime}–${t.endTime}`).join(', '))],
  natRulesIpv4: [col('enabled', 'Status', (o) => (o.enabled === false ? 'inaktiv' : 'aktiv')), col('summary', 'Details', (o) => anySummary('natRulesIpv4', o))],
  // XML
  IPHost: [
    col('family', 'IP-Version', (o) => o.IPFamily),
    col('type', 'Host-Typ', (o) => ({ IP: 'Host', Network: 'Netzwerk', IPRange: 'Bereich', IPList: 'Liste' }[o.HostType] || o.HostType)),
    col('addr', 'IP-Adresse', (o) => (o.HostType === 'Network' ? `${o.IPAddress}/${o.Subnet}` : o.HostType === 'IPRange' ? `${o.StartIPAddress} – ${o.EndIPAddress}` : o.IPAddress || o.ListOfIPAddresses || '–')),
  ],
  IPHostGroup: [col('members', 'Mitglieder', (o) => listOf(o.HostList, 'Host').join(', ')), col('family', 'IP-Version', (o) => o.IPFamily, { hidden: true })],
  FQDNHost: [col('fqdn', 'FQDN', (o) => o.FQDN)],
  FQDNHostGroup: [col('members', 'Mitglieder', (o) => listOf(o.FQDNHostList, 'FQDNHost').join(', '))],
  MACHost: [col('mac', 'MAC-Adresse', (o) => o.MACAddress || listOf(o.MACList, 'MACAddress').join(', '))],
  Services: [
    col('type', 'Typ', (o) => o.Type),
    col('dport', 'Ziel-Port', (o) => listOf(o.ServiceDetails, 'ServiceDetail').map((d) => d.DestinationPort || d.ProtocolName || d.ICMPType).filter(Boolean).join(', ')),
    col('proto', 'Protokoll', (o) => [...new Set(listOf(o.ServiceDetails, 'ServiceDetail').map((d) => d.Protocol).filter(Boolean))].join(', ')),
  ],
  ServiceGroup: [col('members', 'Mitglieder', (o) => listOf(o.ServiceList, 'Service').join(', '))],
  Zone: [col('type', 'Typ', (o) => o.Type)],
  Schedule: [col('type', 'Typ', (o) => o.Type)],
  NATRule: [col('status', 'Status', (o) => o.Status), col('summary', 'Details', (o) => anySummary('NATRule', o))],
  FirewallRuleGroup: [col('members', 'Regeln', (o) => anySummary('FirewallRuleGroup', o))],
}

/** Durchsuchbarer Text eines Objekts (Name + alle Werte). */
export function searchText(o) {
  return JSON.stringify(o).toLowerCase()
}

export function ruleCells(entity, o) {
  return anyRuleView(entity, o)
}
