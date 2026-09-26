/** Spalten je Objekttyp (wie die Tabellen im Config-Studio-Editor) – für REST- und XML-Format. */
import { anyRuleView, anySummary, asList, listOf } from './entities'
import { t } from '../i18n'

const names = (items) => asList(items).map((i) => i?.name ?? i).filter(Boolean).join(', ')
const port = (p) => (p == null || p === '' ? '' : typeof p === 'object' ? (p.from === p.to ? `${p.from}` : `${p.from}:${p.to}`) : String(p))

const col = (key, label, get, opts = {}) => ({ key, label, get, ...opts })

const REST_ADDR = [
  col('type', t("Typ"), (o) => ({ ipv4Address: 'Host', ipv4Network: t("Netzwerk"), ipv4Range: t("Bereich"), ipv4List: t("Liste"), ipv6Address: 'Host', ipv6Network: t("Netzwerk"), ipv6Range: t("Bereich"), ipv6List: t("Liste") }[o.type] || o.type)),
  col('addr', t("Adresse"), (o) => anySummary('addressesIpv4', o).replace(/^(Host|Netz|Bereich|Liste) /, '')),
  col('internal', t("System"), (o) => (o.isInternal ? t("ja") : ''), { hidden: true }),
]

export const COLUMNS = {
  // REST
  addressesIpv4: REST_ADDR,
  addressesIpv6: [
    col('type', t("Typ"), (o) => ({ ipv6Address: 'Host', ipv6Network: t("Netzwerk"), ipv6Range: t("Bereich"), ipv6List: t("Liste") }[o.type] || o.type)),
    col('addr', t("Adresse"), (o) => (o.type === 'ipv6Network' ? `${o.ipv6NetworkAddress}/${o.prefixLength}` : o.type === 'ipv6Range' ? `${o.ipv6AddressStart} – ${o.ipv6AddressEnd}` : o.ipv6Address || asList(o.ipv6Addresses).join(', '))),
  ],
  addressGroupsIpv4: [col('members', t("Mitglieder"), (o) => names(o.ipv4Addresses)), col('n', t("Anzahl"), (o) => asList(o.ipv4Addresses).length)],
  addressGroupsIpv6: [col('members', t("Mitglieder"), (o) => names(o.ipv6Addresses))],
  addressesFqdn: [col('fqdn', 'FQDN', (o) => o.fqdn)],
  addressGroupsFqdn: [col('members', t("Mitglieder"), (o) => names(o.fqdns)), col('n', t("Anzahl"), (o) => asList(o.fqdns).length)],
  addressesMac: [col('mac', 'MAC-Adresse', (o) => o.macAddress || asList(o.macAddresses).join(', '))],
  countryGroups: [col('countries', t("Länder"), (o) => names(o.countries))],
  services: [
    col('type', t("Typ"), (o) => ({ tcpOrUdp: 'TCP/UDP', ip: 'IP', icmp: 'ICMP', icmpv6: 'ICMPv6' }[o.type] || o.type)),
    col('proto', t("Protokoll"), (o) => [...new Set(asList(o.services).map((d) => (d.protocol || d.ipProtocol || d.icmpType || d.icmpv6Type || '').toUpperCase()))].join(', ')),
    col('dport', t("Ziel-Port"), (o) => asList(o.services).map((d) => port(d.destinationPort)).filter(Boolean).join(', ')),
    col('sport', t("Quell-Port"), (o) => asList(o.services).map((d) => port(d.sourcePort)).filter(Boolean).join(', '), { hidden: true }),
  ],
  serviceGroups: [col('members', t("Mitglieder"), (o) => names(o.services))],
  zones: [col('type', t("Typ"), (o) => o.type), col('services', t("Gerätezugriff"), (o) => names(o.services), { hidden: true })],
  schedules: [col('type', t("Typ"), (o) => (o.type === 'oneTime' ? t("einmalig") : t("wiederkehrend"))),
    col('slots', t("Zeiten"), (o) => asList(o.timeSlots).map((t) => `${t.dayOfWeek} ${t.startTime}–${t.endTime}`).join(', '))],
  natRulesIpv4: [col('enabled', t("Status"), (o) => (o.enabled === false ? t("inaktiv") : t("aktiv"))), col('summary', t("Details"), (o) => anySummary('natRulesIpv4', o))],
  webPolicies: [col('default', t("Standardaktion"), (o) => ({ allow: t("Zulassen"), deny: t("Blockieren") }[o.defaultAction] || o.defaultAction || '–')),
    col('rules', t("Regeln"), (o) => asList(o.rules).length), col('safe', 'SafeSearch', (o) => (o.enforceSafeSearch ? t("ja") : ''), { hidden: true })],
  applicationPolicies: [col('rules', t("Regeln"), (o) => asList(o.rules).length)],
  ipsPolicies: [col('rules', t("Regeln"), (o) => asList(o.rules).length)],
  trafficShapingPolicies: [col('type', t("Typ"), (o) => o.type), col('assoc', t("Gilt für"), (o) => o.associatesWith),
    col('bw', t("Bandbreite"), (o) => (o.bandwidth ? JSON.stringify(o.bandwidth).replace(/[{}"]/g, '').replace(/,/g, ', ') : ''), { hidden: true })],
  userGroups: [col('type', t("Typ"), (o) => o.type)],
  users: [col('display', t("Anzeigename"), (o) => o.displayName), col('group', t("Gruppe"), (o) => o.group?.name), col('active', t("Aktiv"), (o) => (o.active === false ? t("nein") : t("ja")))],
  backupSettings: [col('storage', t("Ziel"), (o) => ({ local: t("Lokal"), ftp: 'FTP', email: 'E-Mail' }[o.backupStorage] || o.backupStorage)),
    col('freq', t("Zeitplan"), (o) => ({ never: t("nie"), daily: t("täglich"), weekly: t("wöchentlich"), monthly: t("monatlich") }[o.schedule?.frequency] || '–')),
    col('time', t("Uhrzeit"), (o) => (o.schedule?.hour != null ? `${String(o.schedule.hour).padStart(2, '0')}:${String(o.schedule.minute ?? 0).padStart(2, '0')}` : ''))],
  wafRules: [col('status', t("Status"), (o) => (o.Status === 'Disable' ? t("inaktiv") : t("aktiv"))),
    col('domains', t("Domänen"), (o) => asList(o.HTTPBasedPolicy?.Domains?.Domain).join(', ')),
    col('listen', t("Adresse"), (o) => `${o.HTTPBasedPolicy?.HostedAddress || ''}:${o.HTTPBasedPolicy?.ListenPort || ''}${o.HTTPBasedPolicy?.HTTPS === 'Enable' ? ' (HTTPS)' : ''}`),
    col('backend', t("Webserver"), (o) => [...new Set(asList(o.HTTPBasedPolicy?.AccessPaths?.AccessPath).flatMap((a) => asList(a.backend)))].filter(Boolean).join(', ')),
    col('protection', t("Schutz"), (o) => o.HTTPBasedPolicy?.ProtocolSecurity || '–')],
  wafServers: [col('server', t("Server"), (o) => o.server?.ipv4Address?.name || o.server?.fqdn?.name || ''), col('protocol', t("Protokoll"), (o) => (o.protocol || '').toUpperCase()),
    col('port', t("Port"), (o) => o.port), col('keep', t("Keep-Alive"), (o) => (o.keepAlive ? t("ja") : t("nein")), { hidden: true })],
  wafProtectionPolicies: [col('action', t("Modus"), (o) => (o.action === 'monitor' ? t("überwachen") : t("ablehnen"))),
    col('tf', t("Bedrohungsfilter"), (o) => (o.threatFilter?.enabled ? (o.threatFilter.filterStrength || '').replace('level', 'Stufe ') : t("aus"))),
    col('av', t("Antivirus"), (o) => (o.antivirus?.enabled ? o.antivirus.scanEngine : t("aus")))],
  wafAuthPolicies: [col('fwd', t("Weiterleitung"), (o) => Object.keys(o.authenticationForwarding || {}).join(', ') || '–'),
    col('clients', t("Client-Authentifizierung"), (o) => Object.keys(o.clients || {}).join(', ') || '–')],
  interfaces: [col('hw', t("Hardware"), (o) => o.hardwareName), col('zone', 'Zone', (o) => o.zone?.name || o.zone),
    col('ip', 'IPv4', (o) => o.ipv4?.address || o.ipv4?.ipAddress || (o.ipv4?.assignment || '')), col('enabled', t("Aktiv"), (o) => (o.enabled === false ? t("nein") : t("ja")))],
  // XML
  IPHost: [
    col('family', 'IP-Version', (o) => o.IPFamily),
    col('type', t("Host-Typ"), (o) => ({ IP: 'Host', Network: t("Netzwerk"), IPRange: t("Bereich"), IPList: t("Liste") }[o.HostType] || o.HostType)),
    col('addr', 'IP-Adresse', (o) => (o.HostType === 'Network' ? `${o.IPAddress}/${o.Subnet}` : o.HostType === 'IPRange' ? `${o.StartIPAddress} – ${o.EndIPAddress}` : o.IPAddress || o.ListOfIPAddresses || '–')),
  ],
  IPHostGroup: [col('members', t("Mitglieder"), (o) => listOf(o.HostList, 'Host').join(', ')), col('family', 'IP-Version', (o) => o.IPFamily, { hidden: true })],
  FQDNHost: [col('fqdn', 'FQDN', (o) => o.FQDN)],
  FQDNHostGroup: [col('members', t("Mitglieder"), (o) => listOf(o.FQDNHostList, 'FQDNHost').join(', '))],
  MACHost: [col('mac', 'MAC-Adresse', (o) => o.MACAddress || listOf(o.MACList, 'MACAddress').join(', '))],
  Services: [
    col('type', t("Typ"), (o) => o.Type),
    col('dport', t("Ziel-Port"), (o) => listOf(o.ServiceDetails, 'ServiceDetail').map((d) => d.DestinationPort || d.ProtocolName || d.ICMPType).filter(Boolean).join(', ')),
    col('proto', t("Protokoll"), (o) => [...new Set(listOf(o.ServiceDetails, 'ServiceDetail').map((d) => d.Protocol).filter(Boolean))].join(', ')),
  ],
  ServiceGroup: [col('members', t("Mitglieder"), (o) => listOf(o.ServiceList, 'Service').join(', '))],
  Zone: [col('type', t("Typ"), (o) => o.Type)],
  Schedule: [col('type', t("Typ"), (o) => o.Type)],
  NATRule: [col('status', t("Status"), (o) => o.Status), col('summary', t("Details"), (o) => anySummary('NATRule', o))],
  FirewallRuleGroup: [col('members', t("Regeln"), (o) => anySummary('FirewallRuleGroup', o))],
}

/** Durchsuchbarer Text eines Objekts (Name + alle Werte). */
export function searchText(o) {
  return JSON.stringify(o).toLowerCase()
}

export function ruleCells(entity, o) {
  return anyRuleView(entity, o)
}
