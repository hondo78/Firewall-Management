import { t } from '../i18n'
/** „Mehrfach hinzufügen“: eine Zeile je Objekt, optional „,Name“ (Formate wie im Sophos Config Studio). */

const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/
const MAC = /^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$/i
const FQDN = /^(\*\.)?([a-z0-9-]+\.)+[a-z]{2,}$/i

function maskToCidr(mask) {
  if (!IPV4.test(mask)) return null
  const bits = mask.split('.').map((x) => Number(x).toString(2).padStart(8, '0')).join('')
  return /^1*0*$/.test(bits) ? bits.indexOf('0') === -1 ? 32 : bits.indexOf('0') : null
}

function splitName(line) {
  const i = line.indexOf(',')
  return i === -1 ? [line.trim(), ''] : [line.slice(0, i).trim(), line.slice(i + 1).trim()]
}

export const BULK = {
  address: {
    label: t("IPv4-Adressen / Bereiche / Netze"),
    placeholder: '192.168.1.1\n10.0.0.0/24\n10.0.0.0/255.255.255.0\n172.16.0.1-172.16.0.50\n10.0.0.1+10.0.0.2+10.0.0.3,Meine Liste\n1.1.1.1,dns-server',
    help: [['192.168.1.1', t("einzelner Host")], ['10.0.0.0/24', t("Netz (CIDR)")], ['10.0.0.0/255.255.255.0', t("Netz (Maske)")],
      ['172.16.0.1-172.16.0.50', t("Bereich")], ['10.0.0.1+10.0.0.2', t("Liste (+ als Trenner)")], ['1.1.1.1,my-dns', t("mit eigenem Namen")]],
    parse(value) {
      if (value.includes('+')) {
        const ips = value.split('+').map((x) => x.trim())
        if (ips.every((x) => IPV4.test(x))) return { kind: 'list', ips }
      } else if (value.includes('-')) {
        const [a, b] = value.split('-').map((x) => x.trim())
        if (IPV4.test(a) && IPV4.test(b)) return { kind: 'range', start: a, end: b }
      } else if (value.includes('/')) {
        const [net, m] = value.split('/')
        const cidr = /^\d+$/.test(m) ? Number(m) : maskToCidr(m)
        if (IPV4.test(net) && cidr != null && cidr >= 0 && cidr <= 32) return { kind: 'network', net, cidr }
      } else if (IPV4.test(value)) return { kind: 'host', ip: value }
      throw new Error(t('keine gültige IPv4-Adresse, kein Netz/Bereich/Liste'))
    },
    build(p, name, fmt) {
      if (fmt === 'rest') {
        const base = { name, description: '' }
        if (p.kind === 'host') return { ...base, type: 'ipv4Address', ipv4Address: p.ip }
        if (p.kind === 'network') return { ...base, type: 'ipv4Network', ipv4NetworkAddress: p.net, cidr: p.cidr }
        if (p.kind === 'range') return { ...base, type: 'ipv4Range', ipv4AddressStart: p.start, ipv4AddressEnd: p.end }
        return { ...base, type: 'ipv4List', ipv4Addresses: p.ips }
      }
      const base = { Name: name, Description: '', IPFamily: 'IPv4' }
      if (p.kind === 'host') return { ...base, HostType: 'IP', IPAddress: p.ip }
      if (p.kind === 'network') {
        const mask = [0, 1, 2, 3].map((i) => (0xffffffff << (32 - p.cidr) >>> 0) >>> (24 - 8 * i) & 255).join('.')
        return { ...base, HostType: 'Network', IPAddress: p.net, Subnet: p.cidr === 0 ? '0.0.0.0' : mask }
      }
      if (p.kind === 'range') return { ...base, HostType: 'IPRange', StartIPAddress: p.start, EndIPAddress: p.end }
      return { ...base, HostType: 'IPList', ListOfIPAddresses: p.ips.join(',') }
    },
  },
  fqdn: {
    label: 'FQDN-Adressen',
    placeholder: t("updates.example.com\n*.sophos.com,Sophos-Updates"),
    help: [['host.example.com', 'FQDN'], ['*.example.com', t("mit Platzhalter")], [t("a.example.com,Mein Name"), t("mit eigenem Namen")]],
    parse(value) {
      if (!FQDN.test(value)) throw new Error(t('kein gültiger FQDN'))
      return { fqdn: value }
    },
    build: (p, name, fmt) => (fmt === 'rest' ? { name, description: '', fqdn: p.fqdn } : { Name: name, Description: '', FQDN: p.fqdn }),
  },
  mac: {
    label: 'MAC-Adressen',
    placeholder: t("AA:BB:CC:DD:EE:FF\nAA:BB:CC:DD:EE:01,Drucker"),
    help: [['AA:BB:CC:DD:EE:FF', 'MAC-Adresse'], ['AA:BB:CC:DD:EE:FF,Drucker', t("mit eigenem Namen")]],
    parse(value) {
      if (!MAC.test(value)) throw new Error(t('keine gültige MAC-Adresse'))
      return { mac: value.toUpperCase().replaceAll('-', ':') }
    },
    build: (p, name, fmt) => (fmt === 'rest' ? { name, description: '', type: 'macAddress', macAddress: p.mac }
      : { Name: name, Description: '', Type: 'MACAddress', MACAddress: p.mac }),
  },
  service: {
    label: t("Dienste (TCP/UDP)"),
    placeholder: t("tcp/443\nudp/53,DNS-intern\ntcp/8000-8080,Web-Alt\ntcp+udp/3478,STUN"),
    help: [['tcp/443', 'TCP-Port'], ['udp/53', 'UDP-Port'], ['tcp/8000-8080', t("Portbereich")], ['tcp+udp/3478', t("beide Protokolle")], [t("tcp/443,Mein Dienst"), t("mit eigenem Namen")]],
    parse(value) {
      const m = /^(tcp|udp|tcp\+udp)\/(\d{1,5})(?:[-:](\d{1,5}))?$/i.exec(value)
      if (!m) throw new Error('Format: tcp/443, udp/53, tcp/8000-8080 oder tcp+udp/3478')
      const from = Number(m[2])
      const to = m[3] ? Number(m[3]) : from
      if (from < 1 || to > 65535 || to < from) throw new Error(t('Port außerhalb von 1–65535'))
      return { protocols: m[1].toLowerCase().split('+'), from, to }
    },
    build(p, name, fmt, portsAsText) {
      const dp = p.from === p.to ? `${p.from}` : `${p.from}:${p.to}`
      if (fmt === 'rest') {
        return { name, description: '', type: 'tcpOrUdp', services: p.protocols.map((proto) => (portsAsText
          ? { protocol: proto, sourcePort: '1:65535', destinationPort: dp }
          : { protocol: proto, sourcePort: { from: 1, to: 65535 }, destinationPort: { from: p.from, to: p.to } })) }
      }
      return { Name: name, Description: '', Type: 'TCPorUDP', ServiceDetails: { ServiceDetail: p.protocols.map((proto) => (
        { SourcePort: '1:65535', DestinationPort: dp, Protocol: proto.toUpperCase() })) } }
    },
  },
}

/** Entität → Bulk-Art */
export const BULK_KIND = {
  addressesIpv4: 'address', IPHost: 'address', addressesFqdn: 'fqdn', FQDNHost: 'fqdn',
  addressesMac: 'mac', MACHost: 'mac', services: 'service', Services: 'service',
}

export function parseBulk(kind, text, fmt, portsAsText) {
  const def = BULK[kind]
  return text.split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#')).map((line) => {
    const [value, custom] = splitName(line)
    try {
      const p = def.parse(value)
      const name = (custom || value).slice(0, 60)
      if (fmt === 'rest' && (name.startsWith('#') || name.includes(','))) throw new Error('Name darf nicht mit # beginnen')
      return { line, name, data: def.build(p, name, fmt, portsAsText) }
    } catch (e) {
      return { line, error: e.message }
    }
  })
}
