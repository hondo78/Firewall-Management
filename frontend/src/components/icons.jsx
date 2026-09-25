/** Kleine Strich-Symbole (24er-Raster) für Editor, Seitenleiste und Aktionen. */
const P = {
  host: 'M3 5h18v11H3zM8 20h8M12 16v4',
  group: 'M4 4h6v6H4zM14 4h6v6h-6zM9 14h6v6H9zM7 10v2h10v-2M12 12v2',
  globe: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18',
  cloud: 'M17.5 19a4.5 4.5 0 1 0-1.4-8.78A6 6 0 1 0 6 17.2M6 19h11.5',
  mac: 'M4 6h16v10H4zM2 20h20',
  wrench: 'M14.7 6.3a4 4 0 0 0-5.4 5.4L3 18l3 3 6.3-6.3a4 4 0 0 0 5.4-5.4l-2.5 2.5-2.4-.6-.6-2.4z',
  services: 'M4 6h16M4 12h16M4 18h10',
  flag: 'M5 21V4h11l-1.5 4L16 12H5',
  clock: 'M12 7v5l3 2M21 12a9 9 0 1 1-9-9 9 9 0 0 1 9 9z',
  shield: 'M12 2l8 4v6c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10V6z',
  rule: 'M12 2l8 4v6c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10V6zM9 12l2 2 4-4',
  nat: 'M4 7h13l-3-3M20 17H7l3 3',
  zone: 'M12 2l8 4v6c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10V6z',
  edit: 'M4 20h4L19 9l-4-4L4 16zM13 7l4 4',
  trash: 'M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13',
  power: 'M12 3v9M6.3 6.3a8 8 0 1 0 11.4 0',
  up: 'M12 19V5M5 12l7-7 7 7',
  down: 'M12 5v14M19 12l-7 7-7-7',
  code: 'M8 8l-4 4 4 4M16 8l4 4-4 4',
  search: 'M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14zM21 21l-5-5',
  upload: 'M12 16V4M7 9l5-5 5 5M4 20h16',
  download: 'M12 4v12M7 11l5 5 5-5M4 20h16',
  eye: 'M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12zM12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6z',
  columns: 'M4 4h16v16H4zM10 4v16M16 4v16',
  plus: 'M12 5v14M5 12h14',
  bulk: 'M4 6h10M4 12h10M4 18h6M18 14v6M15 17h6',
  x: 'M6 6l12 12M18 6L6 18',
  chevron: 'M9 6l6 6-6 6',
  menu: 'M4 6h16M4 12h16M4 18h16',
  sync: 'M20 11a8 8 0 0 0-14.3-4.9L4 8M4 4v4h4M4 13a8 8 0 0 0 14.3 4.9L20 16M20 20v-4h-4',
  bulb: 'M9 18h6M10 21h4M12 3a6 6 0 0 0-3.5 10.9V16h7v-2.1A6 6 0 0 0 12 3z',
  alert: 'M12 3l10 18H2zM12 10v5M12 18v.5',
}

export const ENTITY_ICON = {
  FirewallRule: 'rule', firewallRulesIpv4: 'rule', firewallRulesIpv6: 'rule', FirewallRuleGroup: 'group',
  NATRule: 'nat', natRulesIpv4: 'nat', IPHost: 'host', addressesIpv4: 'host', addressesIpv6: 'host',
  IPHostGroup: 'group', addressGroupsIpv4: 'group', addressGroupsIpv6: 'group', FQDNHost: 'globe',
  addressesFqdn: 'globe', FQDNHostGroup: 'cloud', addressGroupsFqdn: 'cloud', MACHost: 'mac', addressesMac: 'mac',
  countryGroups: 'flag', Services: 'wrench', services: 'wrench', ServiceGroup: 'services', serviceGroups: 'services',
  Zone: 'zone', zones: 'zone', Schedule: 'clock', schedules: 'clock',
}

export default function Icon({ name, size = 16, className, title }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"
      strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden={title ? undefined : 'true'}>
      {title && <title>{title}</title>}
      <path d={P[name] || P.host} />
    </svg>
  )
}
