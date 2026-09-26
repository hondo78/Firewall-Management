import { useMemo, useState } from 'react'
import { EditorShell } from './Editors'
import { SINGLETON_ENTITIES, asList, restRefOptions } from './entities'
import { Field, Picker, Seg } from './ui'
import { NEW_POLICY, policyForm } from './SophosPolicies'
import { NEW_WAF, WafProtectionForm, WafServerForm } from './SophosWaf'
import { t } from '../i18n'

/** Editoren für das Format der SFOS REST-API (Objekte 1:1 wie von der API geliefert). */

const toRefs = (names) => names.map((name) => ({ name }))
const refNames = (items) => asList(items).map((i) => i?.name).filter(Boolean)

// --- Objekte -------------------------------------------------------------------------------------------------

const NEW_REST = {
  addressesIpv4: { name: '', description: '', type: 'ipv4Address', ipv4Address: '' },
  addressGroupsIpv4: { name: '', description: '', ipv4Addresses: [] },
  addressesFqdn: { name: '', description: '', fqdn: '' },
  addressGroupsFqdn: { name: '', description: '', fqdns: [] },
  services: { name: '', description: '', type: 'tcpOrUdp', services: [{ protocol: 'tcp', destinationPort: { from: 443, to: 443 } }] },
  serviceGroups: { name: '', description: '', services: [] },
  zones: { name: '', type: 'lan', description: '', services: [] },
  schedules: { name: '', description: '', type: 'recurring', timeSlots: [{ dayOfWeek: 'weekdays', startTime: '08:00', endTime: '18:00' }] },
  addressesMac: { name: '', description: '', type: 'macAddress', macAddress: '' },
  addressesIpv6: { name: '', description: '', type: 'ipv6Address', ipv6Address: '' },
  ...NEW_POLICY,
  ...NEW_WAF,
}

const SFOS_DAYS = [['monday', t("Montag")], ['tuesday', t("Dienstag")], ['wednesday', t("Mittwoch")], ['thursday', t("Donnerstag")],
  ['friday', t("Freitag")], ['saturday', t("Samstag")], ['sunday', t("Sonntag")]]

/** Sicherungszeitplan der Firewall (System › Sicherung & Firmware) */
function BackupSettingsForm({ data, setData }) {
  const sc = data.schedule || { frequency: 'never' }
  const setSc = (patch) => setData({ ...data, schedule: { ...sc, ...patch } })
  const freq = sc.frequency || 'never'
  const setFreq = (f) => setSc({ frequency: f, hour: sc.hour ?? 2, minute: sc.minute ?? 0,
    dayOfWeek: f === 'weekly' ? sc.dayOfWeek || 'sunday' : null, dayOfMonth: f === 'monthly' ? sc.dayOfMonth || 1 : null })
  const time = `${String(sc.hour ?? 0).padStart(2, '0')}:${String(sc.minute ?? 0).padStart(2, '0')}`
  const ftp = data.ftp || {}
  return (
    <div className="stack">
      <Field label={t("Häufigkeit")}><Seg options={[['never', t("Nie")], ['daily', t("Täglich")], ['weekly', t("Wöchentlich")], ['monthly', t("Monatlich")]]} value={freq} onChange={setFreq} /></Field>
      {freq !== 'never' && <div className="form-grid">
        {freq === 'weekly' && <Field label={t("Wochentag")}><select value={sc.dayOfWeek || 'sunday'} onChange={(e) => setSc({ dayOfWeek: e.target.value })}>
          {SFOS_DAYS.map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select></Field>}
        {freq === 'monthly' && <Field label={t("Tag im Monat")}><input type="number" min={1} max={31} value={sc.dayOfMonth ?? 1} onChange={(e) => setSc({ dayOfMonth: Number(e.target.value) })} /></Field>}
        <Field label={t("Uhrzeit (Zeit der Firewall)")}><input type="time" value={time} onChange={(e) => { const [h, m] = e.target.value.split(':').map(Number); setSc({ hour: h, minute: m }) }} /></Field>
      </div>}
      <Field label={t("Ziel")}><Seg options={[['local', t("Lokal")], ['ftp', 'FTP-Server'], ['email', 'E-Mail']]} value={data.backupStorage || 'local'} onChange={(v) => setData({ ...data, backupStorage: v })} /></Field>
      {data.backupStorage === 'ftp' && <div className="form-grid">
        <Field label={t("FTP-Server (IP-Adresse)")}><input value={ftp.server || ''} onChange={(e) => setData({ ...data, ftp: { ...ftp, server: e.target.value } })} /></Field>
        <Field label={t("Pfad")}><input value={ftp.path || ''} onChange={(e) => setData({ ...data, ftp: { ...ftp, path: e.target.value } })} /></Field>
        <Field label={t("Benutzer")}><input value={ftp.username || ''} autoComplete="off" onChange={(e) => setData({ ...data, ftp: { ...ftp, username: e.target.value } })} /></Field>
      </div>}
      {data.backupStorage === 'ftp' && <div className="alert info small">{t("Das FTP-Passwort wird hier bewusst nicht erfasst (es stünde sonst im Antrag und im Audit-Log) – bitte direkt auf der Firewall setzen.")}</div>}
      {data.backupStorage === 'email' && <Field label={t("E-Mail-Empfänger")} hint={t("Kommagetrennt, höchstens 10")}>
        <input value={(data.emailRecipients || []).join(', ')} onChange={(e) => setData({ ...data, emailRecipients: e.target.value.split(/[,;]/).map((x) => x.trim()).filter(Boolean) })} /></Field>}
      <Field label={t("Präfix des Dateinamens")} hint={t("optional, max. 32 Zeichen")}><input maxLength={32} value={data.backupPrefix || ''} onChange={(e) => setData({ ...data, backupPrefix: e.target.value })} /></Field>
    </div>
  )
}

// Gerätezugriff je Zone (Administration › Device access in SFOS)
const ZONE_SERVICES = [['https', t("Web-Admin (HTTPS)")], ['ssh', 'SSH'], ['ping', 'Ping/Ping6'], ['ping6', 'Ping6'], ['dns', 'DNS'],
  ['userPortal', t("Benutzerportal")], ['vpnPortal', 'VPN-Portal'], ['sslVpn', t("SSL VPN")], ['ipsec', 'IPsec'], ['webProxy', t("Web-Proxy")],
  ['captivePortal', t("Captive Portal")], ['clientAuthentication', t("Client-Authentifizierung")], ['adSso', t("AD SSO")], ['radiusSso', t("RADIUS SSO")],
  ['chromebookSso', t("Chromebook SSO")], ['dynamicRouting', t("Dynamisches Routing")], ['smtpRelay', 'SMTP-Relay'], ['snmp', 'SNMP'],
  ['red', 'RED'], ['wirelessProtection', t("Wireless Protection")]]
const DAYS = [['allDays', t("Alle Tage")], ['weekdays', t("Mo–Fr")], ['weekdaysWithSaturday', t("Mo–Sa")], ['mon', t("Montag")], ['tue', t("Dienstag")],
  ['wed', t("Mittwoch")], ['thu', t("Donnerstag")], ['fri', t("Freitag")], ['sat', t("Samstag")], ['sun', t("Sonntag")]]

function ZoneForm({ data, setData, isNew }) {
  const on = new Set(refNames(data.services))
  const toggle = (k) => { const n = new Set(on); n.has(k) ? n.delete(k) : n.add(k); setData({ ...data, services: toRefs([...n]) }) }
  return (
    <div className="stack">
      <NameDesc data={data} setData={setData} isNew={isNew} />
      <Field label={t("Typ")}>
        <select value={data.type} disabled={!isNew} onChange={(e) => setData({ ...data, type: e.target.value })}>
          <option value="lan">LAN</option><option value="dmz">DMZ</option>
          {!['lan', 'dmz'].includes(data.type) && <option value={data.type}>{data.type}</option>}
        </select>
      </Field>
      <div><b className="small">{t("Gerätezugriff")}</b> <span className="muted small">{t("– welche Dienste der Firewall aus dieser Zone erreichbar sind")}</span></div>
      <div className="sf-checks">{ZONE_SERVICES.map(([k, l]) => (
        <label key={k} className="check"><input type="checkbox" checked={on.has(k)} onChange={() => toggle(k)} />{l}</label>))}</div>
    </div>
  )
}

function ScheduleForm({ data, setData, isNew }) {
  const slots = asList(data.timeSlots)
  const setSlots = (t) => setData({ ...data, timeSlots: t })
  const upd = (i, k, v) => setSlots(slots.map((s, j) => (j === i ? { ...s, [k]: v } : s)))
  return (
    <div className="stack">
      <NameDesc data={data} setData={setData} isNew={isNew} />
      <Field label={t("Typ")}><Seg options={[['recurring', t("Wiederkehrend")], ['oneTime', t("Einmalig")]]} value={data.type} onChange={(t) => setData({ ...data, type: t })} /></Field>
      {data.type === 'oneTime' && <div className="form-grid">
        <Field label={t("Von (Datum)")}><input type="date" value={data.startDate || ''} onChange={(e) => setData({ ...data, startDate: e.target.value })} /></Field>
        <Field label={t("Bis (Datum)")}><input type="date" value={data.endDate || ''} onChange={(e) => setData({ ...data, endDate: e.target.value })} /></Field>
      </div>}
      <table><thead><tr><th>{t("Tage")}</th><th>{t("Von")}</th><th>{t("Bis")}</th><th /></tr></thead><tbody>
        {slots.map((t, i) => (
          <tr key={i}>
            <td><select value={t.dayOfWeek} onChange={(e) => upd(i, 'dayOfWeek', e.target.value)}>{DAYS.map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select></td>
            <td><input type="time" value={t.startTime} onChange={(e) => upd(i, 'startTime', e.target.value)} /></td>
            <td><input type="time" value={t.endTime} onChange={(e) => upd(i, 'endTime', e.target.value)} /></td>
            <td><button className="ghost" disabled={slots.length === 1} onClick={() => setSlots(slots.filter((_, j) => j !== i))}>×</button></td>
          </tr>))}
      </tbody></table>
      <div><button className="sm" onClick={() => setSlots([...slots, { dayOfWeek: 'allDays', startTime: '00:00', endTime: '23:59' }])}>{t("+ Zeitfenster")}</button></div>
    </div>
  )
}

function MacForm({ data, setData, isNew }) {
  return (
    <div className="stack">
      <NameDesc data={data} setData={setData} isNew={isNew} />
      <Field label="MAC-Adresse" hint={t("z. B. AA:BB:CC:DD:EE:FF")}><input value={data.macAddress || ''} onChange={(e) => setData({ ...data, type: 'macAddress', macAddress: e.target.value })} /></Field>
    </div>
  )
}

function Ipv6Form({ data, setData, isNew }) {
  const set = (k, num) => (e) => setData({ ...data, [k]: num ? Number(e.target.value) : e.target.value })
  const setType = (t) => {
    const base = { name: data.name, description: data.description, type: t }
    if (t === 'ipv6Address') base.ipv6Address = data.ipv6Address || ''
    if (t === 'ipv6Network') Object.assign(base, { ipv6NetworkAddress: data.ipv6NetworkAddress || '', prefixLength: data.prefixLength ?? 64 })
    if (t === 'ipv6Range') Object.assign(base, { ipv6AddressStart: data.ipv6AddressStart || '', ipv6AddressEnd: data.ipv6AddressEnd || '' })
    setData(base)
  }
  return (
    <div className="stack">
      <NameDesc data={data} setData={setData} isNew={isNew} />
      <Field label={t("Typ")}><Seg options={[['ipv6Address', 'Host'], ['ipv6Network', t("Netzwerk")], ['ipv6Range', t("Bereich")]]} value={data.type} onChange={setType} /></Field>
      <div className="form-grid">
        {data.type === 'ipv6Address' && <Field label="IPv6-Adresse"><input value={data.ipv6Address || ''} onChange={set('ipv6Address')} placeholder="2001:db8::1" /></Field>}
        {data.type === 'ipv6Network' && <>
          <Field label={t("Netzadresse")}><input value={data.ipv6NetworkAddress || ''} onChange={set('ipv6NetworkAddress')} placeholder="2001:db8::" /></Field>
          <Field label={t("Präfixlänge")}><input type="number" min={0} max={128} value={data.prefixLength ?? ''} onChange={set('prefixLength', true)} /></Field>
        </>}
        {data.type === 'ipv6Range' && <>
          <Field label={t("Start")}><input value={data.ipv6AddressStart || ''} onChange={set('ipv6AddressStart')} /></Field>
          <Field label={t("Ende")}><input value={data.ipv6AddressEnd || ''} onChange={set('ipv6AddressEnd')} /></Field>
        </>}
      </div>
    </div>
  )
}

function NameDesc({ data, setData, isNew }) {
  return (
    <div className="form-grid">
      <Field label={t("Name")}><input value={data.name} disabled={!isNew} onChange={(e) => setData({ ...data, name: e.target.value })} autoFocus={isNew} maxLength={60} /></Field>
      <Field label={t("Beschreibung")}><input value={data.description || ''} onChange={(e) => setData({ ...data, description: e.target.value })} /></Field>
    </div>
  )
}

function Ipv4Form({ data, setData, isNew }) {
  const set = (k, num) => (e) => setData({ ...data, [k]: num ? Number(e.target.value) : e.target.value })
  const setType = (t) => {
    const base = { name: data.name, description: data.description, type: t }
    if (t === 'ipv4Address') base.ipv4Address = data.ipv4Address || ''
    if (t === 'ipv4Network') Object.assign(base, { ipv4NetworkAddress: data.ipv4NetworkAddress || '', cidr: data.cidr ?? 24 })
    if (t === 'ipv4Range') Object.assign(base, { ipv4AddressStart: data.ipv4AddressStart || '', ipv4AddressEnd: data.ipv4AddressEnd || '' })
    if (t === 'ipv4List') base.ipv4Addresses = data.ipv4Addresses || []
    setData(base)
  }
  return (
    <div className="stack">
      <NameDesc data={data} setData={setData} isNew={isNew} />
      <Field label={t("Typ")}><Seg options={[['ipv4Address', 'Host'], ['ipv4Network', t("Netzwerk")], ['ipv4Range', t("Bereich")], ['ipv4List', t("Liste")]]}
        value={data.type} onChange={setType} /></Field>
      <div className="form-grid">
        {data.type === 'ipv4Address' && <Field label="IPv4-Adresse"><input value={data.ipv4Address || ''} onChange={set('ipv4Address')} placeholder="10.0.0.1" /></Field>}
        {data.type === 'ipv4Network' && <>
          <Field label={t("Netzadresse")}><input value={data.ipv4NetworkAddress || ''} onChange={set('ipv4NetworkAddress')} placeholder="10.0.0.0" /></Field>
          <Field label={t("Präfixlänge (CIDR)")}><input type="number" min={0} max={32} value={data.cidr ?? ''} onChange={set('cidr', true)} /></Field>
        </>}
        {data.type === 'ipv4Range' && <>
          <Field label={t("Start")}><input value={data.ipv4AddressStart || ''} onChange={set('ipv4AddressStart')} /></Field>
          <Field label={t("Ende")}><input value={data.ipv4AddressEnd || ''} onChange={set('ipv4AddressEnd')} /></Field>
        </>}
        {data.type === 'ipv4List' && <Field label={t("Adressen")} hint={t("Kommagetrennt")}>
          <input value={asList(data.ipv4Addresses).join(', ')} onChange={(e) => setData({ ...data, ipv4Addresses: e.target.value.split(',').map((x) => x.trim()).filter(Boolean) })} /></Field>}
      </div>
    </div>
  )
}

function RestServiceForm({ data, setData, isNew, portsAsText }) {
  const rows = asList(data.services)
  const setRows = (r) => setData({ ...data, services: r })
  const portStr = (p) => (p == null ? '' : typeof p !== 'object' ? String(p) : p.from === p.to ? `${p.from}` : `${p.from}:${p.to}`)
  // Im Format der Firewall zurückschreiben: Text („443“, „8000:8080“) wie von SFOS geliefert, sonst {from, to}
  const parsePort = (v) => {
    if (!v.trim()) return undefined
    const [a, b] = v.split(/[:-]/).map((x) => Number(x.trim()))
    const to = Number.isFinite(b) ? b : a
    return portsAsText ? (a === to ? `${a}` : `${a}:${to}`) : { from: a, to }
  }
  const upd = (i, k, v) => setRows(rows.map((r, j) => {
    if (j !== i) return r
    const next = { ...r, [k]: v }
    if (v === undefined) delete next[k]
    return next
  }))
  return (
    <div className="stack">
      <NameDesc data={data} setData={setData} isNew={isNew} />
      {data.type !== 'tcpOrUdp' ? <div className="alert info small">{t("Diensttyp „")}{data.type}{t("“ – bitte im JSON-Modus bearbeiten.")}</div> : <>
        <table>
          <thead><tr><th>{t("Protokoll")}</th><th>{t("Quell-Port(s)")}</th><th>{t("Ziel-Port(s)")}</th><th /></tr></thead>
          <tbody>{rows.map((r, i) => (
            <tr key={i}>
              <td><select value={r.protocol} onChange={(e) => upd(i, 'protocol', e.target.value)}><option value="tcp">TCP</option><option value="udp">UDP</option></select></td>
              <td><input defaultValue={portStr(r.sourcePort)} placeholder={t("alle")} onBlur={(e) => upd(i, 'sourcePort', parsePort(e.target.value))} /></td>
              <td><input defaultValue={portStr(r.destinationPort)} placeholder="443 oder 8000:8080" onBlur={(e) => upd(i, 'destinationPort', parsePort(e.target.value))} /></td>
              <td><button className="ghost" disabled={rows.length === 1} onClick={() => setRows(rows.filter((_, j) => j !== i))}>×</button></td>
            </tr>))}
          </tbody>
        </table>
        <div><button className="sm" onClick={() => setRows([...rows, { protocol: 'tcp', destinationPort: portsAsText ? '80' : { from: 80, to: 80 } }])}>{t("+ Port hinzufügen")}</button></div>
      </>}
    </div>
  )
}

function RefGroupForm({ data, setData, isNew, field, options, label }) {
  return (
    <div className="stack">
      <NameDesc data={data} setData={setData} isNew={isNew} />
      <Field label={label}><Picker value={refNames(data[field])} options={options} emptyLabel={t("keine")}
        onChange={(v) => setData({ ...data, [field]: toRefs(v) })} /></Field>
    </div>
  )
}

export function RestObjectEditor({ entity, label, config, object, onClose, onSubmit }) {
  const isNew = !object
  // Liefert die Firewall Ports als Text, neue Dienste ebenso anlegen
  const portsAsText = useMemo(() => (config.services || []).some((s) => asList(s.services).some((d) => typeof d.destinationPort === 'string')), [config])
  const [data, setData] = useState(() => {
    const base = structuredClone(object || NEW_REST[entity] || { name: '' })
    if (!object && entity === 'services' && portsAsText) base.services = [{ protocol: 'tcp', sourcePort: '1:65535', destinationPort: '443' }]
    return base
  })
  const opts = useMemo(() => restRefOptions(config), [config])
  const props = { data, setData, isNew }
  const forms = {
    addressesIpv4: <Ipv4Form {...props} />,
    addressGroupsIpv4: <RefGroupForm {...props} field="ipv4Addresses" options={opts.ipv4} label={t("Mitglieder (IPv4-Adressen)")} />,
    addressesFqdn: <div className="stack"><NameDesc {...props} /><Field label="FQDN" hint={t("Wildcards wie *.example.com erlaubt")}>
      <input value={data.fqdn || ''} onChange={(e) => setData({ ...data, fqdn: e.target.value })} /></Field></div>,
    addressGroupsFqdn: <RefGroupForm {...props} field="fqdns" options={opts.fqdn} label={t("Mitglieder (FQDN-Adressen)")} />,
    services: <RestServiceForm {...props} portsAsText={portsAsText} />,
    serviceGroups: <RefGroupForm {...props} field="services" options={opts.serviceItems} label={t("Mitglieder (Dienste)")} />,
    addressGroupsIpv6: <RefGroupForm {...props} field="ipv6Addresses" options={opts.ipv6} label={t("Mitglieder (IPv6-Adressen)")} />,
    zones: <ZoneForm {...props} />,
    schedules: <ScheduleForm {...props} />,
    addressesMac: <MacForm {...props} />,
    addressesIpv6: <Ipv6Form {...props} />,
    backupSettings: <BackupSettingsForm {...props} />,
    wafServers: <WafServerForm {...props} config={config} />,
    wafProtectionPolicies: <WafProtectionForm {...props} />,
  }
  return (
    <EditorShell title={isNew ? `${label}: neu` : SINGLETON_ENTITIES.has(entity) ? `${label} bearbeiten` : t("{0} „{1}“ bearbeiten", label, object.name)} entity={entity}
      data={data} setData={setData} isNew={isNew} form={forms[entity] || policyForm(entity, props)} onClose={onClose}
      onSubmit={(payload) => onSubmit({ entity, action: isNew ? 'add' : 'update', name: payload.name, data: payload })} />
  )
}
