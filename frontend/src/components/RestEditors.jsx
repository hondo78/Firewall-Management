import { useMemo, useState } from 'react'
import { EditorShell, PositionField } from './Editors'
import { asList, restNetNames, restRefOptions } from './entities'
import { Field, Picker, Seg } from './ui'

/** Editoren für das Format der SFOS REST-API (Objekte 1:1 wie von der API geliefert). */

const toRefs = (names) => names.map((name) => ({ name }))
const refNames = (items) => asList(items).map((i) => i?.name).filter(Boolean)

/** Liste von Namen → { any: true } bzw. { zones: [...] } */
function zonesValue(names) {
  return names.length ? { zones: toRefs(names) } : { any: true }
}

/** Netzwerk-Namen → { any } bzw. { ipv4Addresses: [...], fqdnGroups: [...], … } (Schlüssel aus den Optionen) */
function netsValue(names, options) {
  if (!names.length) return { any: true }
  const keyOf = Object.fromEntries(options.map((o) => [o.value, o.key]))
  const out = {}
  for (const n of names) {
    const k = keyOf[n] || 'ipv4Addresses'
    out[k] = [...(out[k] || []), { name: n }]
  }
  return out
}

function servicesValue(names, options) {
  if (!names.length) return { any: true }
  const keyOf = Object.fromEntries(options.map((o) => [o.value, o.key]))
  const out = {}
  for (const n of names) {
    const k = keyOf[n] || 'services'
    out[k] = [...(out[k] || []), { name: n }]
  }
  return out
}

function newRule(opts) {
  const find = (want) => opts.zones.find((z) => z.value.toLowerCase() === want)?.value
  const lan = find('lan')
  const wan = find('wan')
  return {
    name: '', description: '', ruleType: 'firewall', enabled: true, action: 'accept',
    sourceZones: lan ? { zones: [{ name: lan }] } : { any: true },
    destinationZones: wan ? { zones: [{ name: wan }] } : { any: true },
    sourceNetworks: { any: true }, destinationNetworks: { any: true }, servicesOrGroups: { any: true },
    logTraffic: true,
  }
}

export function RestRuleEditor({ entity, config, rule, onClose, onSubmit }) {
  const isNew = !rule
  const opts = useMemo(() => restRefOptions(config), [config])
  const rules = (config[entity] || []).map((r) => r.name)
  const [data, setData] = useState(() => structuredClone(rule || newRule(opts)))
  const [position, setPosition] = useState(isNew ? { type: 'top' } : { type: 'keep' })
  const set = (k) => (e) => setData({ ...data, [k]: e.target.value })
  const svc = data.servicesOrGroups || {}
  const isWaf = data.ruleType === 'waf'

  const posField = <PositionField position={position} setPosition={setPosition} rules={rules} name={data.name} isNew={isNew} />
  const form = isWaf ? null : (
    <div className="stack">
      <div className="form-grid">
        <Field label="Regelname"><input value={data.name} disabled={!isNew} onChange={set('name')} autoFocus={isNew} maxLength={60} /></Field>
        <Field label="Beschreibung"><input value={data.description || ''} onChange={set('description')} maxLength={255} /></Field>
      </div>
      <div className="form-grid">
        <Field label="Aktion">
          <Seg options={[['accept', 'Zulassen'], ['drop', 'Verwerfen'], ['reject', 'Ablehnen']]} value={data.action}
            onChange={(v) => setData({ ...data, action: v })} />
        </Field>
        <Field label="Status">
          <Seg options={[[true, 'Aktiv'], [false, 'Inaktiv']]} value={data.enabled !== false}
            onChange={(v) => setData({ ...data, enabled: v })} />
        </Field>
        <Field label="Protokollierung">
          <Seg options={[[true, 'An'], [false, 'Aus']]} value={!!data.logTraffic} onChange={(v) => setData({ ...data, logTraffic: v })} />
        </Field>
        <Field label="Zeitplan">
          <select value={data.schedule?.name || ''} onChange={(e) => {
            const next = { ...data }
            if (e.target.value) next.schedule = { name: e.target.value }
            else delete next.schedule
            setData(next)
          }}>
            <option value="">– immer –</option>
            {opts.schedules.map((s) => <option key={s}>{s}</option>)}
          </select>
        </Field>
      </div>
      <div className="grid two">
        <div className="panel panel-pad stack">
          <h3 style={{ margin: 0 }}>Quelle</h3>
          <Field label="Zonen"><Picker value={data.sourceZones?.any ? [] : refNames(data.sourceZones?.zones)} options={opts.zones}
            onChange={(v) => setData({ ...data, sourceZones: zonesValue(v) })} /></Field>
          <Field label="Netzwerke und Geräte"><Picker value={restNetNames(data.sourceNetworks)} options={opts.networks}
            onChange={(v) => setData({ ...data, sourceNetworks: netsValue(v, opts.networks) })} /></Field>
        </div>
        <div className="panel panel-pad stack">
          <h3 style={{ margin: 0 }}>Ziel</h3>
          <Field label="Zonen"><Picker value={data.destinationZones?.any ? [] : refNames(data.destinationZones?.zones)} options={opts.zones}
            onChange={(v) => setData({ ...data, destinationZones: zonesValue(v) })} /></Field>
          <Field label="Netzwerke"><Picker value={restNetNames(data.destinationNetworks)} options={opts.networks}
            onChange={(v) => setData({ ...data, destinationNetworks: netsValue(v, opts.networks) })} /></Field>
          <Field label="Dienste"><Picker value={svc.any ? [] : [...refNames(svc.services), ...refNames(svc.serviceGroups)]}
            options={opts.services} onChange={(v) => setData({ ...data, servicesOrGroups: servicesValue(v, opts.services) })} /></Field>
        </div>
      </div>
      <div className="muted small">Weitere Einstellungen (Sicherheitsfunktionen, QoS, Benutzer, Ausnahmen) bleiben erhalten und sind im JSON-Modus bearbeitbar.</div>
      {posField}
    </div>
  )
  return (
    <EditorShell title={isNew ? 'Neue Firewall-Regel' : `Regel „${rule.name}“ bearbeiten`} entity={entity}
      data={data} setData={setData} isNew={isNew} form={form} onClose={onClose} positionField={posField}
      onSubmit={(payload) => onSubmit({
        entity, action: isNew ? 'add' : 'update', name: payload.name, data: payload,
        position: position.type === 'keep' ? null : position,
      })} />
  )
}

// --- Objekte -------------------------------------------------------------------------------------------------

const NEW_REST = {
  addressesIpv4: { name: '', description: '', type: 'ipv4Address', ipv4Address: '' },
  addressGroupsIpv4: { name: '', description: '', ipv4Addresses: [] },
  addressesFqdn: { name: '', description: '', fqdn: '' },
  addressGroupsFqdn: { name: '', description: '', fqdns: [] },
  services: { name: '', description: '', type: 'tcpOrUdp', services: [{ protocol: 'tcp', destinationPort: { from: 443, to: 443 } }] },
  serviceGroups: { name: '', description: '', services: [] },
}
export const REST_FORM_ENTITIES = Object.keys(NEW_REST)

function NameDesc({ data, setData, isNew }) {
  return (
    <div className="form-grid">
      <Field label="Name"><input value={data.name} disabled={!isNew} onChange={(e) => setData({ ...data, name: e.target.value })} autoFocus={isNew} maxLength={60} /></Field>
      <Field label="Beschreibung"><input value={data.description || ''} onChange={(e) => setData({ ...data, description: e.target.value })} /></Field>
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
      <Field label="Typ"><Seg options={[['ipv4Address', 'Host'], ['ipv4Network', 'Netzwerk'], ['ipv4Range', 'Bereich'], ['ipv4List', 'Liste']]}
        value={data.type} onChange={setType} /></Field>
      <div className="form-grid">
        {data.type === 'ipv4Address' && <Field label="IPv4-Adresse"><input value={data.ipv4Address || ''} onChange={set('ipv4Address')} placeholder="10.0.0.1" /></Field>}
        {data.type === 'ipv4Network' && <>
          <Field label="Netzadresse"><input value={data.ipv4NetworkAddress || ''} onChange={set('ipv4NetworkAddress')} placeholder="10.0.0.0" /></Field>
          <Field label="Präfixlänge (CIDR)"><input type="number" min={0} max={32} value={data.cidr ?? ''} onChange={set('cidr', true)} /></Field>
        </>}
        {data.type === 'ipv4Range' && <>
          <Field label="Start"><input value={data.ipv4AddressStart || ''} onChange={set('ipv4AddressStart')} /></Field>
          <Field label="Ende"><input value={data.ipv4AddressEnd || ''} onChange={set('ipv4AddressEnd')} /></Field>
        </>}
        {data.type === 'ipv4List' && <Field label="Adressen" hint="Kommagetrennt">
          <input value={asList(data.ipv4Addresses).join(', ')} onChange={(e) => setData({ ...data, ipv4Addresses: e.target.value.split(',').map((x) => x.trim()).filter(Boolean) })} /></Field>}
      </div>
    </div>
  )
}

function RestServiceForm({ data, setData, isNew }) {
  const rows = asList(data.services)
  const setRows = (r) => setData({ ...data, services: r })
  const portStr = (p) => (!p ? '' : p.from === p.to ? `${p.from}` : `${p.from}:${p.to}`)
  const parsePort = (v) => {
    if (!v.trim()) return undefined
    const [a, b] = v.split(/[:-]/).map((x) => Number(x.trim()))
    return { from: a, to: Number.isFinite(b) ? b : a }
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
      {data.type !== 'tcpOrUdp' ? <div className="alert info small">Diensttyp „{data.type}“ – bitte im JSON-Modus bearbeiten.</div> : <>
        <table>
          <thead><tr><th>Protokoll</th><th>Quell-Port(s)</th><th>Ziel-Port(s)</th><th /></tr></thead>
          <tbody>{rows.map((r, i) => (
            <tr key={i}>
              <td><select value={r.protocol} onChange={(e) => upd(i, 'protocol', e.target.value)}><option value="tcp">TCP</option><option value="udp">UDP</option></select></td>
              <td><input defaultValue={portStr(r.sourcePort)} placeholder="alle" onBlur={(e) => upd(i, 'sourcePort', parsePort(e.target.value))} /></td>
              <td><input defaultValue={portStr(r.destinationPort)} placeholder="443 oder 8000:8080" onBlur={(e) => upd(i, 'destinationPort', parsePort(e.target.value))} /></td>
              <td><button className="ghost" disabled={rows.length === 1} onClick={() => setRows(rows.filter((_, j) => j !== i))}>×</button></td>
            </tr>))}
          </tbody>
        </table>
        <div><button className="sm" onClick={() => setRows([...rows, { protocol: 'tcp', destinationPort: { from: 80, to: 80 } }])}>+ Port hinzufügen</button></div>
      </>}
    </div>
  )
}

function RefGroupForm({ data, setData, isNew, field, options, label }) {
  return (
    <div className="stack">
      <NameDesc data={data} setData={setData} isNew={isNew} />
      <Field label={label}><Picker value={refNames(data[field])} options={options} emptyLabel="keine"
        onChange={(v) => setData({ ...data, [field]: toRefs(v) })} /></Field>
    </div>
  )
}

export function RestObjectEditor({ entity, label, config, object, onClose, onSubmit }) {
  const isNew = !object
  const [data, setData] = useState(() => structuredClone(object || NEW_REST[entity] || { name: '' }))
  const opts = useMemo(() => restRefOptions(config), [config])
  const props = { data, setData, isNew }
  const forms = {
    addressesIpv4: <Ipv4Form {...props} />,
    addressGroupsIpv4: <RefGroupForm {...props} field="ipv4Addresses" options={opts.ipv4} label="Mitglieder (IPv4-Adressen)" />,
    addressesFqdn: <div className="stack"><NameDesc {...props} /><Field label="FQDN" hint="Wildcards wie *.example.com erlaubt">
      <input value={data.fqdn || ''} onChange={(e) => setData({ ...data, fqdn: e.target.value })} /></Field></div>,
    addressGroupsFqdn: <RefGroupForm {...props} field="fqdns" options={opts.fqdn} label="Mitglieder (FQDN-Adressen)" />,
    services: <RestServiceForm {...props} />,
    serviceGroups: <RefGroupForm {...props} field="services" options={opts.serviceItems} label="Mitglieder (Dienste)" />,
  }
  return (
    <EditorShell title={isNew ? `${label}: neu` : `${label} „${object.name}“ bearbeiten`} entity={entity}
      data={data} setData={setData} isNew={isNew} form={forms[entity]} onClose={onClose}
      onSubmit={(payload) => onSubmit({ entity, action: isNew ? 'add' : 'update', name: payload.name, data: payload })} />
  )
}
