import { useMemo, useState } from 'react'
import { api } from '../api'
import { asList, isRestEntity, listOf, policy, refOptions, setList, toXml } from './entities'
import { ErrorBox, Field, Modal, Picker, Seg } from './ui'
import { t } from '../i18n'

/** Formular ⇄ Experten-Ansicht (XML bzw. JSON beim REST-Format); Speichern = in den Entwurf übernehmen. */
export function EditorShell({ title, entity, data, setData, isNew, form, onClose, onSubmit, extraFoot, positionField, page }) {
  const json = isRestEntity(entity)
  const [mode, setMode] = useState(form ? 'form' : 'xml')
  const [xml, setXml] = useState(() => (form ? '' : json ? JSON.stringify(data, null, 2) : toXml(entity, data)))

  // Experten-Text → Objekt (JSON lokal, XML serverseitig wie die Firewall es liest)
  const parse = async () => {
    if (!json) return (await api('/xml/parse', { method: 'POST', body: { entity, xml } })).data
    let obj
    try { obj = JSON.parse(xml) } catch (e) { throw new Error(t('JSON ungültig: {0}', e.message)) }
    if (!obj || typeof obj !== 'object' || Array.isArray(obj) || !(obj.name || obj.Name)) throw new Error(t('Objekt benötigt ein Feld „name“ (bzw. „Name“)'))
    return obj
  }
  const [error, setError] = useState('')
  const [warnings, setWarnings] = useState([])
  const [busy, setBusy] = useState(false)

  const switchMode = async (m) => {
    setError('')
    if (m === 'xml') setXml(json ? JSON.stringify(data, null, 2) : toXml(entity, data))
    if (m === 'form' && mode === 'xml') {
      try { setData(await parse()) } catch (e) { setError(e.message); return }
    }
    setMode(m)
  }

  const submit = async () => {
    setBusy(true)
    setError('')
    try {
      let payload = data
      if (mode === 'xml') payload = await parse()
      const r = await onSubmit(payload)
      if (r?.warnings?.length) setWarnings(r.warnings)
      else onClose()
    } catch (e) { setError(e.message) } finally { setBusy(false) }
  }

  const modeSwitch = form ? <Seg options={[['form', t("Formular")], ['xml', json ? t("JSON (Experte)") : t("XML (Experte)")]]} value={mode} onChange={switchMode} />
    : <span className="muted small">{t("Für diesen Objekttyp gibt es nur den {0}-Editor.", json ? 'JSON' : 'XML')}</span>
  const hint = <span className="muted small">{isNew ? t("Neues Objekt") : t("Änderung")} {t("wird in Ihren Entwurf übernommen – erst nach Genehmigung aktiv.")}</span>
  const body = <>
      {mode === 'form' ? form : (
        <div className="stack">
          <textarea className="code" value={xml} spellCheck={false} onChange={(e) => setXml(e.target.value)} />
          <div className="muted small">{json
            ? t("Struktur wie in der SFOS REST-API (Felder id/createdAt/updatedAt werden ignoriert). Umbenennen ist nicht möglich.")
            : t("Struktur wie in der Sophos-XML-API bzw. Entities.xml. Umbenennen ist nicht möglich.")}</div>
        </div>
      )}
      {mode === 'xml' && positionField}
      <ErrorBox error={error} />
      {warnings.length > 0 && (
        <div className="alert warn small">
          {t("In den Entwurf übernommen – Hinweise:")}<ul style={{ margin: '6px 0 0', paddingLeft: 18 }}>{warnings.map((w) => <li key={w}>{w}</li>)}</ul>
        </div>
      )}
  </>
  const saveBtn = !warnings.length && <button className="primary" disabled={busy} onClick={submit}>{busy ? t("Übernehme …") : t("In Entwurf übernehmen")}</button>

  // Seitenmodus wie „Edit firewall rule“ in SFOS: ganze Fläche, fester Fuß mit Speichern/Abbrechen
  if (page) return (
    <div className="panel sf-page">
      <div className="sf-page-head">
        <h2>{title}</h2>
        <div className="right row">{modeSwitch}</div>
      </div>
      <div className="sf-page-hint">{hint}</div>
      <div className="sf-page-body">{body}</div>
      <div className="sf-page-foot">
        {saveBtn}
        <button className="link" onClick={onClose}>{warnings.length ? t("Zurück zur Liste") : t("Abbrechen")}</button>
        {extraFoot}
      </div>
    </div>
  )
  return (
    <Modal title={title} onClose={onClose} wide>
      <div className="row between" style={{ marginBottom: 12 }}>{modeSwitch}{hint}</div>
      {body}
      <div className="modal-foot">
        {extraFoot}
        <button onClick={onClose}>{warnings.length ? t("Schließen") : t("Abbrechen")}</button>
        {saveBtn}
      </div>
    </Modal>
  )
}

// --- Firewall-Regel ------------------------------------------------------------------------------------------

const NEW_RULE = {
  Name: '', Description: '', IPFamily: 'IPv4', Status: 'Enable', PolicyType: 'Network',
  NetworkPolicy: {
    Action: 'Accept', LogTraffic: 'Enable', SkipLocalDestined: 'Disable',
    SourceZones: { Zone: ['LAN'] }, DestinationZones: { Zone: ['WAN'] }, Schedule: 'All The Time',
  },
}

export function PositionField({ position, setPosition, rules, name, isNew }) {
  const others = rules.filter((r) => r !== name)
  return (
    <div className="form-grid" style={{ marginTop: 12 }}>
      <Field label={t("Position in der Regelliste")}>
        <select value={position.type} onChange={(e) => setPosition({ type: e.target.value, ref: position.ref || others[0] })}>
          {!isNew && <option value="keep">{t("Unverändert")}</option>}
          <option value="top">{t("Ganz oben")}</option>
          <option value="bottom">{t("Ganz unten")}</option>
          <option value="after">{t("Nach Regel …")}</option>
          <option value="before">{t("Vor Regel …")}</option>
        </select>
      </Field>
      {['after', 'before'].includes(position.type) && (
        <Field label={t("Bezugsregel")}>
          <select value={position.ref} onChange={(e) => setPosition({ ...position, ref: e.target.value })}>
            {others.map((r) => <option key={r}>{r}</option>)}
          </select>
        </Field>
      )}
    </div>
  )
}

export function RuleEditor({ config, rule, onClose, onSubmit }) {
  const isNew = !rule
  const [data, setData] = useState(() => structuredClone(rule || NEW_RULE))
  const [position, setPosition] = useState(isNew ? { type: 'top' } : { type: 'keep' })
  const opts = useMemo(() => refOptions(config), [config])
  const p = policy(data)
  const polKey = data.UserPolicy ? 'UserPolicy' : 'NetworkPolicy'
  const setPol = (next) => setData({ ...data, [polKey]: next })
  const setTop = (k) => (e) => setData({ ...data, [k]: e.target.value })
  const setP = (k) => (e) => setPol({ ...p, [k]: e.target.value })
  const list = (c, k) => listOf(p[c], k)

  const posField = <PositionField position={position} setPosition={setPosition} rules={opts.rules} name={data.Name} isNew={isNew} />
  const form = (
    <div className="stack">
      <div className="form-grid">
        <Field label={t("Regelname")}><input value={data.Name} disabled={!isNew} onChange={setTop('Name')} autoFocus={isNew} /></Field>
        <Field label={t("Beschreibung")}><input value={data.Description || ''} onChange={setTop('Description')} /></Field>
      </div>
      <div className="form-grid">
        <Field label={t("Aktion")}>
          <Seg options={[['Accept', t("Zulassen")], ['Drop', t("Verwerfen")], ['Reject', t("Ablehnen")]]} value={p.Action}
            onChange={(v) => setPol({ ...p, Action: v })} />
        </Field>
        <Field label={t("Status")}>
          <Seg options={[['Enable', t("Aktiv")], ['Disable', t("Inaktiv")]]} value={data.Status || 'Enable'}
            onChange={(v) => setData({ ...data, Status: v })} />
        </Field>
        <Field label={t("Protokollierung")}>
          <Seg options={[['Enable', 'An'], ['Disable', t("Aus")]]} value={p.LogTraffic || 'Disable'}
            onChange={(v) => setPol({ ...p, LogTraffic: v })} />
        </Field>
        <Field label={t("Zeitplan")}>
          <select value={p.Schedule || 'All The Time'} onChange={setP('Schedule')}>
            {[...new Set(['All The Time', ...opts.schedules])].map((s) => <option key={s}>{s}</option>)}
          </select>
        </Field>
      </div>
      {data.PolicyType === 'User' && <div className="alert info small">{t("Benutzerbasierte Regel – Benutzer/Gruppen im XML-Editor pflegen.")}</div>}
      <div className="grid two">
        <div className="panel panel-pad stack">
          <h3 style={{ margin: 0 }}>{t("Quelle")}</h3>
          <Field label={t("Zonen")}><Picker value={list('SourceZones', 'Zone')} options={opts.zones}
            onChange={(v) => setPol(setList(p, 'SourceZones', 'Zone', v))} /></Field>
          <Field label={t("Netzwerke und Geräte")}><Picker value={list('SourceNetworks', 'Network')} options={opts.networks}
            onChange={(v) => setPol(setList(p, 'SourceNetworks', 'Network', v))} /></Field>
        </div>
        <div className="panel panel-pad stack">
          <h3 style={{ margin: 0 }}>{t("Ziel")}</h3>
          <Field label={t("Zonen")}><Picker value={list('DestinationZones', 'Zone')} options={opts.zones}
            onChange={(v) => setPol(setList(p, 'DestinationZones', 'Zone', v))} /></Field>
          <Field label={t("Netzwerke")}><Picker value={list('DestinationNetworks', 'Network')} options={opts.networks}
            onChange={(v) => setPol(setList(p, 'DestinationNetworks', 'Network', v))} /></Field>
          <Field label={t("Dienste")}><Picker value={list('Services', 'Service')} options={opts.services}
            onChange={(v) => setPol(setList(p, 'Services', 'Service', v))} /></Field>
        </div>
      </div>
      {posField}
    </div>
  )

  return (
    <EditorShell title={isNew ? t("Neue Firewall-Regel") : t("Regel „{0}“ bearbeiten", rule.Name)} entity="FirewallRule"
      data={data} setData={setData} isNew={isNew} form={form} onClose={onClose} positionField={posField}
      onSubmit={(payload) => onSubmit({
        entity: 'FirewallRule', action: isNew ? 'add' : 'update', name: payload.Name, data: payload,
        position: position.type === 'keep' ? null : position,
      })} />
  )
}

// --- Hosts, Dienste, Gruppen ---------------------------------------------------------------------------------

const NEW_OBJECTS = {
  IPHost: { Name: '', Description: '', IPFamily: 'IPv4', HostType: 'IP', IPAddress: '' },
  IPHostGroup: { Name: '', Description: '', HostList: { Host: [] }, IPFamily: 'IPv4' },
  FQDNHost: { Name: '', FQDN: '', Description: '' },
  FQDNHostGroup: { Name: '', Description: '', FQDNHostList: { FQDNHost: [] } },
  Services: { Name: '', Description: '', Type: 'TCPorUDP', ServiceDetails: { ServiceDetail: [{ SourcePort: '1:65535', DestinationPort: '', Protocol: 'TCP' }] } },
  ServiceGroup: { Name: '', Description: '', ServiceList: { Service: [] } },
}

export const FORM_ENTITIES = Object.keys(NEW_OBJECTS)

function IPHostForm({ data, setData, isNew }) {
  const set = (k) => (e) => setData({ ...data, [k]: e.target.value })
  const type = data.HostType || 'IP'
  const setType = (t) => {
    const base = { Name: data.Name, Description: data.Description, IPFamily: data.IPFamily || 'IPv4', HostType: t }
    if (t === 'IP') base.IPAddress = data.IPAddress || ''
    if (t === 'Network') Object.assign(base, { IPAddress: data.IPAddress || '', Subnet: data.Subnet || '255.255.255.0' })
    if (t === 'IPRange') Object.assign(base, { StartIPAddress: data.StartIPAddress || '', EndIPAddress: data.EndIPAddress || '' })
    if (t === 'IPList') base.ListOfIPAddresses = data.ListOfIPAddresses || ''
    if (data.HostGroupList) base.HostGroupList = data.HostGroupList
    setData(base)
  }
  return (
    <div className="stack">
      <div className="form-grid">
        <Field label={t("Name")}><input value={data.Name} disabled={!isNew} onChange={set('Name')} autoFocus={isNew} /></Field>
        <Field label={t("Beschreibung")}><input value={data.Description || ''} onChange={set('Description')} /></Field>
        <Field label="IP-Version">
          <select value={data.IPFamily || 'IPv4'} onChange={set('IPFamily')}><option>IPv4</option><option>IPv6</option></select>
        </Field>
      </div>
      <Field label={t("Typ")}><Seg options={[['IP', 'IP'], ['Network', t("Netzwerk")], ['IPRange', t("Bereich")], ['IPList', t("Liste")]]}
        value={type} onChange={setType} /></Field>
      <div className="form-grid">
        {(type === 'IP' || type === 'Network') && <Field label="IP-Adresse"><input value={data.IPAddress || ''} onChange={set('IPAddress')} placeholder="10.0.0.1" /></Field>}
        {type === 'Network' && <Field label={t("Subnetzmaske")}><input value={data.Subnet || ''} onChange={set('Subnet')} placeholder="255.255.255.0" /></Field>}
        {type === 'IPRange' && <>
          <Field label={t("Start-IP")}><input value={data.StartIPAddress || ''} onChange={set('StartIPAddress')} /></Field>
          <Field label={t("End-IP")}><input value={data.EndIPAddress || ''} onChange={set('EndIPAddress')} /></Field>
        </>}
        {type === 'IPList' && <Field label="IP-Adressen" hint={t("Kommagetrennt")}><input value={data.ListOfIPAddresses || ''} onChange={set('ListOfIPAddresses')} /></Field>}
      </div>
    </div>
  )
}

function ServiceForm({ data, setData, isNew }) {
  const set = (k) => (e) => setData({ ...data, [k]: e.target.value })
  const details = listOf(data.ServiceDetails, 'ServiceDetail')
  const setDetails = (d) => setData({ ...data, ServiceDetails: { ServiceDetail: d } })
  const upd = (i, k) => (e) => setDetails(details.map((d, j) => (j === i ? { ...d, [k]: e.target.value } : d)))
  return (
    <div className="stack">
      <div className="form-grid">
        <Field label={t("Name")}><input value={data.Name} disabled={!isNew} onChange={set('Name')} autoFocus={isNew} /></Field>
        <Field label={t("Beschreibung")}><input value={data.Description || ''} onChange={set('Description')} /></Field>
      </div>
      {data.Type !== 'TCPorUDP' ? <div className="alert info small">{t("Diensttyp „")}{data.Type}{t("“ – bitte im XML-Editor bearbeiten.")}</div> : (
        <table>
          <thead><tr><th>{t("Protokoll")}</th><th>{t("Quell-Port(s)")}</th><th>{t("Ziel-Port(s)")}</th><th /></tr></thead>
          <tbody>
            {details.map((d, i) => (
              <tr key={i}>
                <td><select value={d.Protocol} onChange={upd(i, 'Protocol')}><option>TCP</option><option>UDP</option></select></td>
                <td><input value={d.SourcePort || ''} onChange={upd(i, 'SourcePort')} placeholder="1:65535" /></td>
                <td><input value={d.DestinationPort || ''} onChange={upd(i, 'DestinationPort')} placeholder="443 oder 8000:8080" /></td>
                <td><button className="ghost" disabled={details.length === 1} onClick={() => setDetails(details.filter((_, j) => j !== i))}>×</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {data.Type === 'TCPorUDP' && <div><button className="sm" onClick={() => setDetails([...details, { SourcePort: '1:65535', DestinationPort: '', Protocol: 'TCP' }])}>{t("+ Port hinzufügen")}</button></div>}
    </div>
  )
}

function GroupForm({ data, setData, isNew, container, itemKey, options, label }) {
  const set = (k) => (e) => setData({ ...data, [k]: e.target.value })
  return (
    <div className="stack">
      <div className="form-grid">
        <Field label={t("Name")}><input value={data.Name} disabled={!isNew} onChange={set('Name')} autoFocus={isNew} /></Field>
        <Field label={t("Beschreibung")}><input value={data.Description || ''} onChange={set('Description')} /></Field>
      </div>
      <Field label={label}>
        <Picker value={asList(data[container]?.[itemKey])} options={options} emptyLabel={t("keine")}
          onChange={(v) => setData({ ...data, [container]: { [itemKey]: v } })} />
      </Field>
    </div>
  )
}

function FQDNForm({ data, setData, isNew }) {
  const set = (k) => (e) => setData({ ...data, [k]: e.target.value })
  return (
    <div className="form-grid">
      <Field label={t("Name")}><input value={data.Name} disabled={!isNew} onChange={set('Name')} autoFocus={isNew} /></Field>
      <Field label="FQDN" hint={t("Wildcards wie *.example.com erlaubt")}><input value={data.FQDN || ''} onChange={set('FQDN')} /></Field>
      <Field label={t("Beschreibung")}><input value={data.Description || ''} onChange={set('Description')} /></Field>
    </div>
  )
}

export function ObjectEditor({ entity, label, config, object, onClose, onSubmit }) {
  const isNew = !object
  const [data, setData] = useState(() => structuredClone(object || NEW_OBJECTS[entity] || { Name: '' }))
  const opts = useMemo(() => refOptions(config), [config])
  const props = { data, setData, isNew }
  const forms = {
    IPHost: <IPHostForm {...props} />,
    FQDNHost: <FQDNForm {...props} />,
    Services: <ServiceForm {...props} />,
    IPHostGroup: <GroupForm {...props} container="HostList" itemKey="Host" options={opts.hosts} label={t("Mitglieder (IP-Hosts)")} />,
    ServiceGroup: <GroupForm {...props} container="ServiceList" itemKey="Service" options={opts.serviceItems} label={t("Mitglieder (Dienste)")} />,
    FQDNHostGroup: <GroupForm {...props} container="FQDNHostList" itemKey="FQDNHost" options={opts.fqdnHosts} label={t("Mitglieder (FQDN-Hosts)")} />,
  }
  return (
    <EditorShell title={isNew ? `${label}: neu` : t("{0} „{1}“ bearbeiten", label, object.Name)} entity={entity}
      data={data} setData={setData} isNew={isNew} form={forms[entity]} onClose={onClose}
      onSubmit={(payload) => onSubmit({ entity, action: isNew ? 'add' : 'update', name: payload.Name, data: payload })} />
  )
}
