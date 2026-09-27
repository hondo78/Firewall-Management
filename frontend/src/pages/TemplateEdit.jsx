import { Fragment, useEffect, useMemo, useState } from 'react'
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { api, crNo, fmt } from '../api'
import { ObjectEditor, RuleEditor } from '../components/Editors'
import { READ_ONLY_ENTITIES, RULE_TABLE_ENTITIES, anyRuleView, anySummary, oname } from '../components/entities'
import Icon, { ENTITY_ICON } from '../components/icons'
import { RestObjectEditor } from '../components/RestEditors'
import { SophosNatEditor, SophosRuleEditor } from '../components/SophosRules'
import { WafRuleEditor } from '../components/SophosWaf'
import { DiffTable, Empty, ErrorBox, Field, Modal, Status, useLoad } from '../components/ui'
import { t } from '../i18n'
import { RowMenu, store, useDismiss } from './firewall/tableParts'

/**
 * Vorlage bearbeiten: Einträge (Soll-Zustand) anlegen/ändern/entfernen, aus einer Firewall übernehmen und per
 * Antrag auf Firewalls ausrollen. Auswahllisten in den Formularen kommen von einer Referenz-Firewall gleichen Formats.
 */

const ORDERED = new Set([...RULE_TABLE_ENTITIES, 'natRulesIpv4', 'wafRules', 'NATRule'])

function summary(entity, obj) {
  if (!obj) return ''
  if (RULE_TABLE_ENTITIES.has(entity)) {
    const v = anyRuleView(entity, obj)
    const list = (x) => (x.length ? x.join(', ') : t('Beliebig'))
    return `${list(v.srcZones)} → ${list(v.dstZones)} · ${list(v.services)} · ${t({ Accept: 'Annehmen', Drop: 'Verwerfen', Reject: 'Ablehnen' }[v.action] || v.action)}`
  }
  if (entity === 'wafRules') {
    const p = obj.HTTPBasedPolicy || {}
    return `${[].concat(p.Domains?.Domain || []).join(', ')} · ${p.HostedAddress || ''}:${p.ListenPort || ''}`
  }
  try { return anySummary(entity, obj) || '' } catch { return '' }
}

function ItemEditor({ fmt: format, item, entity, label, config, onClose, onSave }) {
  const submit = (op) => { onSave({ entity: op.entity, name: op.name, action: 'ensure', data: op.data, position: op.position || item?.position || null }); return {} }
  const props = { config, onClose, onSubmit: submit }
  const obj = item?.data || null
  if (format === 'xml') {
    return entity === 'FirewallRule' ? <RuleEditor {...props} rule={obj} /> : <ObjectEditor {...props} entity={entity} label={label} object={obj} />
  }
  if (entity.startsWith('firewallRules')) return <SophosRuleEditor {...props} entity={entity} rule={obj} />
  if (entity === 'natRulesIpv4') return <SophosNatEditor {...props} entity={entity} rule={obj} />
  if (entity === 'wafRules') return <WafRuleEditor {...props} rule={obj} />
  return <RestObjectEditor {...props} entity={entity} label={label} object={obj} />
}

function PickModal({ refFw, cfg, existing, onClose, onAdd }) {
  const choices = cfg.entities.filter((e) => !READ_ONLY_ENTITIES.has(e.entity) && e.count > 0)
  const [entity, setEntity] = useState(choices[0]?.entity || '')
  const [q, setQ] = useState('')
  const [sel, setSel] = useState(new Set())
  const [withDeps, setWithDeps] = useState(true)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const objs = (cfg.objects[entity] || []).filter((o) => !o.isInternal)
  const shown = objs.filter((o) => !q || JSON.stringify(o).toLowerCase().includes(q.toLowerCase()))
  const key = (e, n) => `${e}\u0000${n}`
  const toggle = (n) => { const s = new Set(sel); s.has(key(entity, n)) ? s.delete(key(entity, n)) : s.add(key(entity, n)); setSel(s) }
  const position = (e, name) => {
    if (!ORDERED.has(e)) return null
    const names = (cfg.objects[e] || []).map(oname)
    const i = names.indexOf(name)
    return i > 0 ? { type: 'after', ref: names[i - 1] } : { type: 'top' }
  }
  const add = async () => {
    setBusy(true)
    setError('')
    try {
      const picked = [...sel].map((k) => k.split('\u0000'))
      const items = picked.map(([e, n]) => ({ entity: e, name: n, action: 'ensure', data: (cfg.objects[e] || []).find((o) => oname(o) === n), position: position(e, n) }))
      let deps = []
      if (withDeps) {
        const r = await api('/templates/dependencies', { method: 'POST', body: { firewall_id: refFw, items: picked.map(([e, n]) => ({ entity: e, name: n })) } })
        deps = r.items.map((d) => ({ entity: d.entity, name: d.name, action: 'ensure', data: d.data, position: position(d.entity, d.name) }))
      }
      // Abhängigkeiten zuerst (Objekte vor Regeln), Doppelte weglassen
      const all = [...deps, ...items].filter((i, n, arr) => arr.findIndex((x) => x.entity === i.entity && x.name === i.name) === n
        && !existing.some((x) => x.entity === i.entity && x.name === i.name))
      onAdd(all, deps.length)
    } catch (e) { setError(e.message) }
    setBusy(false)
  }
  return (
    <Modal title={t('Aus Firewall übernehmen')} onClose={onClose} wide>
      <div className="stack">
        <div className="form-grid">
          <Field label={t('Objekttyp')}>
            <select value={entity} onChange={(e) => { setEntity(e.target.value); setQ('') }}>
              {choices.map((e) => <option key={e.entity} value={e.entity}>{e.label} ({e.count})</option>)}
            </select>
          </Field>
          <Field label={t('Suchen')}><input value={q} onChange={(e) => setQ(e.target.value)} placeholder={t('Filtern …')} /></Field>
        </div>
        <div className="table-wrap" style={{ maxHeight: 380, overflowY: 'auto' }}>
          {!shown.length ? <Empty>{t('Keine Einträge.')}</Empty> : <table><tbody>
            {shown.slice(0, 500).map((o) => {
              const n = oname(o)
              const dup = existing.some((x) => x.entity === entity && x.name === n)
              return (
                <tr key={n} className={dup ? 'row-disabled' : ''}>
                  <td style={{ width: 28 }}><input type="checkbox" disabled={dup} checked={sel.has(key(entity, n))} onChange={() => toggle(n)} aria-label={t('{0} auswählen', n)} /></td>
                  <td><b>{n}</b>{dup && <span className="badge" style={{ marginLeft: 6 }}>{t('schon in der Vorlage')}</span>}</td>
                  <td className="small muted">{summary(entity, o)}</td>
                </tr>
              )
            })}
          </tbody></table>}
        </div>
        <label className="check"><input type="checkbox" checked={withDeps} onChange={(e) => setWithDeps(e.target.checked)} />
          <span>{t('Abhängigkeiten mitnehmen')} <span className="muted small">{t('(Hosts, Gruppen, Dienste, Zonen, Richtlinien, auf die die Auswahl verweist)')}</span></span></label>
        <ErrorBox error={error} />
      </div>
      <div className="modal-foot">
        <button onClick={onClose}>{t('Abbrechen')}</button>
        <button className="primary" disabled={!sel.size || busy} onClick={add}>{t('{0} übernehmen', sel.size)}</button>
      </div>
    </Modal>
  )
}

function RemoveModal({ cfg, onClose, onAdd }) {
  const choices = cfg.entities.filter((e) => !READ_ONLY_ENTITIES.has(e.entity) && !['backupSettings'].includes(e.entity))
  const [entity, setEntity] = useState(choices[0]?.entity || '')
  const [name, setName] = useState('')
  return (
    <Modal title={t('Auf den Firewalls entfernen')} onClose={onClose}>
      <div className="stack">
        <div className="muted small">{t('Beim Ausrollen wird das Objekt gelöscht, falls es auf der Firewall existiert (sonst übersprungen).')}</div>
        <Field label={t('Objekttyp')}><select value={entity} onChange={(e) => setEntity(e.target.value)}>
          {choices.map((e) => <option key={e.entity} value={e.entity}>{e.label}</option>)}</select></Field>
        <Field label={t('Name')}><input list="tpl-remove-names" value={name} onChange={(e) => setName(e.target.value)} />
          <datalist id="tpl-remove-names">{(cfg.objects[entity] || []).map((o) => <option key={oname(o)} value={oname(o)} />)}</datalist></Field>
      </div>
      <div className="modal-foot">
        <button onClick={onClose}>{t('Abbrechen')}</button>
        <button className="primary" disabled={!name.trim()} onClick={() => onAdd({ entity, name: name.trim(), action: 'remove' })}>{t('Hinzufügen')}</button>
      </div>
    </Modal>
  )
}

function AddMenu({ entities, onPick }) {
  const [open, setOpen] = useState(false)
  const ref = useDismiss(open, setOpen)
  return (
    <div className="dropdown" ref={ref}>
      <button className="primary" onClick={() => setOpen(!open)} aria-expanded={open} aria-haspopup="menu"><Icon name="plus" size={14} /> {t('Hinzufügen')} ▾</button>
      {open && <div className="dropdown-menu" role="menu" style={{ maxHeight: 380, overflowY: 'auto', minWidth: 240 }}>
        {entities.map((e) => <button key={e.entity} role="menuitem" onClick={() => { setOpen(false); onPick(e.entity) }}>
          <Icon name={ENTITY_ICON[e.entity] || 'host'} size={14} /> {e.label}</button>)}
      </div>}
    </div>
  )
}

const STATUS_LABEL = { add: t('wird angelegt'), update: t('wird geändert'), remove: t('wird gelöscht'), same: t('bereits konform'), absent: t('nicht vorhanden'), error: t('Fehler') }
const STATUS_CLASS = { add: 'b-ok', update: 'b-warn', remove: 'b-danger', same: '', absent: '', error: 'b-danger' }

function PushModal({ tpl, onClose }) {
  const nav = useNavigate()
  const [fws] = useLoad(() => api('/firewalls'), [])
  const candidates = (fws || []).filter((f) => f.capabilities.format === tpl.format && f.permissions.includes('change.create'))
  const [sel, setSel] = useState([])
  const [preview, setPreview] = useState(null)
  const [open, setOpen] = useState(null)
  const [form, setForm] = useState({ title: tpl.name, justification: '', ticket_ref: '', deploy_after: '' })
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [result, setResult] = useState(null)
  const groups = [...new Set(candidates.map((f) => f.group || ''))]
  const toggle = (id) => { setPreview(null); setSel(sel.includes(id) ? sel.filter((x) => x !== id) : [...sel, id]) }
  const runPreview = async () => {
    setBusy(true); setError('')
    try { setPreview(await api(`/templates/${tpl.id}/preview`, { method: 'POST', body: { firewall_ids: sel } })) } catch (e) { setError(e.message) }
    setBusy(false)
  }
  const blocked = preview?.firewalls.some((f) => f.errors?.length)
  const withChanges = preview?.firewalls.filter((f) => f.changes > 0) || []
  const push = async () => {
    setBusy(true); setError('')
    try {
      setResult(await api(`/templates/${tpl.id}/push`, { method: 'POST', body: { ...form, firewall_ids: withChanges.map((f) => f.firewall_id), version: tpl.version,
        deploy_after: form.deploy_after ? new Date(form.deploy_after).toISOString() : null } }))
    } catch (e) { setError(e.message) }
    setBusy(false)
  }
  if (result) return (
    <Modal title={t('Anträge eingereicht')} onClose={onClose} wide>
      <div className="stack">
        <div className="alert ok small">{t('Die Anträge warten jetzt auf die Genehmigung (Vier-Augen-Prinzip). Ausgerollt wird erst danach.')}</div>
        <table><tbody>{result.changes.map((c) => (
          <tr key={c.id}><td><Link to={`/changes/${c.id}`}>{crNo(c.number)}</Link></td><td>{c.firewall}</td><td className="small muted">{t('{0} Änderung(en)', c.operations)}</td></tr>))}
        </tbody></table>
        {result.unchanged.length > 0 && <div className="muted small">{t('Bereits konform (kein Antrag): {0}', result.unchanged.join(', '))}</div>}
      </div>
      <div className="modal-foot"><button onClick={() => nav('/changes')}>{t('Zu den Anträgen')}</button><button className="primary" onClick={onClose}>{t('Schließen')}</button></div>
    </Modal>
  )
  return (
    <Modal title={t('Vorlage „{0}“ ausrollen', tpl.name)} onClose={onClose} wide>
      <div className="stack">
        <div className="muted small">{t('Je Firewall wird verglichen: Fehlendes wird angelegt, Abweichendes angeglichen, Konformes übersprungen. Es entsteht ein (Sammel-)Antrag, der wie jede Änderung genehmigt werden muss.')}</div>
        <h3 style={{ margin: 0 }}>{t('1. Firewalls wählen')}</h3>
        {!candidates.length ? <div className="alert info small">{t('Keine Firewall mit passendem Format ({0}), für die Sie Änderungen beantragen dürfen.', tpl.format === 'rest' ? 'REST' : 'XML')}</div> : (
          <div className="stack" style={{ gap: 6 }}>
            <div className="row" style={{ flexWrap: 'wrap' }}>
              <button className="sm" onClick={() => { setPreview(null); setSel(candidates.map((f) => f.id)) }}>{t('Alle')}</button>
              {groups.filter(Boolean).map((g) => <button key={g} className="sm" onClick={() => { setPreview(null); setSel([...new Set([...sel, ...candidates.filter((f) => f.group === g).map((f) => f.id)])]) }}>+ {g}</button>)}
              <button className="sm" onClick={() => { setPreview(null); setSel([]) }}>{t('Keine')}</button>
            </div>
            <div className="perm-grid">{candidates.map((f) => (
              <label key={f.id} className="check"><input type="checkbox" checked={sel.includes(f.id)} onChange={() => toggle(f.id)} />
                <span>{f.name}{f.group && <span className="muted small"> · {f.group}</span>}{!f.last_sync_at && <span className="badge b-warn" style={{ marginLeft: 4 }}>{t('nie synchronisiert')}</span>}</span></label>))}</div>
            <div><button className="primary" disabled={!sel.length || busy} onClick={runPreview}>{busy && !preview ? t('Prüfe …') : t('Vorschau')}</button></div>
          </div>
        )}
        {preview && <>
          <h3 style={{ margin: '8px 0 0' }}>{t('2. Vorschau')}</h3>
          <table className="cs-grid">
            <thead><tr><th>{t('Firewall')}</th><th>{t('Ergebnis')}</th><th /></tr></thead>
            <tbody>{preview.firewalls.map((f) => (
              <Fragment key={f.firewall_id}>
                <tr>
                  <td><b>{f.firewall}</b></td>
                  <td>{f.errors?.length ? <span className="badge b-danger">{t('{0} Fehler', f.errors.length)}</span> : f.changes === 0
                    ? <span className="badge b-ok">{t('bereits konform')}</span>
                    : <span className="chips">{['add', 'update', 'remove'].filter((k) => f.counts[k]).map((k) => <span key={k} className={`badge ${STATUS_CLASS[k]}`}>{f.counts[k]} {STATUS_LABEL[k]}</span>)}
                      {f.counts.same > 0 && <span className="badge">{f.counts.same} {t('bereits konform')}</span>}</span>}
                    {f.warnings?.length > 0 && <div className="small text-warn" style={{ marginTop: 4 }}>⚠ {f.warnings.join(' · ')}</div>}
                    {f.errors?.map((e) => <div key={e} className="small text-error">{e}</div>)}</td>
                  <td className="actions"><button className="ghost sm" onClick={() => setOpen(open === f.firewall_id ? null : f.firewall_id)}>{open === f.firewall_id ? t('Weniger') : t('Details')}</button></td>
                </tr>
                {open === f.firewall_id && <tr><td colSpan={3}>
                  <table><tbody>{f.rows.map((r) => (
                    <Fragment key={`${r.entity}:${r.name}`}>
                      <tr><td className="small">{t(r.label)}</td><td><b>{r.name}</b></td>
                        <td><span className={`badge ${STATUS_CLASS[r.status]}`}>{STATUS_LABEL[r.status]}</span>{r.note && <div className="small muted">{r.note}</div>}</td></tr>
                      {r.diff?.length > 0 && <tr><td /><td colSpan={2}><DiffTable rows={r.diff} /></td></tr>}
                    </Fragment>))}</tbody></table>
                </td></tr>}
              </Fragment>))}</tbody>
          </table>
          {blocked && <div className="alert error small">{t('Firewalls mit Fehlern bitte abwählen oder die Vorlage anpassen – eingereicht wird nur alles oder nichts.')}</div>}
          {!blocked && withChanges.length > 0 && <>
            <h3 style={{ margin: '8px 0 0' }}>{t('3. Antrag einreichen')}</h3>
            <div className="form-grid">
              <Field label={t('Titel')}><input value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} /></Field>
              <Field label={t('Ticket-Referenz')}><input value={form.ticket_ref} onChange={(e) => setForm({ ...form, ticket_ref: e.target.value })} placeholder="CHG-1234" /></Field>
              <Field label={t('Frühestens ausrollen ab')} hint={t('leer = sofort nach Genehmigung')}>
                <input type="datetime-local" value={form.deploy_after} onChange={(e) => setForm({ ...form, deploy_after: e.target.value })} /></Field>
            </div>
            <Field label={t('Begründung')}><textarea rows={3} value={form.justification} onChange={(e) => setForm({ ...form, justification: e.target.value })}
              placeholder={t('Warum wird die Änderung benötigt? Wer hat sie angefordert?')} /></Field>
          </>}
          {!blocked && !withChanges.length && <div className="alert ok small">{t('Alle ausgewählten Firewalls entsprechen bereits der Vorlage.')}</div>}
        </>}
        <ErrorBox error={error} />
      </div>
      <div className="modal-foot">
        <button onClick={onClose}>{t('Abbrechen')}</button>
        {preview && !blocked && withChanges.length > 0 && <button className="primary" disabled={busy || !form.title.trim() || !form.justification.trim()} onClick={push}>
          {t('{0} Antrag/Anträge zur Genehmigung einreichen', withChanges.length)}</button>}
      </div>
    </Modal>
  )
}

export default function TemplateEdit() {
  const { id } = useParams()
  const [params, setParams] = useSearchParams()
  const [tpl, error, reload] = useLoad(() => api(`/templates/${id}`), [id])
  const [fws] = useLoad(() => api('/firewalls'), [])
  const [form, setForm] = useState(null)
  const [refFw, setRefFw] = useState(() => store.get(`fwm.tpl.ref.${id}`, ''))
  const [cfg, setCfg] = useState(null)
  const [edit, setEdit] = useState(null)          // {index|-1, entity}
  const [modal, setModal] = useState(null)        // 'pick' | 'remove' | 'push'
  const [msg, setMsg] = useState(null)
  const [saving, setSaving] = useState(false)

  useEffect(() => { if (tpl) setForm({ name: tpl.name, description: tpl.description, items: tpl.items.map(({ label, ...i }) => i) }) }, [tpl])
  useEffect(() => { if (params.get('push') && tpl) { setModal('push'); setParams({}, { replace: true }) } }, [params, tpl, setParams])
  const candidates = (fws || []).filter((f) => tpl && f.capabilities.format === tpl.format && f.last_sync_at)
  const ref = candidates.find((f) => f.id === refFw) || candidates[0]
  useEffect(() => {
    if (!ref) return
    api(`/firewalls/${ref.id}/config`).then((c) => setCfg({ ...c, entities: c.entities.map((e) => ({ ...e, label: t(e.label), section: t(e.section) })) })).catch((e) => setMsg({ kind: 'error', text: e.message }))
  }, [ref?.id])  // eslint-disable-line react-hooks/exhaustive-deps

  // Auswahllisten der Formulare: Referenz-Firewall + Objekte der Vorlage selbst
  const editConfig = useMemo(() => {
    const c = { ...(cfg?.objects || {}) }
    for (const it of form?.items || []) {
      if (it.action !== 'ensure' || !it.data) continue
      const list = [...(c[it.entity] || [])]
      const i = list.findIndex((o) => oname(o) === it.name)
      if (i >= 0) list[i] = it.data; else list.push(it.data)
      c[it.entity] = list
    }
    return c
  }, [cfg, form])

  if (error) return <ErrorBox error={error} />
  if (!tpl || !form) return null
  const dirty = JSON.stringify({ name: tpl.name, description: tpl.description, items: tpl.items.map(({ label, ...i }) => i) }) !== JSON.stringify(form)
  const labelOf = (e) => cfg?.entities.find((x) => x.entity === e)?.label || t(tpl.items.find((i) => i.entity === e)?.label || e)
  const setItems = (items) => setForm({ ...form, items })
  const upsert = (item, index) => {
    const items = [...form.items]
    const at = index >= 0 ? index : items.findIndex((x) => x.entity === item.entity && x.name === item.name)
    if (at >= 0) items[at] = item; else items.push(item)
    setItems(items)
  }
  const move = (i, d) => { const items = [...form.items]; [items[i], items[i + d]] = [items[i + d], items[i]]; setItems(items) }
  const save = async () => {
    setSaving(true); setMsg(null)
    try {
      await api(`/templates/${id}`, { method: 'PUT', body: { ...form, version: tpl.version } })
      await reload()
      setMsg({ kind: 'ok', text: t('Gespeichert (Version {0}).', tpl.version + 1) })
    } catch (e) { setMsg({ kind: 'error', text: e.message }) }
    setSaving(false)
  }
  const addable = (cfg?.entities || []).filter((e) => !READ_ONLY_ENTITIES.has(e.entity) && e.entity !== 'backupSettings')
  const settingsEntities = (cfg?.entities || []).filter((e) => e.entity === 'backupSettings')

  return (
    <>
      <div className="page-head">
        <div>
          <div className="small"><Link to="/templates">{t('Vorlagen')}</Link></div>
          <h1>{form.name || tpl.name} <span className="badge b-info">{tpl.format === 'rest' ? 'REST' : 'XML'}</span> <span className="muted small">v{tpl.version}</span></h1>
        </div>
        <div className="right row">
          {tpl.may_edit && <button className="primary" disabled={!dirty || saving} onClick={save}>{saving ? t('Speichere …') : t('Speichern')}</button>}
          <button className="primary" disabled={dirty || !form.items.length} title={dirty ? t('Erst speichern') : ''} onClick={() => setModal('push')}>
            <Icon name="upload" size={14} /> {t('Auf Firewalls ausrollen …')}</button>
        </div>
      </div>
      {msg && <div className={`alert ${msg.kind} small`}>{msg.text}</div>}
      {!tpl.may_edit && <div className="alert info small">{t('Nur der Ersteller oder ein Administrator kann diese Vorlage ändern. Ausrollen dürfen alle, die Änderungen beantragen dürfen.')}</div>}

      <div className="panel panel-pad stack">
        <div className="form-grid">
          <Field label={t('Name')}><input value={form.name} disabled={!tpl.may_edit} onChange={(e) => setForm({ ...form, name: e.target.value })} /></Field>
          <Field label={t('Beschreibung')}><input value={form.description} disabled={!tpl.may_edit} onChange={(e) => setForm({ ...form, description: e.target.value })} /></Field>
        </div>
        <Field label={t('Referenz-Firewall')} hint={t('Liefert die Auswahllisten (Zonen, Hosts, Dienste …) und die Objekte für „Aus Firewall übernehmen“. Auf ihr wird nichts geändert.')}>
          <select value={ref?.id || ''} onChange={(e) => { setRefFw(e.target.value); store.set(`fwm.tpl.ref.${id}`, e.target.value) }} style={{ maxWidth: 420 }}>
            {!candidates.length && <option value="">{t('– keine synchronisierte Firewall mit passendem Format –')}</option>}
            {candidates.map((f) => <option key={f.id} value={f.id}>{f.name}</option>)}
          </select>
        </Field>
      </div>

      <div className="panel" style={{ marginTop: 14 }}>
        <div className="panel-head">
          <h3>{t('Inhalt der Vorlage')} <span className="muted" style={{ fontWeight: 400 }}>({form.items.length})</span></h3>
          {tpl.may_edit && cfg && <div className="right row">
            <AddMenu entities={[...addable, ...settingsEntities]} onPick={(entity) => {
              // Einstellungen (z. B. Sicherungs-Zeitplan) gibt es nur einmal → vom Stand der Referenz-Firewall ausgehen
              if (entity === 'backupSettings') { const cur = (cfg.objects.backupSettings || [])[0]; setEdit({ index: -1, entity, item: cur ? { entity, name: oname(cur), action: 'ensure', data: cur } : null }) }
              else setEdit({ index: -1, entity, item: null })
            }} />
            <button onClick={() => setModal('pick')}><Icon name="download" size={14} /> {t('Aus Firewall übernehmen …')}</button>
            <button onClick={() => setModal('remove')}><Icon name="trash" size={14} /> {t('Entfernen auf Ziel …')}</button>
          </div>}
        </div>
        {!cfg && candidates.length > 0 && <div className="muted small" style={{ padding: 16 }}>{t('Lade Referenz-Firewall …')}</div>}
        {!form.items.length ? <Empty>{t('Die Vorlage ist leer – Einträge über „Hinzufügen“ oder „Aus Firewall übernehmen“ anlegen.')}</Empty> : (
          <div className="table-wrap">
            <table className="cs-grid">
              <thead><tr><th style={{ width: 36 }}>#</th><th>{t('Typ')}</th><th>{t('Name')}</th><th>{t('Soll')}</th><th>{t('Inhalt')}</th><th className="actions" /></tr></thead>
              <tbody>
                {form.items.map((it, i) => (
                  <tr key={`${it.entity}:${it.name}`}>
                    <td className="muted">{i + 1}</td>
                    <td className="small nowrap"><Icon name={ENTITY_ICON[it.entity] || 'host'} size={14} /> {labelOf(it.entity)}</td>
                    <td><b>{it.name}</b>{it.position && ORDERED.has(it.entity) && <div className="small muted">
                      {it.position.type === 'after' ? t('nach „{0}“', it.position.ref) : it.position.type === 'before' ? t('vor „{0}“', it.position.ref) : it.position.type === 'top' ? t('ganz oben') : t('ganz unten')}</div>}</td>
                    <td>{it.action === 'remove' ? <span className="badge b-danger">{t('entfernen')}</span> : <span className="badge b-ok">{t('anlegen/angleichen')}</span>}</td>
                    <td className="small muted">{it.action === 'ensure' ? summary(it.entity, it.data) : ''}</td>
                    <td className="actions">{tpl.may_edit && <RowMenu label={it.name} items={[
                      it.action === 'ensure' && cfg && { label: t('Bearbeiten'), icon: 'edit', onClick: () => setEdit({ index: i, entity: it.entity, item: it }) },
                      { label: t('Nach oben'), icon: 'up', disabled: i === 0, onClick: () => move(i, -1) },
                      { label: t('Nach unten'), icon: 'down', disabled: i === form.items.length - 1, onClick: () => move(i, 1) },
                      { label: t('Aus Vorlage entfernen'), icon: 'trash', danger: true, onClick: () => setItems(form.items.filter((_, j) => j !== i)) },
                    ]} />}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <div className="muted small" style={{ padding: '10px 16px' }}>{t('Reihenfolge: Einträge werden in dieser Reihenfolge angewendet – Objekte vor den Regeln, die sie verwenden.')}</div>
      </div>

      {tpl.history.length > 0 && <div className="panel" style={{ marginTop: 14 }}>
        <div className="panel-head"><h3>{t('Ausgerollt')}</h3></div>
        <div className="table-wrap"><table>
          <thead><tr><th>{t('Antrag')}</th><th>{t('Firewall')}</th><th>{t('Version')}</th><th>{t('Status')}</th><th>{t('Datum')}</th></tr></thead>
          <tbody>{tpl.history.map((h) => (
            <tr key={h.id}><td><Link to={`/changes/${h.id}`}>{crNo(h.number)}</Link></td><td>{h.firewall}</td><td>v{h.version}</td><td><Status value={h.status} /></td><td className="small">{fmt(h.created_at)}</td></tr>))}
          </tbody>
        </table></div>
      </div>}

      {edit && <ItemEditor fmt={tpl.format} item={edit.item} entity={edit.entity} label={labelOf(edit.entity)} config={editConfig}
        onClose={() => setEdit(null)} onSave={(item) => { upsert(item, edit.index); setEdit(null) }} />}
      {modal === 'pick' && cfg && <PickModal refFw={ref.id} cfg={cfg} existing={form.items} onClose={() => setModal(null)}
        onAdd={(items, deps) => { setItems([...form.items, ...items]); setModal(null); setMsg({ kind: 'ok', text: t('{0} Einträge übernommen (davon {1} Abhängigkeiten) – noch nicht gespeichert.', items.length, deps) }) }} />}
      {modal === 'remove' && cfg && <RemoveModal cfg={cfg} onClose={() => setModal(null)} onAdd={(item) => { upsert(item, -1); setModal(null) }} />}
      {modal === 'push' && <PushModal tpl={tpl} onClose={() => { setModal(null); reload() }} />}
    </>
  )
}
