import { useEffect, useState } from 'react'
import { useAuth } from '../../App'
import { api, can } from '../../api'
import ConfigObjectEditor from '../../components/ConfigObjectEditor'
import { READ_ONLY_ENTITIES, oname } from '../../components/entities'
import Findings, { FINDING_CODE, SEVERITY } from '../../components/Findings'
import { ErrorBox, Seg } from '../../components/ui'
import { t } from '../../i18n'

/**
 * Regel-Analyse. Ein Klick auf den Namen öffnet das Formular des Objekts; die Änderung landet im Entwurf und die
 * Konfiguration wird sofort neu bewertet (Stand inkl. Entwurf) – behobene, verbliebene und neue Befunde.
 */

const key = (f) => `${f.code}\u0000${f.message}`

function Evaluation({ ev, onClose }) {
  const Row = ({ f, cls, label }) => (
    <tr><td><span className={`badge ${cls}`}>{label}</span></td><td><span className={`badge ${SEVERITY[f.severity][0]}`}>{SEVERITY[f.severity][1]}</span></td>
      <td className="small">{FINDING_CODE[f.code] || f.code}</td><td className="small">{f.message}</td></tr>
  )
  const delta = (s) => ev.after.counts[s] - ev.before.counts[s]
  const sign = (n) => (n > 0 ? `+${n}` : `${n}`)
  const clean = !ev.remaining.length && !ev.added.length
  return (
    <div className={`panel panel-pad stack eval ${clean ? 'eval-ok' : ev.added.length ? 'eval-bad' : 'eval-mixed'}`}>
      <div className="row between">
        <h3 style={{ margin: 0 }}>{t('Neue Bewertung für „{0}“', ev.name)}</h3>
        <button className="ghost sm" onClick={onClose} aria-label={t('Schließen')}>×</button>
      </div>
      <div className="small">{clean
        ? t('Keine Befunde mehr für dieses Objekt.')
        : t('{0} behoben · {1} verbleibend · {2} neu', ev.resolved.length, ev.remaining.length, ev.added.length)}
        {ev.warnings?.length > 0 && <span className="text-warn"> · ⚠ {ev.warnings.join(' · ')}</span>}</div>
      {(ev.resolved.length + ev.remaining.length + ev.added.length) > 0 && <div className="table-wrap"><table><tbody>
        {ev.resolved.map((f) => <Row key={`r${key(f)}`} f={f} cls="b-ok" label={t('behoben')} />)}
        {ev.remaining.map((f) => <Row key={`s${key(f)}`} f={f} cls="" label={t('verbleibend')} />)}
        {ev.added.map((f) => <Row key={`n${key(f)}`} f={f} cls="b-danger" label={t('neu')} />)}
      </tbody></table></div>}
      <div className="row small" style={{ flexWrap: 'wrap' }}>
        <span className="muted">{t('Gesamt:')}</span>
        {['high', 'medium', 'info'].map((s) => (
          <span key={s} className={`badge ${SEVERITY[s][0]}`}>{SEVERITY[s][1]} {ev.before.counts[s]} → {ev.after.counts[s]}{delta(s) ? ` (${sign(delta(s))})` : ''}</span>))}
      </div>
      <div className="muted small">{t('Die Änderung liegt in Ihrem Entwurf – wirksam wird sie erst nach Einreichen und Genehmigung.')}</div>
    </div>
  )
}

export default function AnalysisTab({ fw, onDraftChanged }) {
  const { me } = useAuth()
  const mayEdit = can(me, 'change.create', fw) && !!fw.last_sync_at
  const [mode, setMode] = useState(null)          // 'draft' | 'fw'
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  const [cfg, setCfg] = useState(null)
  const [editing, setEditing] = useState(null)    // {f, entity, obj}
  const [evaluation, setEvaluation] = useState(null)

  const load = async (m) => {
    const r = await api(`/firewalls/${fw.id}/analysis${m === 'draft' ? '?with_draft=true' : ''}`)
    setData(r)
    return r
  }
  useEffect(() => {
    // Standard: mit eigenem Entwurf, falls vorhanden
    api(`/firewalls/${fw.id}/analysis?with_draft=true`).then((r) => { setMode(r.draft ? 'draft' : 'fw'); setData(r) }).catch((e) => setError(e.message))
  }, [fw.id, fw.last_sync_at])
  const switchMode = (m) => { setMode(m); setEvaluation(null); load(m).catch((e) => setError(e.message)) }
  const loadCfg = async () => {
    const c = await api(`/firewalls/${fw.id}/config`)
    setCfg(c)
    return c
  }

  // Welches Objekt gehört zum Befund? WAF-Regeln mit XML-Zugang → vollständiges WAF-Formular
  const target = (c, f) => {
    const list = c.preview[f.entity] || []
    const obj = list.find((o) => oname(o) === f.name)
    if (obj && obj.ruleType === 'waf' && fw.waf_xml) {
      const waf = (c.preview.wafRules || []).find((w) => w.Name === f.name)
      if (waf) return { entity: 'wafRules', obj: waf }
    }
    return obj ? { entity: f.entity, obj } : null
  }
  const openFor = (f) => {
    if (!mayEdit || READ_ONLY_ENTITIES.has(f.entity)) return null
    return async () => {
      setError('')
      try {
        const c = cfg || await loadCfg()
        const tg = target(c, f)
        if (!tg) { setError(t('„{0}“ ist in der Konfiguration nicht (mehr) vorhanden.', f.name)); return }
        setEditing({ f, ...tg, label: t(c.entities.find((e) => e.entity === tg.entity)?.label || tg.entity) })
      } catch (e) { setError(e.message) }
    }
  }
  const submit = async (op) => {
    const before = data
    const r = await api(`/firewalls/${fw.id}/draft/operations`, { method: 'POST', body: op })
    // Neu bewerten: Stand inkl. Entwurf
    const after = await load('draft')
    setMode('draft')
    const f = editing.f
    const mine = (d) => d.findings.filter((x) => x.entity === f.entity && x.name === f.name)
    const b = mine(before)
    const a = mine(after)
    const bk = new Set(b.map(key))
    const ak = new Set(a.map(key))
    setEvaluation({ name: f.name, before, after, warnings: r.warnings,
      resolved: b.filter((x) => !ak.has(key(x))), remaining: a.filter((x) => bk.has(key(x))), added: a.filter((x) => !bk.has(key(x))) })
    setCfg(null)          // Vorschau (inkl. Entwurf) beim nächsten Öffnen neu laden
    onDraftChanged?.()
    return r
  }

  if (error && !data) return <ErrorBox error={error} />
  if (!data) return <div className="muted">{t('Analysiere …')}</div>
  return (
    <div className="stack">
      <div className="row" style={{ flexWrap: 'wrap' }}>
        {data.draft && <Seg options={[['draft', t('Mit meinem Entwurf ({0})', data.draft.operations)], ['fw', t('Firewall (synchronisiert)')]]} value={mode} onChange={switchMode} />}
        <span className="badge b-danger">{data.counts.high} {t('hoch')}</span>
        <span className="badge b-warn">{data.counts.medium} {t('mittel')}</span>
        <span className="badge">{data.counts.info} {t('Hinweise')}</span>
        {data.baseline_counts && <span className="muted small">{t('Firewall ohne Entwurf: {0} hoch · {1} mittel · {2} Hinweise', data.baseline_counts.high, data.baseline_counts.medium, data.baseline_counts.info)}</span>}
      </div>
      <div className="muted small">{t('Hinweise auf zu offene, verdeckte oder überflüssige Regeln und Objekte – keine automatische Änderung.')}
        {mayEdit && ` ${t('Namen anklicken, um das Objekt zu bearbeiten und neu bewerten zu lassen.')}`}</div>
      <ErrorBox error={error} />
      {evaluation && <Evaluation ev={evaluation} onClose={() => setEvaluation(null)} />}
      <div className="panel panel-pad"><Findings findings={data.findings} openFor={openFor} /></div>
      {editing && <ConfigObjectEditor format={cfg?.format || (fw.connector === 'rest' ? 'rest' : 'xml')} entity={editing.entity} label={editing.label}
        config={cfg?.preview || {}} obj={editing.obj} onClose={() => setEditing(null)} onSubmit={submit} />}
    </div>
  )
}
