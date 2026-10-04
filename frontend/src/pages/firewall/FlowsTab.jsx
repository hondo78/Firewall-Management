import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { api, can, fmt } from '../../api'
import { useAuth } from '../../App'
import { Empty, ErrorBox, Field, Modal, Seg, useLoad } from '../../components/ui'
import { t } from '../../i18n'
import { Pager, store, usePaging } from './tableParts'

/**
 * Verbindungsanalyse: Verbindungen aus den Syslog-Firewall-Logs eines Zeitraums als Netzwerkplan und Tabelle.
 * Verbindungen werden als legitim / nicht legitim eingestuft; daraus entsteht eine Regel-Vorlage (Präfix wählbar),
 * die wie jede Vorlage über einen Antrag mit Vier-Augen-Prinzip ausgerollt wird.
 */

const PRESETS = [['1h', t("1 Stunde"), 1], ['24h', t("24 Stunden"), 24], ['7d', t("7 Tage"), 168], ['30d', t("30 Tage"), 720], ['custom', t("Zeitraum …"), 0]]
const VERDICT = { legit: [t("legitim"), 'b-ok'], illegit: [t("nicht legitim"), 'b-danger'] }
const COLOR = { legit: 'var(--ok)', illegit: 'var(--danger)', open: 'var(--muted)' }
const PLAN_MAX = 250

const local = (d) => { const x = new Date(d); x.setMinutes(x.getMinutes() - x.getTimezoneOffset()); return x.toISOString().slice(0, 16) }
const label = (e, side) => e[`${side}_name`] || e[side]
const port = (e) => (e.dst_port ? `${e.protocol}/${e.dst_port}` : e.protocol)
const size = (b) => (b > 1e9 ? `${(b / 1e9).toFixed(1)} GB` : b > 1e6 ? `${(b / 1e6).toFixed(1)} MB` : b > 1e3 ? `${(b / 1e3).toFixed(0)} kB` : `${b} B`)
/** Externe Zone(n): WAN, bei mehreren Uplinks auch Varianten wie „WAN2“ */
const isWan = (zone) => /^wan/i.test(zone || '')
const ref = (e) => ({ src: e.src, dst: e.dst, protocol: e.protocol, dst_port: e.dst_port })

/** Zonen von links nach rechts: intern zuerst, WAN zuletzt */
function zoneOrder(zones) {
  const rank = (z) => (z === 'LAN' ? 0 : z === 'WAN' ? 9 : /dmz/i.test(z) ? 2 : z === '–' ? 8 : 1)
  return [...zones].sort((a, b) => rank(a) - rank(b) || a.localeCompare(b))
}

/** Eine Linie je Host-Paar (Zone + Adresse auf beiden Seiten); die Ports stehen an der Linie und im Untermenü. */
function pairsOf(edges) {
  const map = new Map()
  edges.forEach((e) => {
    const k = `${e.src_zone || '–'}|${e.src}|${e.dst_zone || '–'}|${e.dst}`
    const p = map.get(k) || { key: k, src: e.src, dst: e.dst, src_name: e.src_name, dst_name: e.dst_name,
      src_zone: e.src_zone || '–', dst_zone: e.dst_zone || '–', count: 0, edges: [] }
    p.count += e.count
    p.edges.push(e)
    map.set(k, p)
  })
  map.forEach((p) => {
    p.edges.sort((a, b) => b.count - a.count)
    const v = new Set(p.edges.map((e) => e.verdict || 'open'))
    p.state = v.has('illegit') ? 'illegit' : v.size === 1 && v.has('legit') ? 'legit' : v.has('legit') ? 'mixed' : 'open'
    p.denied = p.edges.every((e) => e.action === 'deny')
    const ports = [...new Set(p.edges.map(port))]
    p.label = ports.slice(0, 2).join(', ') + (ports.length > 2 ? ` +${ports.length - 2}` : '')
  })
  return [...map.values()].sort((a, b) => b.count - a.count)
}

const PAIR_COLOR = { ...COLOR, mixed: 'var(--warn)' }

function Plan({ edges, selected, openPair, onOpenPair, onToggleMany }) {
  const allPairs = useMemo(() => pairsOf(edges), [edges])
  const pairs = allPairs.slice(0, PLAN_MAX)
  const { nodes, columns, height } = useMemo(() => {
    const byKey = new Map()
    const add = (zone, addr, name, count, keys) => {
      const k = `${zone}|${addr}`
      const n = byKey.get(k) || { key: k, zone, addr, name, count: 0, edges: [] }
      n.count += count
      n.edges.push(...keys)
      byKey.set(k, n)
      return n
    }
    pairs.forEach((p) => {
      const keys = p.edges.map((e) => e.key)
      add(p.src_zone, p.src, p.src_name, p.count, keys)
      add(p.dst_zone, p.dst, p.dst_name, p.count, keys)
    })
    const cols = zoneOrder(new Set([...byKey.values()].map((n) => n.zone)))
    let maxRows = 0
    cols.forEach((z, ci) => {
      const list = [...byKey.values()].filter((n) => n.zone === z).sort((a, b) => b.count - a.count)
      list.forEach((n, ri) => { n.x = 40 + ci * 340; n.y = 56 + ri * 46 })
      maxRows = Math.max(maxRows, list.length)
    })
    return { nodes: byKey, columns: cols, height: 80 + maxRows * 46 }
  }, [pairs])
  const W = 190
  const H = 34
  const width = Math.max(columns.length * 340, 600)
  const geo = (p) => {
    const s = nodes.get(`${p.src_zone}|${p.src}`)
    const d = nodes.get(`${p.dst_zone}|${p.dst}`)
    const sy = s.y + H / 2
    const dy = d.y + H / 2
    let pts
    if (d.x > s.x) pts = [s.x + W, sy, s.x + W + 80, sy, d.x - 80, dy, d.x, dy]
    else if (d.x < s.x) pts = [s.x, sy, s.x - 80, sy, d.x + W + 80, dy, d.x + W, dy]
    else pts = [s.x + W, sy, s.x + W + 70, sy, d.x + W + 70, dy, d.x + W, dy]
    const [x0, y0, x1, y1, x2, y2, x3, y3] = pts
    // Mitte der Bézierkurve (t = 0,5) für die Port-Beschriftung
    const mx = (x0 + 3 * x1 + 3 * x2 + x3) / 8
    const my = (y0 + 3 * y1 + 3 * y2 + y3) / 8
    return { d: `M${x0},${y0} C${x1},${y1} ${x2},${y2} ${x3},${y3}`, mx, my }
  }
  const labelled = new Set(pairs.slice(0, 40).map((p) => p.key))
  return (
    <div className="flow-plan">
      {allPairs.length > PLAN_MAX && <div className="muted small">{t("Der Plan zeigt die {0} häufigsten von {1} Verbindungen – Filter oder die Netz-Ebene nutzen; die Tabelle zeigt alle.", PLAN_MAX, allPairs.length)}</div>}
      <svg width={width} height={height} role="img" aria-label={t("Netzwerkplan")}>
        {columns.map((z, i) => (
          <g key={z}>
            <rect x={20 + i * 340} y={8} width={230} height={height - 16} rx={10} className="flow-zone" />
            <text x={135 + i * 340} y={32} textAnchor="middle" className="flow-zone-label">{z}</text>
          </g>
        ))}
        {pairs.map((p) => {
          const g = geo(p)
          const open = openPair === p.key
          const sel = p.edges.some((e) => selected.has(e.key))
          const dim = (openPair && !open) || (selected.size && !sel && !open)
          return (
            <g key={p.key} className="flow-edge" onClick={() => onOpenPair(open ? null : p.key)} opacity={dim ? 0.25 : 0.9}>
              <path d={g.d} fill="none" stroke="transparent" strokeWidth={12} />
              <path d={g.d} fill="none" stroke={PAIR_COLOR[p.state]} strokeWidth={(open || sel ? 3 : 1) + Math.log10(p.count + 1)}
                strokeDasharray={p.denied ? '6 4' : undefined} />
              {(labelled.has(p.key) || open) && <g transform={`translate(${g.mx},${g.my})`}>
                <rect x={-(p.label.length * 3.4) - 5} y={-9} width={p.label.length * 6.8 + 10} height={17} rx={8} className="flow-port-bg" />
                <text textAnchor="middle" y={4} className="flow-port">{p.label}</text>
              </g>}
              <title>{`${label(p, 'src')} → ${label(p, 'dst')}\n${p.edges.map((e) => `${port(e)}${e.service ? ` (${e.service})` : ''} · ${e.count}× · ${e.verdict ? VERDICT[e.verdict][0] : t("nicht eingestuft")}`).join('\n')}`}</title>
            </g>
          )
        })}
        {[...nodes.values()].map((n) => {
          const sel = n.edges.some((k) => selected.has(k))
          return (
            <g key={n.key} transform={`translate(${n.x},${n.y})`} className="flow-node" onClick={() => onToggleMany(n.edges)}>
              <rect width={W} height={H} rx={7} className={sel ? 'sel' : ''} />
              <text x={10} y={n.name ? 14 : 21} className="flow-node-name">{(n.name || n.addr).slice(0, 26)}</text>
              {n.name && <text x={10} y={28} className="flow-node-addr">{n.addr}</text>}
              <title>{`${n.name ? `${n.name} · ` : ''}${n.addr} (${n.zone}) · ${n.count}×`}</title>
            </g>
          )
        })}
      </svg>
      <div className="flow-legend small">
        <span><i style={{ background: COLOR.open }} /> {t("nicht eingestuft")}</span>
        <span><i style={{ background: COLOR.legit }} /> {t("legitim")}</span>
        <span><i style={{ background: PAIR_COLOR.mixed }} /> {t("teilweise eingestuft")}</span>
        <span><i style={{ background: COLOR.illegit }} /> {t("mind. ein Port nicht legitim")}</span>
        <span><i className="dash" /> {t("von der Firewall blockiert")}</span>
        <span className="muted">{t("Linie anklicken = Ports dieser Verbindung, Knoten anklicken = alle seine Verbindungen auswählen")}</span>
      </div>
    </div>
  )
}

/** Untermenü einer Verbindung zwischen zwei Hosts: alle Ports einzeln oder zusammen einstufen */
function PairPanel({ pair, mayClassify, onClassify, onClose }) {
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState(false)
  const run = async (edges, v) => { setBusy(true); try { await onClassify(edges, v, note) } finally { setBusy(false) } }
  return (
    <div className="flow-pair panel">
      <div className="panel-head">
        <div style={{ minWidth: 0 }}>
          <b>{label(pair, 'src')}</b> <span className="muted">→</span> <b>{label(pair, 'dst')}</b>
          <div className="muted small">{pair.src} ({pair.src_zone}) → {pair.dst} ({pair.dst_zone})</div>
        </div>
        <button className="ghost sm right" onClick={onClose} aria-label={t("Schließen")}>×</button>
      </div>
      <div className="flow-pair-body">
        <table className="no-resize">
          <thead><tr><th>{t("Port")}</th><th>{t("Anzahl")}</th><th>{t("Einstufung")}</th>{mayClassify && <th />}</tr></thead>
          <tbody>{pair.edges.map((e) => (
            <tr key={e.key + e.action}>
              <td><span className="mono">{port(e)}</span>{e.service && <div className="muted small">{e.service}</div>}
                {e.action === 'deny' && <div><span className="badge b-warn">{t("blockiert")}</span></div>}</td>
              <td className="num small">{e.count.toLocaleString()}<div className="muted">{size(e.bytes)}</div></td>
              <td>{e.verdict ? <span className={`badge ${VERDICT[e.verdict][1]}`} title={e.note || ''}>{VERDICT[e.verdict][0]}{!e.verdict_exact && ' *'}</span> : <span className="muted small">–</span>}</td>
              {mayClassify && <td className="nowrap">
                <button className="sm flow-ok" disabled={busy} title={t("legitim")} onClick={() => run([e], 'legit')}>✓</button>{' '}
                <button className="sm danger" disabled={busy} title={t("nicht legitim")} onClick={() => run([e], 'illegit')}>✕</button>{' '}
                {e.verdict && e.verdict_exact && <button className="sm ghost" disabled={busy} title={t("Einstufung entfernen")} onClick={() => run([e], null)}>↺</button>}
              </td>}
            </tr>))}
          </tbody>
        </table>
      </div>
      {mayClassify && <div className="flow-pair-foot stack">
        <input placeholder={t("Notiz (optional), z. B. Ticket oder Begründung")} value={note} onChange={(ev) => setNote(ev.target.value)} />
        <div className="row" style={{ flexWrap: 'wrap', gap: 6 }}>
          <span className="small muted">{t("Alle {0} Ports:", pair.edges.length)}</span>
          <button className="sm flow-ok" disabled={busy} onClick={() => run(pair.edges, 'legit')}>{t("legitim")}</button>
          <button className="sm danger" disabled={busy} onClick={() => run(pair.edges, 'illegit')}>{t("nicht legitim")}</button>
          <button className="sm" disabled={busy} onClick={() => run(pair.edges, null)}>{t("zurücksetzen")}</button>
        </div>
      </div>}
      <div className="muted small" style={{ padding: '0 12px 10px' }}>{t("* von einem umfassenderen Netz übernommen – „zurücksetzen“ wirkt nur auf eigene Einstufungen.")}</div>
    </div>
  )
}

function TemplateModal({ fw, range, level, prefix, onClose }) {
  const [form, setForm] = useState({ name: '', prefix, include_allow: true, include_deny: true, log_traffic: true, position: 'top', per_connection: false, level })
  const [preview, setPreview] = useState(null)
  const [done, setDone] = useState(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const set = (k) => (e) => { setForm({ ...form, [k]: e?.target ? (e.target.type === 'checkbox' ? e.target.checked : e.target.value) : e }); setPreview(null) }
  const run = async (dry) => {
    setBusy(true); setError('')
    try {
      const r = await api(`/firewalls/${fw.id}/flows/template`, { method: 'POST', body: { ...form, ...range, preview: dry } })
      dry ? setPreview(r) : setDone(r)
    } catch (e) { setError(e.message) } finally { setBusy(false) }
  }
  return (
    <Modal title={t("Regeln als Vorlage erzeugen")} onClose={onClose} wide>
      {done ? <div className="stack">
        <div className="alert ok">{t("Vorlage „{0}“ mit {1} Regeln angelegt.", done.name, done.counts.rules)}</div>
        {done.notes.map((n) => <div key={n} className="alert warn small">{n}</div>)}
        <div className="muted small">{t("Ausgerollt wird die Vorlage wie jede andere: Vorschau je Firewall, dann ein Antrag mit Vier-Augen-Freigabe.")}</div>
        <div className="modal-foot"><button onClick={onClose}>{t("Schließen")}</button>
          <Link className="button primary" to={`/templates/${done.id}?push=1`}>{t("Vorlage öffnen und ausrollen")}</Link></div>
      </div> : <div className="stack">
        <div className="muted small">{t("Aus den eingestuften Verbindungen des gewählten Zeitraums: legitime werden zu Allow-, nicht legitime zu Drop-Regeln. Je Ziel und Dienst entsteht eine Regel mit allen beobachteten Quellen – sie erlaubt nur, was tatsächlich gesehen wurde. Vorhandene Host- und Dienstobjekte werden wiederverwendet, fehlende mit dem Präfix angelegt.")}</div>
        <div className="form-grid">
          <Field label={t("Name der Vorlage")} hint={t("leer = automatisch")}><input value={form.name} onChange={set('name')} /></Field>
          <Field label={t("Präfix für Regeln und Objekte")} hint={t("Buchstaben, Ziffern, _ . - (max. 20)")}><input value={form.prefix} maxLength={20} onChange={set('prefix')} /></Field>
        </div>
        <div className="row" style={{ flexWrap: 'wrap', gap: 16 }}>
          <label className="check"><input type="checkbox" checked={form.include_allow} onChange={set('include_allow')} /><span>{t("Allow-Regeln aus legitimen Verbindungen")}</span></label>
          <label className="check"><input type="checkbox" checked={form.include_deny} onChange={set('include_deny')} /><span>{t("Drop-Regeln aus nicht legitimen Verbindungen")}</span></label>
          <label className="check"><input type="checkbox" checked={form.log_traffic} onChange={set('log_traffic')} /><span>{t("Verkehr protokollieren")}</span></label>
        </div>
        <div className="form-grid">
          <Field label={t("Position in der Regelliste")}><Seg options={[['top', t("ganz oben")], ['bottom', t("ganz unten")]]} value={form.position} onChange={set('position')} /></Field>
          <Field label={t("Granularität")}><Seg options={[[false, t("je Ziel und Dienst")], [true, t("je Verbindung")]]} value={form.per_connection} onChange={set('per_connection')} /></Field>
          <Field label={t("Adressen in den Regeln")} hint={t("Netze (/24) fassen die Regeln weiter, Hosts nur exakt die beobachteten Adressen")}>
            <Seg options={[['host', t("Hosts")], ['net', t("Netze (/24)")]]} value={form.level} onChange={set('level')} /></Field>
        </div>
        {preview && <div className="panel panel-pad stack small">
          <b>{t("{0} Regeln ({1} Allow, {2} Drop), {3} neue Objekte", preview.counts.rules, preview.counts.allow, preview.counts.deny, preview.counts.objects)}</b>
          {preview.notes.map((n) => <div key={n} className="text-warn">{n}</div>)}
          <div style={{ maxHeight: 220, overflowY: 'auto' }}>
            {preview.items.map((i) => <div key={i.entity + i.name}><span className="muted">{t(i.label)}:</span> <code>{i.name}</code></div>)}
          </div>
        </div>}
        <ErrorBox error={error} />
        <div className="modal-foot"><button onClick={onClose}>{t("Abbrechen")}</button>
          <button disabled={busy} onClick={() => run(true)}>{t("Vorschau")}</button>
          <button className="primary" disabled={busy || !preview || !preview.counts.rules} onClick={() => run(false)}>{busy ? t("Erzeuge …") : t("Vorlage anlegen")}</button></div>
      </div>}
    </Modal>
  )
}

export default function FlowsTab({ fw }) {
  const { me } = useAuth()
  const mayClassify = can(me, 'change.create', fw)
  const [preset, setPreset] = useState('24h')
  const [custom, setCustom] = useState(() => ({ start: local(Date.now() - 86400000), end: local(Date.now()) }))
  const [level, setLevel] = useState('host')
  const [view, setView] = useState('plan')
  const [verdict, setVerdict] = useState('all')
  const [action, setAction] = useState('all')
  const [q, setQ] = useState('')
  // Verbindungen von/zur WAN-Zone ausblenden (gemerkt) – übersichtlicher für den internen Verkehr
  const [hideWan, setHideWanState] = useState(() => store.get('fwm.flows.hideWan', false))
  const setHideWan = (v) => { setHideWanState(v); store.set('fwm.flows.hideWan', v) }
  const [selected, setSelected] = useState(new Set())
  const [note, setNote] = useState('')
  const [msg, setMsg] = useState(null)
  const [modal, setModal] = useState(false)
  const [tick, setTick] = useState(0)
  const range = useMemo(() => {
    if (preset === 'custom') return { start: new Date(custom.start).toISOString(), end: new Date(custom.end).toISOString() }
    const hours = PRESETS.find((p) => p[0] === preset)[2]
    const end = new Date()
    return { start: new Date(end - hours * 3600000).toISOString(), end: end.toISOString() }
  }, [preset, custom, tick]) // eslint-disable-line react-hooks/exhaustive-deps
  const [data, error] = useLoad(() => api(`/firewalls/${fw.id}/flows?${new URLSearchParams({ ...range, level })}`), [fw.id, range, level])
  const f = q.toLowerCase()
  const edges = useMemo(() => (data?.edges || []).filter((e) =>
    (verdict === 'all' || (verdict === 'open' ? !e.verdict : e.verdict === verdict))
    && (action === 'all' || e.action === action)
    && (!hideWan || (!isWan(e.src_zone) && !isWan(e.dst_zone)))
    && (!f || `${e.src} ${e.dst} ${e.src_name} ${e.dst_name} ${port(e)} ${e.service} ${e.src_zone} ${e.dst_zone}`.toLowerCase().includes(f))), [data, verdict, action, f, hideWan])
  const paging = usePaging('flows', edges.length)
  const [openPair, setOpenPair] = useState(null)
  // Paar aus den aktuellen Daten – nach dem Einstufen mit neuen Einstufungen
  const pair = useMemo(() => (openPair ? pairsOf(edges).find((p) => p.key === openPair) || null : null), [openPair, edges])
  const toggle = (k) => { const s = new Set(selected); s.has(k) ? s.delete(k) : s.add(k); setSelected(s) }
  const toggleMany = (keys) => {
    const s = new Set(selected)
    const all = keys.every((k) => s.has(k))
    keys.forEach((k) => (all ? s.delete(k) : s.add(k)))
    setSelected(s)
  }
  const classify = async (v, edgeList = null, noteText = note) => {
    const items = edgeList || (data?.edges || []).filter((e) => selected.has(e.key))
    const unique = [...new Map(items.map((e) => [e.key, ref(e)])).values()]
    try {
      const r = await api(`/firewalls/${fw.id}/flows/decisions`, { method: 'POST', body: { items: unique, verdict: v, note: noteText } })
      setMsg({ kind: 'ok', text: v ? t("{0} Verbindungen als „{1}“ eingestuft.", r.updated, VERDICT[v][0]) : t("Einstufung von {0} Verbindungen entfernt.", r.updated) })
      if (!edgeList) { setSelected(new Set()); setNote('') }
      setTick(tick + 1)
    } catch (e) { setMsg({ kind: 'error', text: e.message }) }
  }

  if (error) return <ErrorBox error={error} />
  if (!data) return <div className="muted">{t("Lade Verbindungen …")}</div>
  const noData = !data.total && !data.senders.length
  return (
    <div className="stack">
      <div className="row" style={{ flexWrap: 'wrap', gap: 10 }}>
        <Seg options={PRESETS.map(([k, l]) => [k, l])} value={preset} onChange={(v) => { setPreset(v); setSelected(new Set()) }} />
        {preset === 'custom' && <>
          <input type="datetime-local" value={custom.start} onChange={(e) => setCustom({ ...custom, start: e.target.value })} aria-label={t("Beginn")} style={{ width: 'auto' }} />
          <input type="datetime-local" value={custom.end} onChange={(e) => setCustom({ ...custom, end: e.target.value })} aria-label={t("Ende")} style={{ width: 'auto' }} />
        </>}
        <Seg options={[['host', t("Hosts")], ['net', t("Netze (/24)")]]} value={level} onChange={(v) => { setLevel(v); setSelected(new Set()) }} />
        <button className="sm" onClick={() => setTick(tick + 1)}>{t("Aktualisieren")}</button>
        <div className="right row">
          <Seg options={[['plan', t("Netzwerkplan")], ['table', t("Tabelle")]]} value={view} onChange={setView} />
          {mayClassify && <button className="primary sm" onClick={() => setModal(true)}>{t("Regeln als Vorlage erzeugen …")}</button>}
        </div>
      </div>
      <div className="row small" style={{ flexWrap: 'wrap', gap: 8 }}>
        <span className="badge">{t("{0} Verbindungen", data.total)}</span>
        <span className="badge">{t("{0} nicht eingestuft", data.counts.open)}</span>
        <span className="badge b-ok">{t("{0} legitim", data.counts.legit)}</span>
        <span className="badge b-danger">{t("{0} nicht legitim", data.counts.illegit)}</span>
        <span className="muted">{t("Letzter Log-Eingang:")} {data.last_received ? fmt(data.last_received) : t("noch keiner")}
          {data.senders.length > 0 && ` · ${t("Absender")} ${data.senders.join(', ')}`}</span>
      </div>
      {noData && <div className="alert info small stack">
        <b>{t("Noch keine Logs von dieser Firewall empfangen.")}</b>
        <div>{t("Auf der Firewall unter System services › Log settings einen Syslog-Server anlegen: IP-Adresse dieses Servers, Port {0}, Protokoll UDP oder TCP, Format „Standard syslog protocol“. Anschließend in der Log-Liste bei „Firewall“ die Firewall-Regeln (erlaubt und blockiert) für diesen Server aktivieren.", data.receiver_port || 514)}</div>
        <div>{t("Die Zuordnung geschieht über die Seriennummer im Log; ist sie hier nicht hinterlegt, unter Administration › Einstellungen › Verbindungsanalyse den Absender dieser Firewall zuordnen. In den Firewall-Regeln muss „Protokollierung“ aktiv sein, sonst gibt es keine Logs.")}</div>
      </div>}
      {!data.enabled && <div className="alert warn small">{t("Die Verbindungsanalyse ist in den Einstellungen ausgeschaltet – neue Logs werden nicht ausgewertet.")}</div>}
      {msg && <div className={`alert ${msg.kind} small`}>{msg.text}</div>}
      <div className="row small" style={{ flexWrap: 'wrap', gap: 10 }}>
        <Seg options={[['all', t("Alle")], ['open', t("Nicht eingestuft")], ['legit', t("Legitim")], ['illegit', t("Nicht legitim")]]} value={verdict} onChange={setVerdict} />
        <Seg options={[['all', t("Erlaubt + blockiert")], ['allow', t("Erlaubt")], ['deny', t("Blockiert")]]} value={action} onChange={setAction} />
        <label className="check small"><input type="checkbox" checked={hideWan} onChange={(e) => { setHideWan(e.target.checked); paging.setPage(0) }} />
          <span>{t("WAN ausblenden")}</span></label>
        <input placeholder={t("Suchen (IP, Name, Port, Zone) …")} value={q} onChange={(e) => { setQ(e.target.value); paging.setPage(0) }} style={{ flex: 1, minWidth: 200 }} />
      </div>
      {mayClassify && selected.size > 0 && <div className="panel panel-pad row flow-selbar" style={{ flexWrap: 'wrap', gap: 8 }}>
        <b>{t("{0} ausgewählt", selected.size)}</b>
        <input placeholder={t("Notiz (optional), z. B. Ticket oder Begründung")} value={note} onChange={(e) => setNote(e.target.value)} style={{ flex: 1, minWidth: 220 }} />
        <button className="sm" style={{ borderColor: 'var(--ok)', color: 'var(--ok)' }} onClick={() => classify('legit')}>{t("Legitim")}</button>
        <button className="sm danger" onClick={() => classify('illegit')}>{t("Nicht legitim")}</button>
        <button className="sm" onClick={() => classify(null)}>{t("Einstufung entfernen")}</button>
        <button className="sm ghost" onClick={() => setSelected(new Set())}>{t("Auswahl aufheben")}</button>
      </div>}
      {!edges.length ? <div className="panel"><Empty>{t("Keine Verbindungen für diese Auswahl.")}</Empty></div>
        : view === 'plan' ? <div className="flow-plan-wrap">
          <div className="panel panel-pad" style={{ minWidth: 0, flex: 1 }}>
            <Plan edges={edges} selected={selected} openPair={pair?.key} onOpenPair={setOpenPair} onToggleMany={toggleMany} /></div>
          {pair && <PairPanel key={pair.key} pair={pair} mayClassify={mayClassify} onClose={() => setOpenPair(null)}
            onClassify={(list, v, n) => classify(v, list, n)} />}
        </div>
          : <div className="panel table-wrap">
            <table>
              <thead><tr>
                <th style={{ width: 30 }}><input type="checkbox" aria-label={t("Alle auswählen")} checked={paging.slice(edges).every((e) => selected.has(e.key))}
                  onChange={() => toggleMany(paging.slice(edges).map((e) => e.key))} /></th>
                <th>{t("Quelle")}</th><th>{t("Ziel")}</th><th>{t("Dienst")}</th><th>{t("Aktion")}</th>
                <th>{t("Anzahl")}</th><th>{t("Daten")}</th><th>{t("Zuletzt")}</th><th>{t("Regel")}</th><th>{t("Einstufung")}</th>
              </tr></thead>
              <tbody>{paging.slice(edges).map((e) => (
                <tr key={e.key + e.action + e.src_zone + e.dst_zone} className={selected.has(e.key) ? 'selected' : ''} onClick={() => toggle(e.key)} style={{ cursor: 'pointer' }}>
                  <td><input type="checkbox" checked={selected.has(e.key)} readOnly aria-label={t("Auswählen")} /></td>
                  <td><b>{label(e, 'src')}</b>{e.src_name && <div className="muted small">{e.src}</div>}<div className="muted small">{e.src_zone}</div></td>
                  <td><b>{label(e, 'dst')}</b>{e.dst_name && <div className="muted small">{e.dst}</div>}<div className="muted small">{e.dst_zone}</div></td>
                  <td className="mono small">{port(e)}{e.service && <div className="muted">{e.service}</div>}</td>
                  <td>{e.action === 'deny' ? <span className="badge b-warn">{t("blockiert")}</span> : <span className="badge">{t("erlaubt")}</span>}</td>
                  <td className="num">{e.count.toLocaleString()}</td>
                  <td className="num small">{size(e.bytes)}</td>
                  <td className="small">{fmt(e.last_seen)}</td>
                  <td className="small">{e.rules.join(', ') || '–'}</td>
                  <td>{e.verdict ? <span className={`badge ${VERDICT[e.verdict][1]}`} title={e.note || ''}>{VERDICT[e.verdict][0]}{!e.verdict_exact && ' *'}</span> : <span className="muted small">–</span>}</td>
                </tr>))}
              </tbody>
            </table>
            <Pager total={edges.length} {...paging} />
            <div className="muted small" style={{ padding: '0 12px 10px' }}>{t("* Einstufung von einem umfassenderen Netz übernommen.")}</div>
          </div>}
      {modal && <TemplateModal fw={fw} range={range} level={level} prefix={data.rule_prefix} onClose={() => setModal(false)} />}
    </div>
  )
}
