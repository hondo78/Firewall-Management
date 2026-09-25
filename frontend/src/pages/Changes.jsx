import { useState } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { api, crNo, fmt } from '../api'
import { Empty, ErrorBox, Progress, Status, Tabs, useLoad } from '../components/ui'

const TABS = {
  approve: { label: 'Zu genehmigen', query: 'to_approve=true' },
  open: { label: 'Offen', query: 'status=pending,approved,deploying' },
  mine: { label: 'Meine', query: 'mine=true' },
  failed: { label: 'Fehlgeschlagen', query: 'status=failed,conflict' },
  all: { label: 'Alle', query: '' },
}

export default function Changes() {
  const [params, setParams] = useSearchParams()
  const nav = useNavigate()
  const tab = params.get('tab') || 'approve'
  const [q, setQ] = useState('')
  const [rows, error] = useLoad(() => api(`/changes?${TABS[tab].query}${q ? `&q=${encodeURIComponent(q)}` : ''}`), [tab, q])
  const [drafts] = useLoad(() => api('/changes/drafts'), [])

  return (
    <>
      <div className="page-head">
        <h1>Änderungsanträge</h1>
        <span className="sub">Jede Konfigurationsänderung wird von einer zweiten Person geprüft</span>
        <input className="right" placeholder="Titel, Ticket, Begründung …" value={q} onChange={(e) => setQ(e.target.value)} style={{ width: 240 }} />
      </div>
      {drafts?.length > 0 && (
        <div className="alert info small">
          Nicht eingereichte Entwürfe: {drafts.map((d) => <Link key={d.id} to={`/firewalls/${d.firewall_id}`} style={{ marginRight: 10 }}>{d.firewall} ({d.operations_count})</Link>)}
        </div>
      )}
      <Tabs tabs={Object.entries(TABS).map(([k, v]) => [k, v.label])} value={tab} onChange={(t) => setParams({ tab: t })} />
      <ErrorBox error={error} />
      {rows && (!rows.length ? <div className="panel"><Empty>{tab === 'approve' ? 'Keine Anträge warten auf Ihre Genehmigung.' : 'Keine Anträge.'}</Empty></div> : (
        <div className="panel table-wrap">
          <table>
            <thead><tr><th>Nr.</th><th>Titel</th><th>Firewall</th><th>Antragsteller</th><th>Status</th><th>Genehmigungen</th><th>Eingereicht</th></tr></thead>
            <tbody>
              {rows.map((c) => (
                <tr key={c.id} className="clickable" onClick={() => nav(`/changes/${c.id}`)}>
                  <td className="nowrap"><Link to={`/changes/${c.id}`} onClick={(e) => e.stopPropagation()}>{crNo(c.number)}</Link></td>
                  <td>{c.title}{c.expires_at && <span className="badge b-info" style={{ marginLeft: 6 }} title={`bis ${fmt(c.expires_at)}`}>befristet</span>}
                    {c.reverts_id && <span className="badge" style={{ marginLeft: 6 }}>Rücknahme</span>}
                    {c.batch_id && <span className="badge b-accent" style={{ marginLeft: 6 }}>Sammelantrag</span>}
                    <div className="small muted">{c.operations_count} Änderung(en){c.ticket_ref && ` · ${c.ticket_ref}`}</div></td>
                  <td>{c.firewall}</td>
                  <td>{c.created_by}</td>
                  <td><Status value={c.status} />{c.deploy_after && c.status === 'approved' && <div className="small muted">ab {fmt(c.deploy_after)}</div>}</td>
                  <td><Progress value={c.approvals} max={c.required_approvals} /> <span className="small muted">{c.approvals}/{c.required_approvals}</span></td>
                  <td className="small nowrap">{fmt(c.submitted_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ))}
    </>
  )
}
