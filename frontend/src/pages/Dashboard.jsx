import { Link } from 'react-router-dom'
import { useAuth } from '../App'
import { api, ago, canAnywhere, crNo, fmt } from '../api'
import { Empty, ErrorBox, Progress, Status, useLoad } from '../components/ui'
import { AUDIT_LABEL } from './Audit'

export default function Dashboard() {
  const { me } = useAuth()
  const [d, error] = useLoad(() => api('/dashboard'), [])
  const [toApprove] = useLoad(() => api('/changes?to_approve=true'), [])
  const [mine] = useLoad(() => api('/changes?mine=true&limit=8'), [])
  const [fws] = useLoad(() => api('/firewalls'), [])
  if (error) return <ErrorBox error={error} />
  if (!d) return null
  const problems = (fws || []).filter((f) => f.last_sync_error || !f.last_sync_at)
  return (
    <>
      <div className="page-head">
        <h1>Übersicht</h1>
        <span className="sub">Hallo {me.display_name || me.username}</span>
      </div>
      {d.keys_expiring?.length > 0 && (
        <div className="alert warn">API-Keys laufen bald ab oder sind abgelaufen: {d.keys_expiring.map((k) => (
          <Link key={k.id} to={`/firewalls/${k.id}/settings`} style={{ marginRight: 10 }}>{k.name} ({fmt(k.expires_at).split(',')[0]})</Link>))}
          – neuen Key auf der Firewall erzeugen und in den Einstellungen eintragen.</div>
      )}
      <div className="grid tiles">
        <Link className="panel tile" to="/firewalls"><div className="num">{d.firewalls}</div><div className="lbl">Firewalls</div></Link>
        <Link className="panel tile" to="/changes?tab=approve">
          <div className="num" style={{ color: d.to_approve ? 'var(--warn)' : undefined }}>{d.to_approve}</div>
          <div className="lbl">Warten auf Ihre Genehmigung</div>
        </Link>
        <Link className="panel tile" to="/changes?tab=open"><div className="num">{d.pending}</div><div className="lbl">Offene Anträge</div></Link>
        <Link className="panel tile" to="/changes?tab=open"><div className="num">{d.approved}</div><div className="lbl">Genehmigt, noch nicht ausgerollt</div></Link>
        <Link className="panel tile" to="/changes?tab=failed">
          <div className="num" style={{ color: d.failed ? 'var(--danger)' : undefined }}>{d.failed}</div>
          <div className="lbl">Fehlgeschlagen / Konflikt</div>
        </Link>
        <Link className="panel tile" to="/firewalls">
          <div className="num" style={{ color: d.firewalls_error ? 'var(--danger)' : undefined }}>{d.firewalls_error}</div>
          <div className="lbl">Firewalls mit Sync-Fehler</div>
        </Link>
      </div>

      <div className="grid two" style={{ marginTop: 16 }}>
        <div className="panel">
          <div className="panel-head"><h3>Zu genehmigen</h3><Link className="right small" to="/changes?tab=approve">alle</Link></div>
          {!toApprove?.length ? <Empty>Nichts zu tun.</Empty> : (
            <table><tbody>
              {toApprove.slice(0, 8).map((c) => (
                <tr key={c.id}>
                  <td className="nowrap"><Link to={`/changes/${c.id}`}>{crNo(c.number)}</Link></td>
                  <td>{c.title}<div className="small muted">{c.firewall} · von {c.created_by}</div></td>
                  <td className="nowrap"><Progress value={c.approvals} max={c.required_approvals} /></td>
                </tr>
              ))}
            </tbody></table>
          )}
        </div>
        <div className="panel">
          <div className="panel-head"><h3>Meine Anträge</h3><Link className="right small" to="/changes?tab=mine">alle</Link></div>
          {!mine?.length ? <Empty>Noch keine Anträge.</Empty> : (
            <table><tbody>
              {mine.map((c) => (
                <tr key={c.id}>
                  <td className="nowrap"><Link to={`/changes/${c.id}`}>{crNo(c.number)}</Link></td>
                  <td>{c.title}<div className="small muted">{c.firewall} · {fmt(c.submitted_at)}</div></td>
                  <td className="nowrap"><Status value={c.status} /></td>
                </tr>
              ))}
            </tbody></table>
          )}
        </div>
        {problems.length > 0 && (
          <div className="panel">
            <div className="panel-head"><h3>Firewalls mit Problemen</h3></div>
            <table><tbody>
              {problems.map((f) => (
                <tr key={f.id}>
                  <td><Link to={`/firewalls/${f.id}`}>{f.name}</Link></td>
                  <td className="small">{f.last_sync_error
                    ? <span className="text-error">{f.last_sync_error}</span>
                    : <span className="muted">noch nie synchronisiert</span>}</td>
                </tr>
              ))}
            </tbody></table>
          </div>
        )}
        {canAnywhere(me, 'audit.view') && (
          <div className="panel">
            <div className="panel-head"><h3>Letzte Aktivitäten</h3><Link className="right small" to="/audit">Audit-Log</Link></div>
            <table><tbody>
              {d.recent.map((e) => (
                <tr key={e.id}>
                  <td className="nowrap small muted">{ago(e.ts)}</td>
                  <td className="small"><b>{e.actor}</b> · {AUDIT_LABEL[e.action] || e.action}
                    {e.details?.firewall && <span className="muted"> · {e.details.firewall}</span>}
                    {e.details?.number && <span className="muted"> · {crNo(e.details.number)}</span>}</td>
                </tr>
              ))}
            </tbody></table>
          </div>
        )}
      </div>
    </>
  )
}
