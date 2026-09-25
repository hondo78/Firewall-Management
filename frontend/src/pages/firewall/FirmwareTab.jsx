import { useState } from 'react'
import { useAuth } from '../../App'
import { api, can } from '../../api'
import { Empty, ErrorBox, Field, useLoad } from '../../components/ui'

export default function FirmwareTab({ fw }) {
  const { me } = useAuth()
  const [info, error, reload] = useLoad(() => api(`/firewalls/${fw.id}/firmware`), [fw.id])
  const [version, setVersion] = useState('')
  const [at, setAt] = useState('')
  const [msg, setMsg] = useState(null)
  const mayManage = can(me, 'firmware.manage', fw)

  const schedule = async () => {
    setMsg(null)
    try {
      await api(`/firewalls/${fw.id}/firmware`, { method: 'POST', body: { version, upgrade_at: at ? new Date(at).toISOString() : null } })
      setMsg({ kind: 'ok', text: `Update auf ${version} ${at ? 'geplant' : 'gestartet'}.` })
      reload()
    } catch (e) { setMsg({ kind: 'error', text: e.message }) }
  }
  const cancel = async () => {
    try { await api(`/firewalls/${fw.id}/firmware`, { method: 'DELETE' }); setMsg({ kind: 'ok', text: 'Geplantes Update storniert.' }) } catch (e) { setMsg({ kind: 'error', text: e.message }) }
  }
  if (error) return <ErrorBox error={error} />
  if (!info) return <div className="muted">Prüfe verfügbare Versionen bei Sophos Central …</div>
  return (
    <div className="stack">
      <div className="panel panel-pad">
        <div>Installiert: <b>{info.current}</b></div>
      </div>
      <div className="panel">
        <div className="panel-head"><h3>Verfügbare Updates</h3></div>
        {!info.available.length ? <Empty>Die Firewall ist aktuell.</Empty> : (
          <div className="panel-pad stack">
            {info.available.map((v) => (
              <label key={v.version} className="check">
                <input type="radio" name="fwver" checked={version === v.version} onChange={() => setVersion(v.version)} disabled={!mayManage} />
                <span><b>{v.version}</b> {v.size && <span className="muted small">· {v.size}</span>}
                  {v.news?.length > 0 && <div className="small muted">{v.news.join(' · ')}</div>}</span>
              </label>
            ))}
            {mayManage ? <>
              <Field label="Zeitpunkt" hint="leer = sofort"><input type="datetime-local" value={at} onChange={(e) => setAt(e.target.value)} style={{ maxWidth: 260 }} /></Field>
              <div className="row">
                <button className="primary" disabled={!version} onClick={schedule}>Update {at ? 'planen' : 'starten'}</button>
                <button onClick={cancel}>Geplantes Update stornieren</button>
              </div>
            </> : <div className="muted small">Für Firmware-Updates fehlt Ihnen das Recht „firmware.manage“.</div>}
          </div>
        )}
      </div>
      {msg && <div className={`alert ${msg.kind}`}>{msg.text}</div>}
    </div>
  )
}
