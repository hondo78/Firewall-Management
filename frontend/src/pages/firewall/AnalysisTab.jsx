import { api } from '../../api'
import Findings from '../../components/Findings'
import { ErrorBox, useLoad } from '../../components/ui'

/** Regel-Analyse der aktuellen Konfiguration (Stand der letzten Synchronisation). */
export default function AnalysisTab({ fw }) {
  const [data, error] = useLoad(() => api(`/firewalls/${fw.id}/analysis`), [fw.id, fw.last_sync_at])
  if (error) return <ErrorBox error={error} />
  if (!data) return <div className="muted">Analysiere …</div>
  return (
    <div className="stack">
      <div className="row">
        <span className="badge b-danger">{data.counts.high} hoch</span>
        <span className="badge b-warn">{data.counts.medium} mittel</span>
        <span className="badge">{data.counts.info} Hinweise</span>
        <span className="muted small">Hinweise auf zu offene, verdeckte oder überflüssige Regeln und Objekte – keine automatische Änderung.</span>
      </div>
      <div className="panel panel-pad"><Findings findings={data.findings} /></div>
    </div>
  )
}
