import { api } from '../../api'
import Findings from '../../components/Findings'
import { ErrorBox, useLoad } from '../../components/ui'
import { t } from '../../i18n'

/** Regel-Analyse der aktuellen Konfiguration (Stand der letzten Synchronisation). */
export default function AnalysisTab({ fw }) {
  const [data, error] = useLoad(() => api(`/firewalls/${fw.id}/analysis`), [fw.id, fw.last_sync_at])
  if (error) return <ErrorBox error={error} />
  if (!data) return <div className="muted">{t("Analysiere …")}</div>
  return (
    <div className="stack">
      <div className="row">
        <span className="badge b-danger">{data.counts.high} {t("hoch")}</span>
        <span className="badge b-warn">{data.counts.medium} {t("mittel")}</span>
        <span className="badge">{data.counts.info} {t("Hinweise")}</span>
        <span className="muted small">{t("Hinweise auf zu offene, verdeckte oder überflüssige Regeln und Objekte – keine automatische Änderung.")}</span>
      </div>
      <div className="panel panel-pad"><Findings findings={data.findings} /></div>
    </div>
  )
}
