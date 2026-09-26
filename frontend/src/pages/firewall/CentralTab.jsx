import { api, fmt } from '../../api'
import { Empty, ErrorBox, useLoad } from '../../components/ui'
import { t } from '../../i18n'

/** Lizenzen (Licensing API) und offene Alerts (Common API) aus Sophos Central. */
export default function CentralTab({ fw }) {
  const [info, error] = useLoad(() => api(`/firewalls/${fw.id}/central-info`), [fw.id])
  if (error) return <ErrorBox error={error} />
  if (!info) return <div className="muted">{t("Lade Daten aus Sophos Central …")}</div>
  const expired = (d) => d && new Date(d) < new Date()
  const soon = (d) => d && new Date(d) - new Date() < 60 * 86400000
  return (
    <div className="stack">
      {info.errors.map((e) => <div key={e} className="alert warn small">{e}</div>)}
      <div className="panel">
        <div className="panel-head"><h3>{t("Offene Alerts")}</h3><span className="muted small">{t("Sophos Central · product=firewall")}</span></div>
        {!info.alerts?.length ? <Empty>{t("Keine offenen Alerts.")}</Empty> : (
          <div className="table-wrap"><table>
            <thead><tr><th>{t("Schwere")}</th><th>{t("Meldung")}</th><th>{t("Kategorie")}</th><th>{t("Seit")}</th></tr></thead>
            <tbody>{info.alerts.map((a) => (
              <tr key={a.id}>
                <td><span className={`badge ${a.severity === 'high' ? 'b-danger' : a.severity === 'medium' ? 'b-warn' : 'b-info'}`}>{{ high: t("hoch"), medium: t("mittel"), low: t("niedrig") }[a.severity] || a.severity}</span></td>
                <td>{a.description || a.type}<div className="small muted mono">{a.type}</div></td>
                <td className="small">{a.category}</td>
                <td className="small nowrap">{fmt(a.raisedAt)}</td>
              </tr>))}
            </tbody>
          </table></div>
        )}
      </div>
      <div className="panel">
        <div className="panel-head"><h3>{t("Lizenzen")}</h3>{info.model_type && <span className="muted small">{info.model_type === 'virtual' ? t("Virtuell") : t("Hardware")} {t("· zuletzt gesehen")} {fmt(info.last_seen_at)}</span>}</div>
        {!info.licenses?.length ? <Empty>{t("Keine Lizenzdaten für Seriennummer")} {fw.serial || '–'}.</Empty> : (
          <div className="table-wrap"><table>
            <thead><tr><th>{t("Produkt")}</th><th>{t("Typ")}</th><th>{t("Gültig ab")}</th><th>{t("Gültig bis")}</th></tr></thead>
            <tbody>{info.licenses.map((l) => (
              <tr key={l.id}>
                <td>{l.product?.name || l.licenseIdentifier}<div className="small muted mono">{l.product?.code}</div></td>
                <td className="small">{l.type}</td>
                <td className="small">{l.startDate || '–'}</td>
                <td className="small">{l.perpetual ? t("unbegrenzt") : <span className={expired(l.endDate) ? 'text-error' : soon(l.endDate) ? 'text-warn' : ''}>{l.endDate || '–'}</span>}</td>
              </tr>))}
            </tbody>
          </table></div>
        )}
      </div>
    </div>
  )
}
