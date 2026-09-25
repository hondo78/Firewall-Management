import { useState } from 'react'

const SEV = { high: ['b-danger', 'Hoch'], medium: ['b-warn', 'Mittel'], info: ['', 'Info'] }
const CODE = {
  any_any: 'Zu offene Freigabe', wan_open: 'Offen aus dem Internet', no_log_wan: 'Ohne Protokollierung',
  shadowed: 'Wird nie getroffen', disabled: 'Deaktivierte Regel', unused: 'Nicht verwendet',
  duplicate_address: 'Doppelte Adresse',
}
const HINT = {
  unused: 'Geprüft wird nur die Verwendung in Firewall-/NAT-Regeln und Gruppen – nicht in VPN, Web-Filter, DHCP usw. Vor dem Löschen prüfen.',
  shadowed: 'Namensbasierte Prüfung: Eine frühere aktive Regel deckt Zonen, Netze, Dienste und Zeitplan vollständig ab.',
}

export function FindingRow({ f }) {
  return (
    <tr>
      <td><span className={`badge ${SEV[f.severity][0]}`}>{SEV[f.severity][1]}</span></td>
      <td className="small">{CODE[f.code] || f.code}</td>
      <td><b>{f.name}</b><div className="small muted">{f.label}</div></td>
      <td className="small">{f.message}</td>
    </tr>
  )
}

/** Befunde der Regel-Analyse; Info-Befunde je Art zusammengeklappt. */
export default function Findings({ findings, empty = 'Keine Auffälligkeiten.', compact }) {
  const [open, setOpen] = useState({})
  if (!findings?.length) return <div className="muted small" style={{ padding: compact ? 0 : 12 }}>{empty}</div>
  const important = findings.filter((f) => f.severity !== 'info')
  const infos = findings.filter((f) => f.severity === 'info')
  const byCode = infos.reduce((m, f) => ({ ...m, [f.code]: [...(m[f.code] || []), f] }), {})
  return (
    <div className="stack">
      {important.length > 0 && (
        <div className="table-wrap"><table>
          <tbody>{important.map((f, i) => <FindingRow key={i} f={f} />)}</tbody>
        </table></div>
      )}
      {Object.entries(byCode).map(([code, list]) => (
        <div key={code}>
          <button className="link small" onClick={() => setOpen({ ...open, [code]: !open[code] })}>
            {open[code] ? '▾' : '▸'} {CODE[code] || code}: {list.length}
          </button>
          {HINT[code] && <div className="muted small">{HINT[code]}</div>}
          {open[code] && (
            <div className="table-wrap" style={{ maxHeight: 360, overflowY: 'auto' }}><table>
              <tbody>{list.map((f, i) => <FindingRow key={i} f={f} />)}</tbody>
            </table></div>
          )}
        </div>
      ))}
    </div>
  )
}
