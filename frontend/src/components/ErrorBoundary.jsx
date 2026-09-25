import { Component } from 'react'

/** Fängt Abstürze einer Ansicht ab – statt einer weißen Seite gibt es eine Meldung mit „Neu laden“. */
export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props)
    this.state = { error: null }
  }

  static getDerivedStateFromError(error) {
    return { error }
  }

  componentDidCatch(error, info) {
    console.error('[fwm] Ansicht abgestürzt', error, info?.componentStack)
  }

  render() {
    const { error } = this.state
    if (!error) return this.props.children
    // Nach einem Update fehlen alte Programmteile → Neu laden hilft
    const stale = /dynamically imported module|Loading chunk|MIME type/i.test(String(error?.message))
    return (
      <div className="center">
        <div className="panel panel-pad stack" style={{ maxWidth: 560 }}>
          <h2 style={{ margin: 0 }}>Diese Ansicht konnte nicht angezeigt werden</h2>
          <div className="muted small">{stale
            ? 'Die Anwendung wurde aktualisiert. Bitte die Seite neu laden.'
            : 'Ein unerwarteter Fehler ist aufgetreten. Bitte neu laden; bleibt der Fehler, den Text unten an den Administrator weitergeben.'}</div>
          <pre className="xml small">{String(error?.stack || error).slice(0, 1200)}</pre>
          <div className="row">
            <button className="primary" onClick={() => window.location.reload()}>Neu laden</button>
            <button onClick={() => { this.setState({ error: null }); window.history.back() }}>Zurück</button>
          </div>
        </div>
      </div>
    )
  }
}
