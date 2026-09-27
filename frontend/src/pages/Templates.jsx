import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { api, fmt } from '../api'
import { Empty, ErrorBox, Field, Modal, useLoad } from '../components/ui'
import { t } from '../i18n'

/** Vorlagen: Soll-Zustand für Objekte, Regeln und Einstellungen – editierbar, per Antrag auf Firewalls ausrollbar. */

function NewTemplateModal({ onClose }) {
  const nav = useNavigate()
  const [form, setForm] = useState({ name: '', description: '', format: 'rest' })
  const [error, setError] = useState('')
  const create = async () => {
    try {
      const tpl = await api('/templates', { method: 'POST', body: { ...form, items: [] } })
      nav(`/templates/${tpl.id}`)
    } catch (e) { setError(e.message) }
  }
  return (
    <Modal title={t('Neue Vorlage')} onClose={onClose}>
      <div className="stack">
        <Field label={t('Name')}><input autoFocus value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder={t('z. B. Filial-Standard')} /></Field>
        <Field label={t('Beschreibung')}><input value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} /></Field>
        <Field label={t('Format')} hint={t('Vorlagen passen nur auf Firewalls mit gleicher Anbindung')}>
          <select value={form.format} onChange={(e) => setForm({ ...form, format: e.target.value })}>
            <option value="rest">{t('SFOS REST-API')}</option>
            <option value="xml">{t('XML-API / Sophos Central (Entities.xml)')}</option>
          </select>
        </Field>
        <div className="muted small">{t('Tipp: Eine Vorlage lässt sich auch aus einem Entwurf speichern (Leiste „Entwurf“ im Konfigurations-Editor).')}</div>
        <ErrorBox error={error} />
      </div>
      <div className="modal-foot">
        <button onClick={onClose}>{t('Abbrechen')}</button>
        <button className="primary" disabled={!form.name.trim()} onClick={create}>{t('Anlegen')}</button>
      </div>
    </Modal>
  )
}

export default function Templates() {
  const [list, error, reload] = useLoad(() => api('/templates'), [])
  const [creating, setCreating] = useState(false)
  const [confirm, setConfirm] = useState(null)
  const remove = async (tpl) => {
    try { await api(`/templates/${tpl.id}`, { method: 'DELETE' }); setConfirm(null); reload() } catch (e) { alertError(e) }
  }
  const [delError, setDelError] = useState('')
  const alertError = (e) => setDelError(e.message)
  return (
    <>
      <div className="page-head">
        <div><h1>{t('Vorlagen')}</h1>
          <div className="muted small">{t('Standard-Regeln, Objekte und Einstellungen einmal pflegen und per Antrag auf beliebige Firewalls ausrollen – mit Vier-Augen-Freigabe.')}</div></div>
        <button className="primary right" onClick={() => setCreating(true)}>{t('Neue Vorlage')}</button>
      </div>
      <ErrorBox error={error || delError} />
      {list && (!list.length ? <div className="panel"><Empty>{t('Noch keine Vorlagen.')}</Empty></div> : (
        <div className="panel table-wrap">
          <table>
            <thead><tr><th>{t('Name')}</th><th>{t('Format')}</th><th>{t('Einträge')}</th><th>{t('Version')}</th><th>{t('Zuletzt geändert')}</th><th className="actions" /></tr></thead>
            <tbody>
              {list.map((tpl) => (
                <tr key={tpl.id}>
                  <td><Link to={`/templates/${tpl.id}`}><b>{tpl.name}</b></Link>{tpl.description && <div className="small muted">{tpl.description}</div>}</td>
                  <td><span className="badge b-info">{tpl.format === 'rest' ? 'REST' : 'XML'}</span></td>
                  <td className="small">{tpl.items.length}
                    <div className="muted">{[...new Set(tpl.items.map((i) => t(i.label)))].slice(0, 3).join(', ')}</div></td>
                  <td>v{tpl.version}</td>
                  <td className="small">{fmt(tpl.updated_at || tpl.created_at)}<div className="muted">{tpl.updated_by || tpl.created_by || '–'}</div></td>
                  <td className="actions nowrap">
                    <Link className="button sm" to={`/templates/${tpl.id}`}>{tpl.may_edit ? t('Bearbeiten') : t('Ansehen')}</Link>{' '}
                    <Link className="button sm primary" to={`/templates/${tpl.id}?push=1`}>{t('Ausrollen …')}</Link>{' '}
                    {tpl.may_edit && (confirm === tpl.id
                      ? <button className="sm danger solid" onClick={() => remove(tpl)}>{t('Wirklich löschen')}</button>
                      : <button className="sm danger" onClick={() => setConfirm(tpl.id)}>{t('Löschen')}</button>)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ))}
      {creating && <NewTemplateModal onClose={() => setCreating(false)} />}
    </>
  )
}
