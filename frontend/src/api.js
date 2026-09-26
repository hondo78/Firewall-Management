import { lang, locale, t } from './i18n'
const TOKEN_KEY = 'fwm_token'

export function getToken() {
  try { return localStorage.getItem(TOKEN_KEY) } catch { return null }
}

export function setToken(token) {
  try {
    if (token) localStorage.setItem(TOKEN_KEY, token)
    else localStorage.removeItem(TOKEN_KEY)
  } catch { /* privater Modus – Login gilt dann nur bis zum Neuladen */ }
}

export async function api(path, { method = 'GET', body, raw = false } = {}) {
  // Sprache mitsenden – das Backend kann Meldungen künftig passend liefern
  const headers = { 'Accept-Language': lang }
  const token = getToken()
  if (token) headers.Authorization = `Bearer ${token}`
  if (body !== undefined) headers['Content-Type'] = 'application/json'
  const res = await fetch(`/api${path}`, {
    method, headers, body: body !== undefined ? JSON.stringify(body) : undefined,
  })
  if (res.status === 401 && path !== '/auth/login') {
    setToken(null)
    window.dispatchEvent(new Event('fwm:logout'))
  }
  if (!res.ok) {
    let msg = `${res.status} ${res.statusText}`
    let code = ''
    try {
      const j = await res.json()
      if (typeof j.detail === 'string') msg = j.detail
      else if (Array.isArray(j.detail)) msg = j.detail.map((d) => `${d.loc?.slice(-1)[0]}: ${d.msg}`).join(', ')
      else if (j.detail?.message) { msg = j.detail.message; code = j.detail.code || '' }
    } catch { /* keine JSON-Antwort */ }
    // Pflicht-Zwei-Faktor noch nicht eingerichtet → App leitet ins Profil
    if (code === 'mfa_setup_required') window.dispatchEvent(new Event('fwm:mfa-setup'))
    // Feste Meldungen des Backends übersetzen (Meldungen mit Namen bleiben im Original)
    const err = new Error(t(msg))
    err.code = code
    err.status = res.status
    throw err
  }
  if (raw) return res
  return res.status === 204 ? null : res.json()
}

/** Datei-Download mit Bearer-Token (ein <a href> kann keinen Header senden). */
export async function download(path, filename) {
  const res = await api(path, { raw: true })
  const url = URL.createObjectURL(await res.blob())
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

export const fmt = (d) => (d ? new Date(d).toLocaleString(locale, { dateStyle: 'short', timeStyle: 'short' }) : '–')

export function ago(d) {
  if (!d) return t("nie")
  const s = Math.round((Date.now() - new Date(d)) / 1000)
  if (s < 60) return t("gerade eben")
  if (s < 3600) return `vor ${Math.floor(s / 60)} min`
  if (s < 86400) return `vor ${Math.floor(s / 3600)} h`
  return fmt(d)
}

export const crNo = (n) => `CR-${String(n).padStart(4, '0')}`

export const STATUS_LABEL = {
  draft: t("Entwurf"), pending: t("Wartet auf Genehmigung"), approved: t("Genehmigt"), rejected: t("Abgelehnt"),
  withdrawn: t("Zurückgezogen"), deploying: t("Wird ausgerollt"), deployed: t("Ausgerollt"), failed: t("Fehlgeschlagen"),
  conflict: t("Konflikt"),
}

export const ACTION_LABEL = { add: t("Neu"), update: t("Ändern"), remove: t("Löschen") }

export const EVENT_LABEL = {
  created: t("Entwurf angelegt"), draft_changed: t("Entwurf geändert"), submitted: t("Eingereicht"), approved: t("Genehmigt"),
  rejected: t("Abgelehnt"), withdrawn: t("Zurückgezogen"), comment: t("Kommentar"), deploy_started: t("Ausrollen gestartet"),
  deployed: t("Ausgerollt"), failed: t("Fehlgeschlagen"), conflict: t("Konflikt erkannt"),
  preapproved: t("Vorab genehmigt (Befristung)"), expiry_failed: t("Automatische Rücknahme fehlgeschlagen"),
}

/** Recht auf einer Firewall (fw.permissions kommt vom Backend) bzw. global. */
export function can(me, perm, fw) {
  if (!me) return false
  if (me.is_superadmin) return true
  if (fw) return (fw.permissions || []).includes(perm)
  return (me.permissions?.global || []).includes(perm)
}

/** Recht irgendwo (global oder in einer Gruppe) – für die Navigation. */
export function canAnywhere(me, perm) {
  if (!me) return false
  if (me.is_superadmin || (me.permissions?.global || []).includes(perm)) return true
  return Object.values(me.permissions?.groups || {}).some((p) => p.includes(perm))
}

/** Datei-Upload (multipart) mit Bearer-Token. */
export async function upload(path, file) {
  const form = new FormData()
  form.append('file', file)
  const token = getToken()
  const res = await fetch(`/api${path}`, { method: 'POST', body: form, headers: token ? { Authorization: `Bearer ${token}` } : {} })
  const body = await res.json().catch(() => ({}))
  if (!res.ok) throw new Error(typeof body.detail === 'string' ? body.detail : body.detail?.message || `${res.status} ${res.statusText}`)
  return body
}
