import { createContext, useCallback, useContext, useEffect, useState } from 'react'
import { NavLink, Navigate, Route, Routes, useLocation, useNavigate } from 'react-router-dom'
import { api, canAnywhere, getToken, setToken } from './api'
import ErrorBoundary from './components/ErrorBoundary'
import Audit from './pages/Audit'
import ChangeDetail from './pages/ChangeDetail'
import Changes from './pages/Changes'
import Dashboard from './pages/Dashboard'
import FirewallView from './pages/FirewallView'
import Firewalls from './pages/Firewalls'
import Login from './pages/Login'
import Profile from './pages/Profile'
import CentralAccounts from './pages/admin/CentralAccounts'
import Notifications from './pages/admin/Notifications'
import Sso from './pages/admin/Sso'
import Roles from './pages/admin/Roles'
import SettingsPage from './pages/admin/Settings'
import Users from './pages/admin/Users'

const AuthCtx = createContext(null)
export const useAuth = () => useContext(AuthCtx)

function Icon({ d }) {
  return (
    <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"
      strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d={d} /></svg>
  )
}

const I = {
  home: 'M3 11l9-7 9 7v9a1 1 0 0 1-1 1h-5v-6H9v6H4a1 1 0 0 1-1-1z',
  fw: 'M3 5h18v4H3zM3 11h18v4H3zM3 17h18v4H3zM8 5v4M14 11v4M9 17v4',
  changes: 'M9 11l3 3 8-8M20 12v7a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h9',
  audit: 'M12 8v4l3 2M21 12a9 9 0 1 1-9-9 9 9 0 0 1 9 9z',
  users: 'M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM22 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75',
  roles: 'M12 2l8 4v6c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10V6z',
  cloud: 'M17.5 19a4.5 4.5 0 1 0-1.4-8.78A6 6 0 1 0 6 17.2M6 19h11.5',
  bell: 'M18 8a6 6 0 0 0-12 0c0 7-3 9-3 9h18s-3-2-3-9M13.73 21a2 2 0 0 1-3.46 0',
  settings: 'M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 0 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 0 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 0 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 0 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z',
}

function Layout({ children }) {
  const { me, logout, counts } = useAuth()
  const [open, setOpen] = useState(false)
  const loc = useLocation()
  const nav = useNavigate()
  useEffect(() => setOpen(false), [loc.pathname])
  // Pflicht-Zwei-Faktor fehlt → ins Profil zur Einrichtung
  useEffect(() => {
    const go = () => nav('/profile')
    window.addEventListener('fwm:mfa-setup', go)
    return () => window.removeEventListener('fwm:mfa-setup', go)
  }, [nav])
  const isAdmin = me.is_superadmin || me.permissions.global.includes('admin')
  // Im Konfigurations-Editor wird die Navigation zur Symbolleiste (mehr Platz, wie im Config Studio)
  const inEditor = /^\/firewalls\/[^/]+(\/config)?$/.test(loc.pathname)
  const [pinned, setPinned] = useState(() => { try { return localStorage.getItem('fwm.nav.pinned') === '1' } catch { return false } })
  const rail = inEditor && !pinned
  const togglePin = () => { const v = !pinned; setPinned(v); try { localStorage.setItem('fwm.nav.pinned', v ? '1' : '0') } catch { /* egal */ } }
  const link = (to, icon, label, extra) => (
    <NavLink to={to} end={to === '/'} title={rail ? label : undefined}><Icon d={I[icon]} /><span className="nav-label">{label}</span>{extra}</NavLink>
  )
  return (
    <div className="layout">
      <aside className={`sidebar ${open ? 'open' : ''} ${rail ? 'rail' : ''}`}>
        <div className="brand">
          <span className="brand-mark"><Icon d="M5 8h14M5 12h14M5 16h9" /></span>
          <span>Firewall-Management<small>Sophos Firewall</small></span>
        </div>
        <button className="menu-toggle sm" onClick={() => setOpen(!open)} aria-label="Menü">☰</button>
        {inEditor && <button className="rail-toggle" onClick={togglePin} title={rail ? 'Navigation ausklappen' : 'Navigation einklappen'}
          aria-label={rail ? 'Navigation ausklappen' : 'Navigation einklappen'}><Icon d={rail ? 'M9 6l6 6-6 6' : 'M15 6l-6 6 6 6'} /></button>}
        <nav>
          {link('/', 'home', 'Übersicht')}
          {link('/firewalls', 'fw', 'Firewalls')}
          {link('/changes', 'changes', 'Änderungsanträge',
            counts.to_approve > 0 && <span className="count" title="Warten auf Ihre Genehmigung">{counts.to_approve}</span>)}
          {canAnywhere(me, 'audit.view') && link('/audit', 'audit', 'Audit-Log')}
          {isAdmin && <>
            <div className="nav-section">Administration</div>
            {link('/admin/users', 'users', 'Benutzer')}
            {link('/admin/roles', 'roles', 'Rollen & Rechte')}
            {link('/admin/central', 'cloud', 'Sophos Central')}
            {link('/admin/notifications', 'bell', 'Benachrichtigungen')}
            {link('/admin/sso', 'roles', 'Anmeldung & SSO')}
            {link('/admin/settings', 'settings', 'Einstellungen')}
          </>}
        </nav>
        <div className="me">
          <NavLink to="/profile">{me.display_name || me.username}</NavLink>
          <small>{me.is_superadmin ? 'Superadmin' : me.assignments.map((a) => a.role).filter((v, i, s) => s.indexOf(v) === i).join(', ') || 'keine Rolle'}</small>
          <button className="link" onClick={logout}>Abmelden</button>
        </div>
      </aside>
      <main className={`content ${rail ? 'with-rail' : ''}`}>
        {me.mfa_setup_required && <div className="alert warn">Für Ihre Rolle ist die Zwei-Faktor-Anmeldung Pflicht. Bitte im Profil einrichten – bis dahin sind andere Bereiche gesperrt.</div>}
        <ErrorBoundary key={loc.pathname}>{children}</ErrorBoundary>
      </main>
    </div>
  )
}

export default function App() {
  const [me, setMe] = useState(null)
  const [ready, setReady] = useState(false)
  const [counts, setCounts] = useState({})

  const refreshCounts = useCallback(() => {
    api('/dashboard').then(setCounts).catch(() => {})
  }, [])

  useEffect(() => {
    const onLogout = () => setMe(null)
    window.addEventListener('fwm:logout', onLogout)
    if (getToken()) {
      api('/auth/me').then(setMe).catch(() => setMe(null)).finally(() => setReady(true))
    } else setReady(true)
    return () => window.removeEventListener('fwm:logout', onLogout)
  }, [])

  useEffect(() => {
    if (!me) return undefined
    refreshCounts()
    const t = setInterval(refreshCounts, 30000)
    return () => clearInterval(t)
  }, [me, refreshCounts])

  const logout = () => { setToken(null); setMe(null) }
  if (!ready) return null
  if (!me) return <Login onLogin={(token, user) => { setToken(token); setMe(user) }} />

  return (
    <AuthCtx.Provider value={{ me, setMe, logout, counts, refreshCounts }}>
      <Layout>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/firewalls" element={<Firewalls />} />
          <Route path="/firewalls/:id" element={<FirewallView />} />
          <Route path="/firewalls/:id/:tab" element={<FirewallView />} />
          <Route path="/changes" element={<Changes />} />
          <Route path="/changes/:id" element={<ChangeDetail />} />
          <Route path="/audit" element={<Audit />} />
          <Route path="/profile" element={<Profile />} />
          <Route path="/admin/users" element={<Users />} />
          <Route path="/admin/roles" element={<Roles />} />
          <Route path="/admin/central" element={<CentralAccounts />} />
          <Route path="/admin/settings" element={<SettingsPage />} />
          <Route path="/admin/notifications" element={<Notifications />} />
          <Route path="/admin/sso" element={<Sso />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Layout>
    </AuthCtx.Provider>
  )
}
