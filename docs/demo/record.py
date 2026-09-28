"""Demo-Video: Änderung beantragen → zwei Genehmigungen → ausrollen → Audit. Untertitel + sichtbarer Mauszeiger."""
import sys
from playwright.sync_api import sync_playwright
B = "http://127.0.0.1:18097"; PW = "Demo-Passwort-2026"
SH = "/w/demo/shots/"
INIT = r"""
(() => {
  const css = `#demo-cursor{position:fixed;z-index:2147483647;width:22px;height:22px;margin:-3px 0 0 -3px;pointer-events:none;transition:transform .08s}
  #demo-cursor svg{filter:drop-shadow(0 1px 2px rgba(0,0,0,.4))}
  #demo-cursor.down{transform:scale(.8)}
  #demo-ring{position:fixed;z-index:2147483646;width:34px;height:34px;margin:-17px 0 0 -17px;border-radius:50%;border:3px solid #f59e0b;pointer-events:none;opacity:0}
  #demo-ring.go{animation:ring .5s ease-out}
  @keyframes ring{0%{opacity:1;transform:scale(.4)}100%{opacity:0;transform:scale(1.4)}}
  #demo-cap{position:fixed;left:50%;bottom:84px;transform:translateX(-50%);z-index:2147483645;max-width:1000px;padding:14px 22px;border-radius:10px;
    background:rgba(12,20,40,.92);color:#fff;font:500 19px/1.4 system-ui,sans-serif;box-shadow:0 8px 24px rgba(0,0,0,.35);pointer-events:none;text-align:center}
  #demo-cap b{color:#fbbf24;font-weight:600}
  #demo-cap:empty{display:none}
  #demo-card{position:fixed;inset:0;z-index:2147483644;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:14px;
    background:linear-gradient(160deg,#0c1428,#1b2a57);color:#fff;font-family:system-ui,sans-serif;text-align:center}
  #demo-card h1{font-size:44px;margin:0;font-weight:700}#demo-card p{font-size:22px;margin:0;color:#c7d2fe;max-width:900px}`;
  const add = () => {
    if (document.getElementById('demo-cursor')) return;
    const st = document.createElement('style'); st.textContent = css; document.head.appendChild(st);
    const c = document.createElement('div'); c.id = 'demo-cursor';
    c.innerHTML = '<svg width="22" height="22" viewBox="0 0 22 22"><path d="M3 2l15 8.5-6.5 1.5L8.5 19z" fill="#fff" stroke="#111" stroke-width="1.5" stroke-linejoin="round"/></svg>';
    const r = document.createElement('div'); r.id = 'demo-ring';
    const cap = document.createElement('div'); cap.id = 'demo-cap';
    document.body.append(c, r, cap);
    const pos = JSON.parse(sessionStorage.getItem('demo-pos') || '[720,450]'); c.style.left = pos[0] + 'px'; c.style.top = pos[1] + 'px';
    cap.innerHTML = sessionStorage.getItem('demo-cap') || '';
    addEventListener('mousemove', (e) => { c.style.left = e.clientX + 'px'; c.style.top = e.clientY + 'px'; sessionStorage.setItem('demo-pos', JSON.stringify([e.clientX, e.clientY])) }, true);
    addEventListener('mousedown', (e) => { c.classList.add('down'); r.style.left = e.clientX + 'px'; r.style.top = e.clientY + 'px'; r.classList.remove('go'); void r.offsetWidth; r.classList.add('go') }, true);
    addEventListener('mouseup', () => c.classList.remove('down'), true);
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', add); else add();
  window.__demoCap = (h) => { sessionStorage.setItem('demo-cap', h); const el = document.getElementById('demo-cap'); if (el) el.innerHTML = h };
})();
"""

with sync_playwright() as pw:
    br = pw.chromium.launch()
    ctx = br.new_context(viewport={"width": 1440, "height": 900}, record_video_dir="/w/demo/video/", record_video_size={"width": 1440, "height": 900}, locale="de-DE", timezone_id="Europe/Berlin")
    ctx.add_init_script(INIT)
    p = ctx.new_page()
    shot_no = [0]

    def cap(html, wait=0):
        p.evaluate("(h) => window.__demoCap(h)", html); p.wait_for_timeout(wait)

    def shot(name):
        p.evaluate("() => { const c=document.getElementById('demo-cap'); if (c) c.style.visibility='hidden'; const k=document.getElementById('demo-cursor'); if (k) k.style.visibility='hidden' }")
        shot_no[0] += 1; p.screenshot(path=f"{SH}{shot_no[0]:02d}-{name}.png")
        p.evaluate("() => { for (const id of ['demo-cap','demo-cursor']) { const e=document.getElementById(id); if (e) e.style.visibility='' } }")

    def move(loc):
        loc.scroll_into_view_if_needed(); b = loc.bounding_box()
        p.mouse.move(b["x"] + min(b["width"] / 2, 60), b["y"] + b["height"] / 2, steps=18); p.wait_for_timeout(250)

    def click(loc, wait=700):
        loc = loc.first
        try:
            loc.wait_for(timeout=8000)
        except Exception:
            p.screenshot(path="/w/demo/err.png"); raise
        move(loc); loc.click(); p.wait_for_timeout(wait)

    def typ(loc, text):
        click(loc, 150); loc.first.type(text, delay=45); p.wait_for_timeout(250)

    def card(title, sub, ms=3500):
        cap("", 0)
        p.evaluate("([t,s]) => { let c=document.getElementById('demo-card'); if(!c){c=document.createElement('div');c.id='demo-card';document.body.appendChild(c)} c.innerHTML='<h1>'+t+'</h1><p>'+s+'</p>' }", [title, sub])
        p.wait_for_timeout(ms); p.evaluate("() => document.getElementById('demo-card')?.remove()")

    def login(user, who):
        p.goto(B + "/login"); p.wait_for_selector("input[autocomplete=username]")
        cap(who, 600)
        typ(p.locator("input[autocomplete=username]"), user)
        typ(p.locator("input[type=password]"), PW)
        click(p.locator("button:has-text('Anmelden')"), 1500)

    def logout():
        cap("", 0); click(p.locator("text=Abmelden"), 800)

    p.goto(B + "/"); p.evaluate("localStorage.clear(); localStorage.setItem('fwm.lang','de'); sessionStorage.clear()"); p.reload(); p.wait_for_timeout(500)
    card("Firewall-Management", "Änderungen an Sophos-Firewalls mit Vier-Augen-Freigabe<br><br><small>Demo · alle Personen und Firewalls sind fiktiv</small>", 4000)

    # --- 1. Beantragen ---
    login("m.berger", "<b>1 · Beantragen</b> – Martina Berger (Firewall-Administratorin) meldet sich an")
    cap("<b>Übersicht:</b> offene Genehmigungen, eigene Anträge und Status aller Firewalls", 2500); shot("uebersicht")
    click(p.locator("nav >> text=Firewalls"), 1000)
    click(p.locator("a:has-text('FW-Zentrale')"), 1500)
    cap("Der <b>Konfigurations-Editor</b> zeigt den synchronisierten Stand der Firewall", 2500)
    click(p.locator(".cs-item:has-text('IPv4-Adressen')"), 1000)
    cap("Neuer Webserver: zuerst das <b>Host-Objekt</b> anlegen", 1500)
    click(p.locator("button:has-text('Hinzufügen')").last, 900)
    typ(p.locator(".modal label:has-text('Name') input"), "Webserver-DMZ-2")
    typ(p.locator(".modal label:has-text('Beschreibung') input"), "Zweiter Webserver (Lastverteilung)")
    typ(p.locator(".modal label:has-text('IPv4-Adresse') input"), "10.10.20.11")
    shot("host-anlegen")
    cap("<b>In Entwurf übernehmen</b> – nichts geht direkt auf die Firewall", 1800)
    click(p.locator(".modal button:has-text('In Entwurf übernehmen')"), 1500)
    cap("Die Entwurfsleiste zählt die vorgemerkten Änderungen", 2200)

    click(p.locator(".cs-item:has-text('Firewall-Regeln IPv4')"), 1200)
    cap("Jetzt die Regel <b>„Internet nach Webserver“</b> um den neuen Host erweitern", 2000)
    click(p.locator("text=Internet nach Webserver"), 1500)
    zl = p.locator(".sf-list").nth(3)
    click(zl.locator("button:has-text('Neues Element hinzufügen')"), 700)
    typ(p.locator(".sf-list-pop input"), "Webserver-DMZ-2")
    click(p.locator(".sf-list-options button:has-text('Webserver-DMZ-2')"), 600)
    click(p.locator(".sf-list-pop-foot button"), 700)
    cap("Zielnetzwerke: <b>Webserver-DMZ</b> und neu <b>Webserver-DMZ-2</b>", 2200); shot("regel-bearbeiten")
    click(p.locator("button:has-text('In Entwurf übernehmen')"), 1800)

    cap("<b>Vorschau:</b> genau diese API-Aufrufe gehen nach der Freigabe an die Firewall", 800)
    click(p.locator("button:has-text('Vorschau')"), 1500); shot("vorschau"); p.wait_for_timeout(2500)
    p.keyboard.press("Escape"); p.wait_for_timeout(600)
    cap("Antrag stellen: Titel, <b>Ticket</b> und <b>Begründung</b> sind Pflicht", 800)
    click(p.locator("button:has-text('Einreichen …')"), 1200)
    typ(p.locator(".modal label:has-text('Titel') input"), "HTTPS für zweiten Webserver freigeben")
    typ(p.locator(".modal label:has-text('Ticket') input"), "CHG-4802")
    typ(p.locator(".modal textarea"), "Lastverteilung für www.example.com – angefordert vom Web-Team.")
    shot("einreichen"); p.wait_for_timeout(1200)
    click(p.locator("button:has-text('Zur Genehmigung einreichen')"), 2000)
    cap("Antrag ist <b>offen</b>. Martina kann ihren eigenen Antrag <b>nicht</b> genehmigen – Vier-Augen-Prinzip", 3500); shot("antrag-offen")
    cr_url = p.url
    logout()

    # --- 2. Erste Genehmigung ---
    login("s.keller", "<b>2 · Prüfen</b> – Stefan Keller (Approver) meldet sich an")
    cap("Auf der Übersicht wartet ein Antrag auf seine Genehmigung", 2500); shot("approver-uebersicht")
    click(p.locator("a:has-text('HTTPS für zweiten Webserver'), a:has-text('CR-0003')"), 1500)
    cap("Er sieht jede Änderung als <b>Vorher/Nachher</b> samt API-Aufruf und die automatische <b>Regel-Prüfung</b>", 1000)
    p.mouse.wheel(0, 450); p.wait_for_timeout(2500); shot("pruefen")
    p.mouse.wheel(0, 900); p.wait_for_timeout(1500)
    typ(p.locator("textarea").first, "Ziel und Dienst passen zum Ticket.")
    cap("<b>Genehmigen</b> – 1 von 2 nötigen Freigaben", 600)
    click(p.locator("button:has-text('Genehmigen')").last, 2000)
    shot("erste-freigabe"); p.wait_for_timeout(1500)
    logout()

    # --- 3. Zweite Genehmigung ---
    login("t.nguyen", "<b>3 · Zweite Freigabe</b> – Thu Nguyen (Approver)")
    p.goto(cr_url); p.wait_for_timeout(1500)
    cap("Die Einstellung verlangt <b>zwei</b> Genehmigungen – jede Person zählt nur einmal", 2500)
    p.mouse.wheel(0, 1200); p.wait_for_timeout(1000)
    click(p.locator("button:has-text('Genehmigen')").last, 2000)
    p.mouse.wheel(0, -2000); p.wait_for_timeout(500)
    cap("Status <b>Genehmigt</b> – bereit zum Ausrollen", 2500); shot("genehmigt")
    logout()

    # --- 4. Ausrollen ---
    login("m.berger", "<b>4 · Ausrollen</b> – Martina rollt den genehmigten Antrag aus")
    p.goto(cr_url); p.wait_for_timeout(1500)
    cap("Vor dem Schreiben prüft das Tool den <b>Live-Stand</b> der Firewall auf Abweichungen", 1200)
    click(p.locator("button:has-text('Jetzt ausrollen')"), 4000)
    p.reload(); p.wait_for_timeout(1500)
    cap("<b>Ausgerollt</b> – mit Protokoll; bei Bedarf per „Rückgängig machen …“ als neuer Antrag umkehrbar", 1000)
    p.mouse.wheel(0, 700); p.wait_for_timeout(2500); shot("ausgerollt")
    logout()

    # --- 5. Audit ---
    login("a.wolf", "<b>5 · Nachweis</b> – Andrea Wolf (Auditorin) prüft das Audit-Log")
    click(p.locator("nav >> text=Audit"), 1500)
    cap("Jeder Schritt ist im <b>hash-verketteten Audit-Log</b> festgehalten – wer, wann, was, von welcher IP", 3500)
    click(p.locator("button:has-text('Integrität prüfen')"), 1500)
    cap("<b>Integrität prüfen:</b> die Hash-Kette zeigt, dass kein Eintrag verändert oder gelöscht wurde", 3500); shot("audit")
    card("Zusammengefasst", "Entwurf → Antrag mit Begründung → zwei unabhängige Freigaben → Ausrollen mit Abweichungsprüfung → lückenloses Audit-Log", 5000)
    ctx.close(); br.close()
    print("ok")
