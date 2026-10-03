"""Demo-Video: Änderung beantragen → zwei Genehmigungen → ausrollen → Audit. Untertitel + sichtbarer Mauszeiger.

Aufruf (im Playwright-Container, docs/ als /w eingebunden):  python /w/demo/record.py --lang en|de
Ergebnis in /w/demo/out/<lang>/: video/*.webm und die Screenshots unter den Namen aus docs/media.
Oberflächentexte (L), Untertitel (C) und Eingaben (D) je Sprache in TEXT – der Ablauf ist für beide Sprachen gleich.
"""
import argparse
import os
from playwright.sync_api import sync_playwright

B = "http://127.0.0.1:18097"
PW = "Demo-Passwort-2026"

TEXT = {
    "de": {
        "locale": "de-DE",
        "L": {"sign_in": "Anmelden", "sign_out": "Abmelden", "ipv4": "IPv4-Adressen", "add": "Hinzufügen", "name": "Name",
              "description": "Beschreibung", "add_to_draft": "In Entwurf übernehmen", "rules": "Firewall-Regeln IPv4",
              "dest_networks": "Zielnetzwerke – neues Element hinzufügen", "preview": "Vorschau", "submit": "Einreichen …",
              "title": "Titel", "submit_final": "Zur Genehmigung einreichen", "approve": "Genehmigen",
              "deploy": "Jetzt ausrollen", "check": "Integrität prüfen"},
        "D": {"host_desc": "Zweiter Webserver (Lastverteilung)", "cr_title": "HTTPS für zweiten Webserver freigeben",
              "justification": "Lastverteilung für www.example.com – angefordert vom Web-Team.",
              "comment": "Ziel und Dienst passen zum Ticket."},
        "C": {
            "intro": ("Firewall-Management", "Änderungen an Sophos-Firewalls mit Vier-Augen-Freigabe<br><br><small>Demo · alle Personen und Firewalls sind fiktiv</small>"),
            "login1": "<b>1 · Beantragen</b> – Martina Berger (Firewall-Administratorin) meldet sich an",
            "overview": "<b>Übersicht:</b> offene Genehmigungen, eigene Anträge und Status aller Firewalls",
            "editor": "Der <b>Konfigurations-Editor</b> zeigt den synchronisierten Stand der Firewall",
            "host": "Neuer Webserver: zuerst das <b>Host-Objekt</b> anlegen",
            "draft": "<b>In Entwurf übernehmen</b> – nichts geht direkt auf die Firewall",
            "draftbar": "Die Entwurfsleiste zählt die vorgemerkten Änderungen",
            "rule": "Jetzt die Regel <b>„Internet nach Webserver“</b> um den neuen Host erweitern",
            "dest": "Zielnetzwerke: <b>Webserver-DMZ</b> und neu <b>Webserver-DMZ-2</b>",
            "preview": "<b>Vorschau:</b> genau diese API-Aufrufe gehen nach der Freigabe an die Firewall",
            "submit": "Antrag stellen: Titel, <b>Ticket</b> und <b>Begründung</b> sind Pflicht",
            "pending": "Antrag ist <b>offen</b>. Martina kann ihren eigenen Antrag <b>nicht</b> genehmigen – Vier-Augen-Prinzip",
            "login2": "<b>2 · Prüfen</b> – Stefan Keller (Approver) meldet sich an",
            "waiting": "Auf der Übersicht wartet ein Antrag auf seine Genehmigung",
            "review": "Er sieht jede Änderung als <b>Vorher/Nachher</b> samt API-Aufruf und die automatische <b>Regel-Prüfung</b>",
            "approve1": "<b>Genehmigen</b> – 1 von 2 nötigen Freigaben",
            "login3": "<b>3 · Zweite Freigabe</b> – Thu Nguyen (Approver)",
            "two": "Die Einstellung verlangt <b>zwei</b> Genehmigungen – jede Person zählt nur einmal",
            "approved": "Status <b>Genehmigt</b> – bereit zum Ausrollen",
            "login4": "<b>4 · Ausrollen</b> – Martina rollt den genehmigten Antrag aus",
            "drift": "Vor dem Schreiben prüft das Tool den <b>Live-Stand</b> der Firewall auf Abweichungen",
            "deployed": "<b>Ausgerollt</b> – mit Protokoll; bei Bedarf per „Rückgängig machen …“ als neuer Antrag umkehrbar",
            "login5": "<b>5 · Nachweis</b> – Andrea Wolf (Auditorin) prüft das Audit-Log",
            "audit": "Jeder Schritt ist im <b>hash-verketteten Audit-Log</b> festgehalten – wer, wann, was, von welcher IP",
            "integrity": "<b>Integrität prüfen:</b> die Hash-Kette zeigt, dass kein Eintrag verändert oder gelöscht wurde",
            "outro": ("Zusammengefasst", "Entwurf → Antrag mit Begründung → zwei unabhängige Freigaben → Ausrollen mit Abweichungsprüfung → lückenloses Audit-Log"),
        },
    },
    "en": {
        "locale": "en-GB",
        "L": {"sign_in": "Sign in", "sign_out": "Sign out", "ipv4": "IPv4 addresses", "add": "Add", "name": "Name",
              "description": "Description", "add_to_draft": "Add to draft", "rules": "Firewall rules IPv4",
              "dest_networks": "Destination networks – add new item", "preview": "Preview", "submit": "Submit …",
              "title": "Title", "submit_final": "Submit for approval", "approve": "Approve",
              "deploy": "Deploy now", "check": "Check integrity"},
        "D": {"host_desc": "Second web server (load balancing)", "cr_title": "Allow HTTPS to second web server",
              "justification": "Load balancing for www.example.com – requested by the web team.",
              "comment": "Destination and service match the ticket."},
        "C": {
            "intro": ("Firewall Management", "Changes to Sophos firewalls with four-eyes approval<br><br><small>Demo · all people and firewalls are fictitious</small>"),
            "login1": "<b>1 · Request</b> – Martina Berger (firewall administrator) signs in",
            "overview": "<b>Overview:</b> pending approvals, your own requests and the status of every firewall",
            "editor": "The <b>configuration editor</b> shows the firewall's synchronised state",
            "host": "New web server: first create the <b>host object</b>",
            "draft": "<b>Add to draft</b> – nothing goes straight to the firewall",
            "draftbar": "The draft bar counts the pending changes",
            "rule": "Now add the new host to the rule <b>“Internet nach Webserver”</b>",
            "dest": "Destination networks: <b>Webserver-DMZ</b> plus the new <b>Webserver-DMZ-2</b>",
            "preview": "<b>Preview:</b> exactly these API calls go to the firewall after approval",
            "submit": "Submit the request: title, <b>ticket</b> and <b>justification</b> are required",
            "pending": "The request is <b>pending</b>. Martina <b>cannot</b> approve her own request – four-eyes principle",
            "login2": "<b>2 · Review</b> – Stefan Keller (approver) signs in",
            "waiting": "The overview shows a request waiting for his approval",
            "review": "He sees every change as <b>before/after</b> with its API call, plus the automatic <b>rule check</b>",
            "approve1": "<b>Approve</b> – 1 of 2 required approvals",
            "login3": "<b>3 · Second approval</b> – Thu Nguyen (approver)",
            "two": "The settings require <b>two</b> approvals – each person counts only once",
            "approved": "Status <b>Approved</b> – ready to deploy",
            "login4": "<b>4 · Deploy</b> – Martina deploys the approved request",
            "drift": "Before writing, the tool checks the firewall's <b>live state</b> for drift",
            "deployed": "<b>Deployed</b> – with a log; “Revert …” turns it back via a new request if needed",
            "login5": "<b>5 · Evidence</b> – Andrea Wolf (auditor) checks the audit log",
            "audit": "Every step is recorded in the <b>hash-chained audit log</b> – who, when, what, from which IP",
            "integrity": "<b>Check integrity:</b> the hash chain proves no entry was changed or deleted",
            "outro": ("In short", "Draft → request with justification → two independent approvals → deploy with drift check → complete audit log"),
        },
    },
}

args = argparse.ArgumentParser()
args.add_argument("--lang", choices=sorted(TEXT), default="en")
LANG = args.parse_args().lang
L, C, D = TEXT[LANG]["L"], TEXT[LANG]["C"], TEXT[LANG]["D"]
OUT = f"/w/demo/out/{LANG}"
os.makedirs(OUT, exist_ok=True)

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
    ctx = br.new_context(viewport={"width": 1440, "height": 900}, record_video_dir=f"{OUT}/video/",
                         record_video_size={"width": 1440, "height": 900}, locale=TEXT[LANG]["locale"], timezone_id="Europe/Berlin")
    ctx.add_init_script(INIT)
    p = ctx.new_page()

    def cap(html, wait=0):
        p.evaluate("(h) => window.__demoCap(h)", html); p.wait_for_timeout(wait)

    def shot(name):
        p.evaluate("() => { const c=document.getElementById('demo-cap'); if (c) c.style.visibility='hidden'; const k=document.getElementById('demo-cursor'); if (k) k.style.visibility='hidden' }")
        p.screenshot(path=f"{OUT}/{name}.png")
        p.evaluate("() => { for (const id of ['demo-cap','demo-cursor']) { const e=document.getElementById(id); if (e) e.style.visibility='' } }")

    def move(loc):
        loc.scroll_into_view_if_needed(); b = loc.bounding_box()
        p.mouse.move(b["x"] + min(b["width"] / 2, 60), b["y"] + b["height"] / 2, steps=18); p.wait_for_timeout(250)

    def click(loc, wait=700):
        loc = loc.first
        try:
            loc.wait_for(timeout=8000)
        except Exception:
            p.screenshot(path=f"{OUT}/error.png"); raise
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
        click(p.locator(f"button:has-text('{L['sign_in']}')"), 1500)

    def logout():
        cap("", 0); click(p.locator(f"text={L['sign_out']}"), 800)

    p.goto(B + "/"); p.evaluate("(l) => { localStorage.clear(); localStorage.setItem('fwm.lang', l); sessionStorage.clear() }", LANG)
    p.reload(); p.wait_for_timeout(500)
    card(*C["intro"], 4000)

    # --- 1. Beantragen ---
    login("m.berger", C["login1"])
    cap(C["overview"], 2500); shot("01-overview")
    click(p.locator("nav >> text=Firewalls"), 1000)
    click(p.locator("a:has-text('FW-Zentrale')"), 1500)
    cap(C["editor"], 2500)
    click(p.locator(f".cs-item:has-text('{L['ipv4']}')"), 1000)
    cap(C["host"], 1500)
    click(p.locator(f"button:has-text('{L['add']}')").last, 900)
    # Felder über ihre Beschriftung bzw. den Platzhalter finden – nicht über die Position
    typ(p.locator(f".modal label:has-text('{L['name']}') input"), "Webserver-DMZ-2")
    typ(p.locator(f".modal label:has-text('{L['description']}') input"), D["host_desc"])
    typ(p.locator(".modal input[placeholder='10.0.0.1']"), "10.10.20.11")
    shot("02-create-host")
    cap(C["draft"], 1800)
    click(p.locator(f".modal button:has-text('{L['add_to_draft']}')"), 1500)
    cap(C["draftbar"], 2200)

    click(p.locator(f".cs-item:has-text('{L['rules']}')"), 1200)
    cap(C["rule"], 2000)
    click(p.locator("text=Internet nach Webserver"), 1500)
    # Zielnetzwerke über das Bedienhilfe-Label des „Neues Element“-Knopfs (unabhängig von der Reihenfolge der Felder)
    click(p.locator(f"button[aria-label='{L['dest_networks']}']"), 700)
    typ(p.locator(".sf-list-pop input"), "Webserver-DMZ-2")
    click(p.locator(".sf-list-options button:has-text('Webserver-DMZ-2')"), 600)
    click(p.locator(".sf-list-pop-foot button"), 700)
    cap(C["dest"], 2200); shot("03-edit-rule")
    click(p.locator(f"button:has-text('{L['add_to_draft']}')"), 1800)

    cap(C["preview"], 800)
    click(p.locator(f"button:has-text('{L['preview']}')"), 1500); shot("04-preview"); p.wait_for_timeout(2500)
    p.keyboard.press("Escape"); p.wait_for_timeout(600)
    cap(C["submit"], 800)
    click(p.locator(f"button:has-text('{L['submit']}')"), 1200)
    typ(p.locator(f".modal label:has-text('{L['title']}') input"), D["cr_title"])
    typ(p.locator(".modal label:has-text('Ticket') input"), "CHG-4802")
    typ(p.locator(".modal textarea"), D["justification"])
    shot("05-submit"); p.wait_for_timeout(1200)
    click(p.locator(f"button:has-text('{L['submit_final']}')"), 2000)
    cap(C["pending"], 3500); shot("06-pending")
    cr_url = p.url
    logout()

    # --- 2. Erste Genehmigung ---
    login("s.keller", C["login2"])
    cap(C["waiting"], 2500); shot("07-approver-overview")
    click(p.locator(f"a:has-text('{D['cr_title']}'), a:has-text('CR-0003')"), 1500)
    cap(C["review"], 1000)
    p.mouse.wheel(0, 450); p.wait_for_timeout(2500); shot("08-review")
    p.mouse.wheel(0, 900); p.wait_for_timeout(1500)
    typ(p.locator("textarea").first, D["comment"])          # erstes Textfeld = Kommentar zur Entscheidung
    cap(C["approve1"], 600)
    click(p.locator(f"button:has-text('{L['approve']}')").last, 2000)
    shot("09-first-approval"); p.wait_for_timeout(1500)
    logout()

    # --- 3. Zweite Genehmigung ---
    login("t.nguyen", C["login3"])
    p.goto(cr_url); p.wait_for_timeout(1500)
    cap(C["two"], 2500)
    p.mouse.wheel(0, 1200); p.wait_for_timeout(1000)
    click(p.locator(f"button:has-text('{L['approve']}')").last, 2000)
    p.mouse.wheel(0, -2000); p.wait_for_timeout(500)
    cap(C["approved"], 2500); shot("10-approved")
    logout()

    # --- 4. Ausrollen ---
    login("m.berger", C["login4"])
    p.goto(cr_url); p.wait_for_timeout(1500)
    cap(C["drift"], 1200)
    click(p.locator(f"button:has-text('{L['deploy']}')"), 4000)
    p.reload(); p.wait_for_timeout(1500)
    cap(C["deployed"], 1000)
    p.mouse.wheel(0, 700); p.wait_for_timeout(2500); shot("11-deployed")
    logout()

    # --- 5. Audit ---
    login("a.wolf", C["login5"])
    click(p.locator("nav >> text=Audit"), 1500)
    cap(C["audit"], 3500)
    click(p.locator(f"button:has-text('{L['check']}')"), 1500)
    cap(C["integrity"], 3500); shot("12-audit-log")
    card(*C["outro"], 5000)
    ctx.close(); br.close()
    print("ok", OUT)
