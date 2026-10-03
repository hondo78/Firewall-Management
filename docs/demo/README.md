# Recording the demo video

The videos in `docs/media/` (`approval-demo.mp4` in English, `de/freigabe-demo.mp4` in German) and the screenshots of
the [approval guide](../approval-guide.md) are recorded automatically with Playwright against the Sophos mock.
Re-record them after UI changes.

| File | Purpose |
|---|---|
| `seed_demo.py --lang en\|de` | Resets the mock and creates fictitious users (m.berger, s.keller, t.nguyen, a.wolf; password `Demo-Passwort-2026`), two REST firewalls, the settings (2 approvals, ticket required, no auto-deploy, default language) and some history. It stops with a clear message if the mock is not reachable or the database is already seeded. |
| `record.py --lang en\|de` | Plays the story (request → two approvals → deploy → audit log) with subtitles and a visible cursor. It writes the video and the screenshots, already named as in `docs/media`, to `docs/demo/out/<lang>/`. All texts are in one table per language, and form fields are found by label, placeholder or accessible name, never by position. |
| `vite.demo.mjs` | Vite dev server on `:18097` that proxies `/api` to the demo backend on `:18000`. |

The demo backend is a separate container with a fresh SQLite database. It gets its **own** master key and JWT secret
and **no syslog target**, so nothing reaches the production database, the production audit forwarding or real
firewalls. The worker is disabled, so it does not sync or back up anything.

## Steps

Run from the project directory. `LANG_=en` (or `de`).

```bash
LANG_=en
rm -rf docs/demo/out/$LANG_                       # old takes would otherwise end up in the glob below

# 1. Mock and a separate demo backend
COMPOSE_PROFILES=mock docker compose up -d sophos-mock
docker compose run -d --no-deps --name fwm-demo -p 18000:8000 \
  -v $PWD/docs/demo/seed_demo.py:/app/seed_demo.py \
  -e DATABASE_URL=sqlite:////tmp/demo.db -e DISABLE_WORKER=1 -e ADMIN_PASSWORD=admin-password-123 \
  -e FWM_MASTER_KEY=$(openssl rand -base64 32) -e JWT_SECRET=demo-only -e SYSLOG_HOST= \
  backend
sleep 8 && docker exec fwm-demo python seed_demo.py --lang $LANG_

# 2. Frontend dev server
cp docs/demo/vite.demo.mjs frontend/
(cd frontend && nohup npx vite --config vite.demo.mjs > /tmp/fwm-demo-vite.log 2>&1 &)

# 3. Record (docs/ is mounted as /w)
docker run --rm --network host -v $PWD/docs:/w mcr.microsoft.com/playwright/python:v1.55.0-noble \
  bash -c "pip install -q playwright==1.55.0 && python /w/demo/record.py --lang $LANG_; chown -R $(id -u):$(id -g) /w/demo/out"

# 4. MP4, poster and screenshots (paths for English; German: docs/media/de/freigabe-demo*.{mp4,jpg})
OUT=docs/demo/out/$LANG_
ffmpeg -y -i "$(ls -t $OUT/video/*.webm | head -1)" -c:v libx264 -preset slow -crf 26 -pix_fmt yuv420p \
  -movflags +faststart -an docs/media/approval-demo.mp4
ffmpeg -y -ss 40 -i docs/media/approval-demo.mp4 -frames:v 1 -q:v 4 docs/media/approval-demo-poster.jpg
for f in $OUT/[0-9]*.png; do ffmpeg -y -loglevel error -i "$f" -q:v 4 "docs/media/$(basename "${f%.png}").jpg"; done

# 5. Clean up
pkill -f "vite --config vite.demo.mjs"; rm frontend/vite.demo.mjs
docker rm -f fwm-demo && docker compose stop sophos-mock
```

The guide's screenshots are the English ones. For the German video, skip the screenshot loop in step 4.

Each run seeds the mock from scratch, so database IDs change. The script navigates by name and does not depend on
them. If subtitles drift from the chapter marks in the guide, check the timing on a contact sheet:
`ffmpeg -ss 76 -i docs/media/approval-demo.mp4 -vf "fps=1,scale=240:-1,tile=10x10" -frames:v 1 grid.png`.
