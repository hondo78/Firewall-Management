# Recording the demo video

The videos in `docs/media/` (`approval-demo.mp4` in English, `de/freigabe-demo.mp4` in German) and the screenshots
of the [approval guide](../approval-guide.md) are recorded automatically with Playwright against the Sophos mock.
Re-record them after UI changes.

| File | Purpose |
|---|---|
| `seed_demo.py` / `seed_demo_en.py` | Resets the mock and creates fictitious users (m.berger, s.keller, t.nguyen, a.wolf; password `Demo-Passwort-2026`), two REST firewalls, the settings (2 approvals, ticket required, no auto-deploy) and some history. The English variant also sets the default language to English. |
| `record.py` / `record_en.py` | Plays the story (request → two approvals → deploy → audit log) with subtitles and a visible cursor, and records the video and the screenshots. |
| `vite.demo.mjs` | Vite dev server on `:18097` that proxies `/api` to the demo backend on `:18000`. |

The recording never touches the production database or real firewalls: the backend runs as a separate container
with SQLite, and the only firewalls are the mock's.

## Steps

Run from the project directory; `D=docs/demo`.

```bash
# 1. Mock and a separate demo backend (SQLite, no worker)
COMPOSE_PROFILES=mock docker compose up -d sophos-mock
docker compose run -d --no-deps --name fwm-demo -p 18000:8000 \
  -v $PWD/docs/demo/seed_demo_en.py:/app/seed_demo.py \
  -e DATABASE_URL=sqlite:////tmp/demo.db -e ADMIN_PASSWORD=admin-password-123 -e DISABLE_WORKER=1 backend
sleep 7 && docker exec fwm-demo python seed_demo.py

# 2. Frontend dev server
cp docs/demo/vite.demo.mjs frontend/ && (cd frontend && npx vite --config vite.demo.mjs &)

# 3. Record (the scripts write to /w/demo/… inside the Playwright container)
docker run --rm --network host -v $PWD/docs:/w mcr.microsoft.com/playwright/python:v1.55.0-noble \
  bash -c "pip install -q playwright==1.55.0 && python /w/demo/record_en.py"

# 4. Convert the WebM recording to MP4 and extract a poster frame
ffmpeg -i docs/demo/video_en/*.webm -c:v libx264 -preset slow -crf 26 -pix_fmt yuv420p -movflags +faststart -an \
  docs/media/approval-demo.mp4
ffmpeg -ss 40 -i docs/media/approval-demo.mp4 -frames:v 1 -q:v 4 docs/media/approval-demo-poster.jpg

# 5. Clean up
docker rm -f fwm-demo && rm frontend/vite.demo.mjs && docker compose stop sophos-mock
```

For the German version, use `seed_demo.py` and `record.py`; they write to `video/` and `shots/`.
Convert the screenshots with `ffmpeg -i <shot>.png -q:v 4 <name>.jpg` and copy them to `docs/media/` under the names
used in the guide.

Every run seeds the mock from scratch, so the database IDs change. The scripts navigate by name and do not depend
on them. If the subtitles drift from the chapter marks in the guide, check the new chapter times with a contact
sheet: `ffmpeg -ss 76 -i approval-demo.mp4 -vf "fps=1,scale=240:-1,tile=10x10" -frames:v 1 grid.png`.
