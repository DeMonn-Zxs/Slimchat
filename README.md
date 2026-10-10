# SlimChat Backend & Configuration

## Dynamic Domain
The Android client fetches the current backend endpoint dynamically from [domain.txt](domain.txt):
```text
https://chair-nov-hosted-illinois.trycloudflare.com
```

Whenever the backend tunnel domain changes, update `domain.txt` here on `main` branch, and the APK client will automatically connect to the new URL!

## Running the Backend
```bash
npm install
npm start
```
By default, the server runs on port 3678 with SQLite database (`slimchat.db`).

## Exposing via Cloudflare Tunnel
```bash
cloudflared tunnel --url http://127.0.0.1:3678
```
Copy the generated `https://*.trycloudflare.com` URL into `domain.txt` and push to GitHub.
