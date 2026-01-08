## Kuku Yetu — Local Development (Node.js)

This repository has been ported from Flask/Python to Node.js/Express. The JavaScript entrypoint is `server.js` and templates remain in `templates/` (served with Nunjucks).

Quick start:

```bash
npm install
npm start
```

Environment variables:
- `FLASK_SECRET` — session secret (kept for compatibility)
- `MPESA_*` — M-Pesa Daraja integration variables (use same names as before)

Key files:
- `server.js` — Node/Express application entrypoint
- `static/` — static assets and client JS
- `templates/` — Nunjucks templates (Jinja-like)
- `products.json`, `orders.json` — persistent data files

The previous Python files (Flask version) and `requirements.txt` have been removed.

If you need the original Python app, retrieve it from your `git` history.
