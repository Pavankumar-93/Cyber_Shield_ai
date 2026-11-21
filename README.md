# React + Vite

This template provides a minimal setup to get React working in Vite with HMR and some ESLint rules.

Currently, two official plugins are available:

- [@vitejs/plugin-react](https://github.com/vitejs/vite-plugin-react/blob/main/packages/plugin-react) uses [Oxc](https://oxc.rs)
- [@vitejs/plugin-react-swc](https://github.com/vitejs/vite-plugin-react/blob/main/packages/plugin-react-swc) uses [SWC](https://swc.rs/)

## React Compiler

The React Compiler is not enabled on this template because of its impact on dev & build performances. To add it, see [this documentation](https://react.dev/learn/react-compiler/installation).

## Expanding the ESLint configuration

If you are developing a production application, we recommend using TypeScript with type-aware lint rules enabled. Check out the [TS template](https://github.com/vitejs/vite/tree/main/packages/create-vite/template-react-ts) for information on how to integrate TypeScript and [`typescript-eslint`](https://typescript-eslint.io) in your project.


## Google Safe Browsing setup (optional but recommended)

The backend health response reports `safe_browsing_configured: false` when the API key is missing.
To enable it, create `backend/.env` (copy `backend/.env.example`) and replace the placeholder with your Google Safe Browsing API key:

```env
SAFE_BROWSING_API_KEY=your_real_key_here
```

Restart the Python backend after saving the file. The health response should then report `safe_browsing_configured: true`. Keep `.env` private; do not commit or share your API key. A missing key means Google Safe Browsing checks are unavailable, not that a URL is safe.

The Security best practices control in the sidebar is styled as a prominent button and has keyboard focus styling.
