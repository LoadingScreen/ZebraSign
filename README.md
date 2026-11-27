# ZebraSign

Sign a message as "one of these GitHub users", using the SSH keys GitHub
publishes. Runs in the browser: https://loadingscreen.github.io/ZebraSign/

This is a test version. It replaces the original ZebraSign desktop app
([LoadingScreen/zebra](https://github.com/LoadingScreen/zebra)), which used its
own keys and is no longer maintained. The two formats aren't compatible.

- `docs/` holds the built pages: `sign.html`, `verify.html`, and `index.html`
  (a copy of the sign page). Each is one file with no external scripts.
  GitHub Pages serves this folder.
- `src/` is the shared core, `pages/` the page templates. `node build.js`
  rebuilds `docs/`. Commit the rebuilt files; Pages doesn't run the build.
- `PROTOCOL.md` describes the construction.

## Tests

```
npm install         # test-only modules
npm test            # Node: key parsing, sign/verify round trips, tampering, GitHub client
npm run e2e         # browser via Playwright, with a fake GitHub API
```

Test keys are made with Node's crypto and converted by `sshpk`; encrypted
keys use the `bcrypt-pbkdf` npm module. These are test-only and not in the
pages.
