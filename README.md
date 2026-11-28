# ZebraSign

Sign a message as "one of these GitHub users", using the SSH keys GitHub
publishes. Runs in the browser: https://kurt-brown.github.io/ZebraSign/

This is a test version. It replaces the original ZebraSign desktop app
([kurt-brown/zebra](https://github.com/kurt-brown/zebra)), which used its
own keys and is no longer maintained. The two formats aren't compatible.

- `src/` is the shared core and `pages/` the page templates and copy. Edit
  those. On every push to main, a GitHub Actions workflow
  (`.github/workflows/pages.yml`) runs the tests, builds the pages and
  publishes them. Each built page is one self-contained HTML file.
- `node build.js` builds them locally into `docs/` (not committed).
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
