# 🚨 Axios Compromise Checker

**Emergency detection script for the axios npm supply chain attack (March 31, 2026)**

On March 31, 2026, two malicious versions of [axios](https://www.npmjs.com/package/axios) (300M+ weekly downloads) were published to npm via a compromised maintainer account. They contained a hidden dependency (`plain-crypto-js@4.2.1`) that deployed a **cross-platform Remote Access Trojan (RAT)** on any machine that ran `npm install` during a ~3 hour window.

## ⚡ Quick Start

```bash

# Make executable
chmod +x check_axios_compromise.sh

# Run (use sudo for full disk scan)
sudo bash check_axios_compromise.sh
```

## 📋 What It Checks

| # | Check | What It Looks For |
|---|-------|-------------------|
| 1 | **Malware files** | `/tmp/ld.py` (Linux), `/Library/Caches/com.apple.act.mond` (macOS), `%PROGRAMDATA%\wt.exe` (Windows) |
| 2 | **Network connections** | Active connections to C2 server `142.11.206.73:8000` / `sfrclak[.]com` |
| 3 | **Lockfiles** | All `package-lock.json`, `yarn.lock`, `bun.lock` on disk for `axios@1.14.1` or `axios@0.30.4` |
| 4 | **Malicious dependency** | `plain-crypto-js` in `node_modules` or any lockfile |
| 5 | **Related packages** | `@qqbrowser/openclaw-qbot` and `@shadanai/openclaw` |
| 6 | **Axios inventory** | Lists every installed axios version and flags dangerous ones |

## 🔴 If You Are Compromised

1. **CRYPTO WALLETS** — Move all funds to a wallet on a clean device **immediately**
2. **ROTATE ALL SECRETS** — API keys, SSH keys, tokens, passwords, cloud credentials — revoke and reissue everything
3. **ISOLATE** — Disconnect the machine from the network
4. **REBUILD** — Do not attempt to clean the system. Rebuild from a clean image
5. **AUDIT** — Review CI/CD build logs for the March 31, 2026 00:21–03:29 UTC window

## 🟢 If You Are Clean

- Pin axios to a known safe version in `package.json`
- Always commit your lockfile
- Use `npm ci` instead of `npm install` in CI/CD
- Consider `npm ci --ignore-scripts` in build pipelines
- Block `plain-crypto-js` in your security tooling

## 📊 Attack Summary

| Detail | Value |
|--------|-------|
| **Affected versions** | `axios@1.14.1`, `axios@0.30.4` |
| **Root cause** | Hijacked npm maintainer account (`@jasonsaayman`) |
| **Malicious dependency** | `plain-crypto-js@4.2.1` |
| **Payload** | Cross-platform RAT (macOS, Windows, Linux) |
| **C2 server** | `sfrclak[.]com:8000` (IP: `142.11.206.73`) |
| **Published** | March 31, 2026 — 00:21 UTC (`1.14.1`), 01:00 UTC (`0.30.4`) |
| **Removed** | March 31, 2026 — 03:29 UTC |
| **Window** | ~3 hours |
| **Safe versions** | Any version **except** `1.14.1` and `0.30.4` |

## 🔗 References

- [Snyk Advisory — SNYK-JS-AXIOS-15850650](https://security.snyk.io/vuln/SNYK-JS-AXIOS-15850650)
- [Snyk Blog — Full Analysis](https://snyk.io/blog/axios-npm-package-compromised-supply-chain-attack-delivers-cross-platform/)
- [GitHub Issue — axios/axios#10604](https://github.com/axios/axios/issues/10604)

## 🤝 Contributing

Found a bug or want to add a check? PRs welcome.

## 📄 License

MIT — Use freely. Stay safe.
