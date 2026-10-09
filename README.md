# srt-sandbox — Hermes terminal sandbox plugin

Runs every Hermes `terminal` command inside [Anthropic Sandbox Runtime](https://github.com/anthropics/sandbox-runtime)
(`srt`): Linux bubblewrap user-namespace isolation + allow-only network proxy.
No Docker needed.

## Effect

- `terminal.backend: srt` (set in config.yaml)
- **Dangerous-command approval is skipped** while sandboxed — `is_container=True`
  inherits `skip_container_guards=True`, same contract as Hermes' Modal/Daytona backends.
- **Filesystem**: sandboxed commands can write only allow-listed roots
  (`/root`, `/tmp`, `/var/log`, `/etc`, `/usr/local`, `/opt`, `/home`).
  Secrets are denyRead-protected regardless (`/root/.hermes/.env`, `auth.json`,
  `/root/.ssh`, gnupg, aws, gcloud, stt-proxy .env).
- **Network**: allow-list only. Unknown domains → `pre_tool_call` hook returns
  a `block` directive with copy-paste instructions: the user allow-lists the
  domains via `on_allow` (or a manual edit of `settings/srt-settings.json`),
  then retries. Enforcement is at the proxy layer (srt's own HTTP/SOCKS
  proxy), so extraction misses can't bypass.

## Layout

```
/root/hermes-srt-plugin/
├── src/hermes_srt_plugin/     plugin package (symlinked into ~/.hermes/plugins/srt-sandbox)
│   ├── __init__.py            provider + pre_tool_call hook
│   └── plugin.yaml            manifest
├── settings/srt-settings.json live srt settings (allow-list persisted here)
├── settings/domain-requests.log  audit log of every domain decision
└── test_sandbox.py            standalone test harness
```

## Notes

- srt requires `allowAllUnixSockets: true` on this kernel (Aliyun KVM guest
  blocks seccomp user-notify inside nested user namespaces). Unix socket
  blocking is therefore off; filesystem + network fences remain.
- Domain extraction is best-effort UX. The proxy is the enforcement point.
- Switch back anytime: `hermes config set terminal.backend local`.
- `/root/.hermes/cache/scratch` (TMPDIR) is under /root → writable, expected.
