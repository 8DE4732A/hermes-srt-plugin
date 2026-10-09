#!/usr/bin/env python3
"""Standalone test harness for the srt plugin outside Hermes.

Simulates what the plugin does: build settings, wrap a command, verify
isolation (file write outside allowWrite fails, network allow-list enforced).
"""
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, "/root/hermes-srt-plugin/src")
from hermes_srt_plugin import SrtTerminalProvider, _load_settings, _save_settings, SETTINGS_FILE

provider = SrtTerminalProvider()
print("is_available:", provider.is_available())
print("is_container:", provider.is_container, "=> skip_container_guards:", provider.skip_container_guards)

env = provider.create_environment(cwd="/tmp", timeout=60)
print("settings file:", SETTINGS_FILE)

# 1. basic exec
r = env.execute("echo hello-from-srt && whoami && pwd")
print("[basic]", r.get("returncode"), r.get("output", "").strip()[:80])

# 2. write inside allowed /tmp works
r = env.execute("touch /tmp/srt-probe/write-test && ls /tmp/srt-probe/write-test")
print("[write-tmp]", r.get("returncode"), r.get("output", "").strip()[:60])

# 3. network: allowed domain works, unknown domain blocked by proxy
r = env.execute("curl -s -m 8 -o /dev/null -w '%{http_code}' http://cp.cloudflare.com/generate_204")
print("[net-allowed]", r.get("returncode"), r.get("output", "").strip()[-8:])
r = env.execute("curl -s -m 8 -o /dev/null -w '%{http_code}' https://www.baidu.com")
print("[net-denied]", r.get("returncode"), r.get("output", "").strip()[-8:])

# 4. domain extraction for the approval hook
from hermes_srt_plugin import _unknown_domains, _extract_domains
cmd = "curl -s https://hex2077.dev/docs && pip install requests"
print("[domains]", _extract_domains(cmd))
print("[unknown]", _unknown_domains(cmd, _load_settings()))

env.cleanup()
print("ALL TESTS DONE")
