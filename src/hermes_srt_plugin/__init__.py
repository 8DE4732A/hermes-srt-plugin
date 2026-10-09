"""srt-sandbox: Anthropic Sandbox Runtime (srt) terminal backend for Hermes.

Registers a ``TerminalEnvironmentProvider`` named ``srt`` that runs every
terminal command inside ``srt`` (bubblewrap user namespace + allow-only network
proxy). ``is_container = True`` makes Hermes' approval layer skip
dangerous-command prompts while commands stay inside the sandbox.

Network is allow-only. A ``pre_tool_call`` hook extracts outbound domains from
well-known commands (curl, wget, pip, npm, git, ...) and, when it finds one
that is not allow-listed, returns ``{"action": "block"}`` with copy-paste
instructions: Hermes' approval gate cannot update the srt settings file, so
the domain must be added to the persistent allow-list via ``on_allow`` (or a
manual edit) before the command is retried. Sensitive host paths
(/root/.hermes, /root/.ssh, ...) are denyRead / denyWrite so secrets cannot
leak through the sandbox either way.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shlex
import shutil
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from agent.terminal_env_provider import TerminalEnvironmentProvider
from tools.environments.base import BaseEnvironment

logger = logging.getLogger(__name__)

SRT_BINARY = shutil.which("srt") or "/root/.hermes/tools/node-26.7.0-linux-x64/bin/srt"
SETTINGS_DIR = Path(os.environ.get("SRT_SETTINGS_DIR", "/root/hermes-srt-plugin/settings"))
SETTINGS_FILE = SETTINGS_DIR / "srt-settings.json"
AUDIT_LOG = SETTINGS_DIR / "domain-requests.log"

# Domains always allowed (loopback infra on this box + package indexes the user
# pre-approved by installing this plugin). Edit via the settings file instead.
DEFAULT_ALLOWED_DOMAINS = [
    "127.0.0.1",
    "localhost",
    "[::1]",
]

# Paths the sandboxed process must never read/write even though the workspace
# is writable. denyRead wins over allowRead inside srt.
PROTECTED_PATHS = [
    "/root/.hermes/.env",
    "/root/.hermes/auth.json",
    "/root/.ssh",
    "/root/.gnupg",
    "/root/.config/gcloud",
    "/root/.aws",
    "/root/stt-proxy/.env",
]

# Commands that inherently talk to the network through their own configured
# endpoints. Domain extraction is best-effort: if we cannot find a domain we
# let the command run sandboxed (the sandbox itself enforces the allow-list at
# the proxy layer anyway — the hook is UX, the proxy is the enforcement).
_KNOWN_DOMAIN_DEFAULTS = {
    "apt": ["archive.ubuntu.com", "security.ubuntu.com", "ports.ubuntu.com", "ppa.launchpad.net"],
    "apt-get": ["archive.ubuntu.com", "security.ubuntu.com", "ports.ubuntu.com", "ppa.launchpad.net"],
    "pip": ["pypi.org", "files.pythonhosted.org"],
    "pip3": ["pypi.org", "files.pythonhosted.org"],
    "npm": ["registry.npmjs.org"],
    "uv": ["pypi.org", "files.pythonhosted.org"],
}


def _load_settings() -> Dict[str, Any]:
    if SETTINGS_FILE.is_file():
        try:
            return json.loads(SETTINGS_FILE.read_text())
        except Exception:
            logger.warning("srt-sandbox: unreadable settings %s; starting fresh", SETTINGS_FILE)
    return {
        "network": {"allowAllUnixSockets": True, "allowedDomains": list(DEFAULT_ALLOWED_DOMAINS),
                    "deniedDomains": []},
        "filesystem": {
            "denyRead": list(PROTECTED_PATHS),
            "denyWrite": [],
            "allowRead": ["/"],
            "allowWrite": ["/root", "/tmp", "/var/log", "/etc", "/usr/local", "/opt", "/home"],
        },
    }


def _save_settings(settings: Dict[str, Any]) -> None:
    SETTINGS_DIR.mkdir(parents=True, exist_ok=True)
    SETTINGS_FILE.write_text(json.dumps(settings, indent=2))


def _allowed_domains(settings: Dict[str, Any]) -> List[str]:
    return list(settings.get("network", {}).get("allowedDomains") or [])


def _extract_domains(command: str) -> List[str]:
    """Best-effort outbound domains referenced by a shell command."""
    domains: List[str] = []
    url_re = re.compile(r"(?:https?|ftps?|ssh)://([A-Za-z0-9._\-]+)")
    for m in url_re.finditer(command):
        domains.append(m.group(1).lower())
    # apt sources on ubuntu resolve to archive.ubuntu.com etc.
    if re.search(r"\bapt(-get)?\s+install|\bapt(-get)?\s+update", command):
        domains.extend(_KNOWN_DOMAIN_DEFAULTS["apt"])
    if re.search(r"\bpip3?\s+install", command):
        domains.extend(_KNOWN_DOMAIN_DEFAULTS["pip"])
    if re.search(r"\bnpm\s+(install|add|i)\b", command):
        domains.append("registry.npmjs.org")
    if "github.com" in command or re.search(r"\bgh\s+\w+", command):
        domains.append("github.com")
    return sorted(set(d for d in domains if d))


def _unknown_domains(command: str, settings: Dict[str, Any]) -> List[str]:
    allowed = set(_allowed_domains(settings))
    return [d for d in _extract_domains(command) if d not in allowed
            and not any(d.endswith("." + a) for a in allowed)]


class SrtEnvironment(BaseEnvironment):
    """Runs commands inside ``srt`` with the plugin's persisted settings.

    The settings file is the single source of truth and is written ONLY by the
    hook-side helpers (``on_allow`` / manual edits). Environment creation never
    saves — a startup snapshot must not clobber hook-side or hand edits.
    """

    is_local = False

    def __init__(self, cwd: str, timeout: int, settings: Dict[str, Any], **kwargs):
        super().__init__(cwd=cwd, timeout=timeout)
        self._settings_file = str(SETTINGS_FILE)
        # Ensure the settings file exists at all (first run), never overwrite.
        if not SETTINGS_FILE.is_file():
            SETTINGS_DIR.mkdir(parents=True, exist_ok=True)
            _save_settings(settings)

    def get_temp_dir(self) -> str:
        return "/tmp"

    def _run_bash(self, cmd_string: str, *, login: bool = False, timeout: int = 120,
                  stdin_data: str | None = None):
        from tools.environments.base_output import _popen_bash
        # srt -c runs a shell string; cd first so CWD matches the session state.
        wrapped = f"cd {shlex.quote(self.cwd) if self.cwd else '~'} 2>/dev/null || true; " + cmd_string
        argv = [SRT_BINARY, "--settings", self._settings_file, "-c", wrapped]
        return _popen_bash(argv, stdin_data=stdin_data)

    def cleanup(self):
        return None


class SrtTerminalProvider(TerminalEnvironmentProvider):
    name = "srt"
    display_name = "srt sandbox (bubblewrap)"

    def __init__(self):
        self._settings = _load_settings()

    @property
    def is_remote(self) -> bool:
        return False  # same host, just namespaced

    @property
    def is_container(self) -> bool:
        return True

    @property
    def env_description(self) -> str:
        return "an srt bubblewrap sandbox on this host (filesystem-scoped, network allow-listed)"

    def is_available(self) -> bool:
        return Path(SRT_BINARY).exists() and shutil.which("bwrap") is not None

    def create_environment(self, *, cwd: str, timeout: int, task_id: str = "default",
                           image: Optional[str] = None, container_config: Optional[Dict[str, Any]] = None,
                           **kwargs):
        return SrtEnvironment(cwd=cwd, timeout=timeout, settings=self._settings, **kwargs)


_provider = SrtTerminalProvider()


def pre_tool_call_hook(tool_name: str = "", args: Optional[Dict[str, Any]] = None, **kwargs):
    """Network allow-list gate for terminal commands (registered as pre_tool_call).

    Returns a ``block`` directive when the command references domains that are
    not allow-listed yet. Hermes' approval gate CANNOT update the srt settings
    file (request_tool_approval only persists its own allowlist entry), so an
    ``approve`` directive would run the command straight into the srt proxy's
    403 — a broken loop. Instead we block with copy-paste instructions, and the
    allow-list edit takes effect on the NEXT attempt (this one is stopped).

    rule_key includes the domain list so each distinct set of new domains gets
    its own approval-grain entry; combined with ``block`` this only matters if
    the action is ever changed back to ``approve``.
    """
    if tool_name != "terminal" or not isinstance(args, dict):
        return None
    command = str(args.get("command") or "")
    if not command:
        return None
    unknown = _unknown_domains(command, _load_settings())
    if not unknown:
        return None
    for d in unknown:
        _log_request(d, "blocked-pending-allowlist")
    domain_list = ", ".join(unknown)
    # repr-join with commas so the generated list is a real list of all domains
    # (space-joining would be implicit string concatenation; f-string {d!r} would
    # capture only the last loop-leaked domain).
    domain_reprs = ", ".join(repr(d) for d in unknown)
    return {
        "action": "block",
        "message": (
            f"srt sandbox: command contacts domain(s) not on the network allow-list: {domain_list}. "
            f"The command was NOT run. To allow-list, add to "
            f"\"network.allowedDomains\" in {SETTINGS_FILE} (helper: "
            f"python3 -c \"import sys; sys.path.insert(0, '/root/hermes-srt-plugin/src'); "
            f"from hermes_srt_plugin import on_allow; [on_allow(d) for d in [{domain_reprs}]]\"), "
            f"then retry the command."
        ),
        "rule_key": f"srt_network_allowlist:{hashlib.sha256(domain_list.encode()).hexdigest()[:12]}",
    }


def get_provider():
    return _provider


def _log_request(domain: str, decision: str) -> None:
    try:
        SETTINGS_DIR.mkdir(parents=True, exist_ok=True)
        with AUDIT_LOG.open("a") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {domain} {decision}\n")
    except Exception:
        pass


def on_allow(domain: str) -> bool:
    """Add *domain* to the persistent allow-list. Returns True when added."""
    settings = _load_settings()
    allowed = settings.setdefault("network", {}).setdefault("allowedDomains", [])
    if domain not in allowed:
        allowed.append(domain)
        _save_settings(settings)
        _log_request(domain, "allowed")
        return True
    return False


def register(ctx) -> None:
    ctx.register_terminal_environment_provider(_provider)
    ctx.register_hook("pre_tool_call", pre_tool_call_hook)
    logger.info("srt-sandbox plugin registered (settings: %s)", SETTINGS_FILE)
