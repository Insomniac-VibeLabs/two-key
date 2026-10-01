"""Deployment mode: one early, global setting, ``personal`` or ``enterprise``.

The author (CONCEPTION_NOTES.md Entry 9, 2026-09-30): a local ledger is fine for
personal use; for enterprise use, anchor to an enterprise-level (not fully
public) blockchain; tie the configuration to whether Two-Key is used
personally or by an enterprise, as an early setting, because "many other
settings will likely need to be addressed based on the use case".

- **Where it is set.** ``TwoKey(deployment_mode=...)``, the environment
  variable ``TWOKEY_DEPLOYMENT_MODE``, or ``deployment_mode:`` in a config
  file (JSON or YAML, ``TwoKey(deployment_config=path)``). Default
  ``personal``, so behavior is unchanged. If more than one source sets it,
  they must agree.
- **Set once.** The mode is recorded in the ledger's first
  ``constitution_loaded`` entry (``deployment``). Reopening that ledger in the
  other mode is refused. A ledger created before this setting existed counts
  as ``personal``.
- **What it changes today.** Anchoring and identities:
  - ``personal``: local ledger as before; anchor ``None``,
    ``NullAnchor``, or ``LocalFileAnchor``. Optional seed-phrase key
    backup (seedphrase.py; Entry 11).
  - ``enterprise``: every signed ledger head is also anchored to a
    permissioned chain through a ``PermissionedLedgerAnchor``. With none
    configured, startup fails (PLACEHOLDER pending a maintainer decision).
  - ``enterprise`` also uses PKI identities (pki.py; CONCEPTION_NOTES
    Entry 11): a ``pki`` configuration and a principal certificate are
    required at startup (PLACEHOLDER pending a maintainer decision), and seed phrases are
    refused.
- **Other mode-dependent settings** hang off ``DeploymentConfig.mode_defaults``
  later. It is empty on purpose: nothing else changes with the mode until
  The maintainers decide. Candidates are listed in docs/DEPLOYMENT_MODES.md.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .anchoring import Anchor, LocalFileAnchor, NullAnchor, PermissionedLedgerAnchor

MODES = ("personal", "enterprise")
DEFAULT_MODE = "personal"
ENV_VAR = "TWOKEY_DEPLOYMENT_MODE"
CONFIG_KEY = "deployment_mode"


class DeploymentConfigError(ValueError):
    pass


@dataclass(frozen=True)
class DeploymentConfig:
    mode: str
    source: str            # "argument", "environment", "config:<path>", "default", or several joined by "+"

    @property
    def is_enterprise(self) -> bool:
        return self.mode == "enterprise"

    def mode_defaults(self) -> dict:
        """Settings whose default depends on the mode. Empty: none yet (docs/DEPLOYMENT_MODES.md)."""
        return {}

    def to_record(self) -> dict:
        return {"mode": self.mode, "source": self.source}


def _norm(value: Any, where: str) -> str:
    if not isinstance(value, str) or value.strip().casefold() not in MODES:
        raise DeploymentConfigError(f"{where}: deployment_mode must be one of {MODES} (got {value!r})")
    return value.strip().casefold()


def load_config_file(path: str | Path) -> Mapping[str, Any]:
    """Read a JSON or YAML mapping (YAML needs PyYAML)."""
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if p.suffix.lower() in (".yaml", ".yml"):
        try:
            import yaml
        except ImportError:
            raise DeploymentConfigError("YAML config files need PyYAML; use JSON instead") from None
        data = yaml.safe_load(text)
    else:
        data = json.loads(text)
    if not isinstance(data, Mapping):
        raise DeploymentConfigError(f"{p}: the config file must be a mapping")
    return data


def resolve(explicit: str | None = None, *, config_path: str | Path | None = None,
            env: Mapping[str, str] | None = None) -> DeploymentConfig:
    """The deployment mode from the argument, the environment, and the config file. All that are set must
    agree; none set means ``personal``."""
    env = os.environ if env is None else env
    found: list[tuple[str, str]] = []
    if explicit is not None:
        found.append(("argument", _norm(explicit, "argument")))
    if env.get(ENV_VAR) not in (None, ""):
        found.append(("environment", _norm(env[ENV_VAR], ENV_VAR)))
    if config_path is not None:
        data = load_config_file(config_path)
        if CONFIG_KEY in data:
            found.append((f"config:{config_path}", _norm(data[CONFIG_KEY], str(config_path))))
    modes = {m for _, m in found}
    if len(modes) > 1:
        raise DeploymentConfigError("deployment_mode is set differently in "
                                    + ", ".join(f"{src} ({m})" for src, m in found))
    if not found:
        return DeploymentConfig(DEFAULT_MODE, "default")
    return DeploymentConfig(found[0][1], "+".join(src for src, _ in found))


def check_anchor(config: DeploymentConfig, anchor: Anchor | None) -> None:
    """Enterprise mode needs a permissioned-chain anchor; personal mode uses a local one (or none)."""
    if config.is_enterprise:
        if not isinstance(anchor, PermissionedLedgerAnchor):
            raise DeploymentConfigError(
                "deployment_mode 'enterprise' requires a permissioned-ledger anchor (anchor=FabricAnchor(...), "
                "RestPermissionedAnchor(...), or another PermissionedLedgerAnchor); none is configured. "
                "This startup check is a placeholder pending a maintainer decision (docs/DEPLOYMENT_MODES.md)")
    elif anchor is not None and not isinstance(anchor, (NullAnchor, LocalFileAnchor)):
        raise DeploymentConfigError("deployment_mode 'personal' keeps the ledger local: use no anchor, NullAnchor, "
                                    "or LocalFileAnchor (set deployment_mode='enterprise' for a permissioned chain)")


def check_pki(config: DeploymentConfig, pki: Any) -> None:
    """Enterprise mode uses PKI identities (Entry 11): refuse to start without a PKI configuration."""
    if config.is_enterprise and pki is None:
        raise DeploymentConfigError(
            "deployment_mode 'enterprise' requires PKI identities (pki=PkiConfig(...) or a 'pki:' section in the "
            "deployment config, plus principal_credential=); none is configured. This startup check is a "
            "placeholder pending a maintainer decision (docs/KEYS_AND_PKI.md)")


def recorded_mode(ledger: Any) -> str | None:
    """The mode recorded in an existing ledger's first constitution_loaded entry (``personal`` for a ledger
    from before this setting); None for an empty ledger."""
    for e in ledger.entries:
        if e.kind == "constitution_loaded":
            dep = e.body.get("deployment")
            return dep.get("mode", DEFAULT_MODE) if isinstance(dep, Mapping) else DEFAULT_MODE
    return None
