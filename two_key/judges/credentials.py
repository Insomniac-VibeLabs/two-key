"""Credential providers for Path B judge connectors.

Judges connect to whichever AI the user picks, by "api or username/password
or single sign on login".

What is implemented:
- ``EnvApiKey``: an API key read from an environment variable at call
  time. Working.
- ``KeyringApiKey``: an API key read from the OS secret store through the
  optional ``keyring`` package. Working if keyring is installed.
- ``StaticToken``: for tests only.
- ``CallbackTokenProvider``: calls a user-supplied function that returns
  a bearer token. This is the generic hook for any SSO/OAuth/session flow
  the user wires up.
- ``BasicAuthCredential``: a username and a password, each read from its own
  environment variable, sent as HTTP Basic auth. HTTPS only: a judge or agent
  with this credential and a plain-HTTP ``base_url`` refuses to start.

The OAuth device-code grant is not supported. Bring such a token
in through ``env`` or ``callback``.

Secrets are never hardcoded, logged, or written to the ledger, and
``repr()`` output is redacted.
"""

from __future__ import annotations

import abc
import base64
import os
from typing import Callable

from ..agent_meta import type_tag


class CredentialError(RuntimeError):
    """A credential could not be obtained. The judge abstains (fail closed)."""


class CredentialProvider(abc.ABC):
    kind: str = "abstract"

    @abc.abstractmethod
    def get_token(self) -> str:
        """Return a secret (API key or bearer token). Raise CredentialError on failure."""

    def __repr__(self) -> str:  # never reveal secrets
        return f"<{type(self).__name__} kind={self.kind} [redacted]>"


class NoCredential(CredentialProvider):
    kind = "none"

    def get_token(self) -> str:
        return ""


class EnvApiKey(CredentialProvider):
    kind = "env"

    def __init__(self, var: str):
        if not var or not isinstance(var, str):
            raise ValueError("env credential requires a variable name")
        self.var = var

    def get_token(self) -> str:
        v = os.environ.get(self.var)
        if not v:
            raise CredentialError(f"environment variable {self.var} is not set")
        return v

    def __repr__(self) -> str:
        return f"<EnvApiKey var={self.var} [redacted]>"


class KeyringApiKey(CredentialProvider):
    kind = "keyring"

    def __init__(self, service: str, username: str):
        self.service, self.username = service, username

    def get_token(self) -> str:
        try:
            import keyring  # optional dependency
        except ImportError as e:
            raise CredentialError("keyring package not installed (pip install keyring)") from e
        v = keyring.get_password(self.service, self.username)
        if not v:
            raise CredentialError(f"no secret in keyring for {self.service}/{self.username}")
        return v


class StaticToken(CredentialProvider):
    """Tests only. Do not use it to hardcode real keys."""

    kind = "static"

    def __init__(self, token: str):
        self._t = token

    def get_token(self) -> str:
        return self._t


class CallbackTokenProvider(CredentialProvider):
    """Generic SSO/OAuth hook: ``fn()`` returns a current bearer token."""

    kind = "callback"

    def __init__(self, fn: Callable[[], str]):
        self._fn = fn

    def get_token(self) -> str:
        try:
            t = self._fn()
        except Exception as e:
            raise CredentialError(f"token callback failed: {type_tag(e)}") from e
        if not t or not isinstance(t, str):
            raise CredentialError("token callback returned no token")
        return t


class BasicAuthCredential(CredentialProvider):
    """A username and password from two environment variables, sent as HTTP Basic auth over HTTPS only.

    ``get_token`` returns the ``username:password`` pair. Two-Key fingerprints that pair (PBKDF2 under the
    per-install key, ``identity.password_fingerprint``) to tell a judge from the monitored agent; the pair itself
    is never stored or logged."""

    kind = "basic"

    def __init__(self, username_var: str, password_var: str):
        for v in (username_var, password_var):
            if not v or not isinstance(v, str):
                raise ValueError("basic credential requires username_env and password_env variable names")
        self.username_var, self.password_var = username_var, password_var

    def get_token(self) -> str:
        user, password = os.environ.get(self.username_var), os.environ.get(self.password_var)
        if not user:
            raise CredentialError(f"environment variable {self.username_var} is not set")
        if not password:
            raise CredentialError(f"environment variable {self.password_var} is not set")
        if ":" in user:
            raise CredentialError(f"the username in {self.username_var} must not contain ':' (HTTP Basic)")
        return f"{user}:{password}"

    def __repr__(self) -> str:
        return f"<BasicAuthCredential user={self.username_var} password={self.password_var} [redacted]>"


def basic_authorization(pair: str) -> dict:
    """The HTTP Basic ``Authorization`` header for a ``username:password`` pair (HTTPS only; callers check)."""
    return {"Authorization": "Basic " + base64.b64encode(pair.encode("utf-8")).decode("ascii")}
