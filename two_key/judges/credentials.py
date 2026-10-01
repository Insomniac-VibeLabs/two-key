"""Credential providers for Path B judge connectors.

This follows Stephan's conception (CONCEPTION_NOTES.md entry 1): judges
connect to whichever AI the user picks, by "api or username/password or
single sign on login".

What is implemented:
- ``EnvApiKey``: an API key read from an environment variable at call
  time. Working.
- ``KeyringApiKey``: an API key read from the OS secret store through the
  optional ``keyring`` package. Working if keyring is installed.
- ``StaticToken``: for tests only.
- ``CallbackTokenProvider``: calls a user-supplied function that returns
  a bearer token. This is the generic hook for any SSO/OAuth/session flow
  the user wires up.

Interfaces with documented stubs (no vendor login is faked):
- ``UsernamePasswordProvider``: needs a user-supplied ``login(username,
  password) -> token`` hook. Model vendors generally do not offer a
  password-based API login, so no default is provided.
- ``OAuthDeviceCodeProvider``: the OAuth 2.0 Device Authorization Grant
  (RFC 8628) hook points. ``get_token`` raises NotImplementedError unless
  hooks are supplied.

Secrets are never hardcoded, logged, or written to the ledger, and
``repr()`` output is redacted.
"""

from __future__ import annotations

import abc
import os
from typing import Callable


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
            raise CredentialError(f"token callback failed: {type(e).__name__}") from e
        if not t or not isinstance(t, str):
            raise CredentialError("token callback returned no token")
        return t


class UsernamePasswordProvider(CredentialProvider):
    """Username/password login. INTERFACE ONLY: supply a ``login`` hook.

    ``login(username, password) -> token`` must perform the provider's real
    login flow. For example, a self-hosted model gateway that issues session
    tokens. The password is read from an environment variable at call time
    and is not stored on the object.
    """

    kind = "username_password"

    def __init__(self, username: str, password_env: str,
                 login: Callable[[str, str], str] | None = None):
        self.username, self.password_env, self._login = username, password_env, login
        self._cached: str | None = None

    def get_token(self) -> str:
        if self._login is None:
            raise NotImplementedError(
                "UsernamePasswordProvider needs a login(username, password) -> token hook for your "
                "provider; none is built in because model vendors do not offer password API logins.")
        if self._cached:
            return self._cached
        pw = os.environ.get(self.password_env)
        if not pw:
            raise CredentialError(f"environment variable {self.password_env} is not set")
        try:
            self._cached = self._login(self.username, pw)
        except Exception as e:
            raise CredentialError(f"login failed: {type(e).__name__}") from e
        return self._cached


class OAuthDeviceCodeProvider(CredentialProvider):
    """OAuth 2.0 Device Authorization Grant (RFC 8628). DOCUMENTED STUB.

    Intended flow, to be implemented for a specific identity provider:
      1. POST ``device_authorization_endpoint`` with client_id and scope, which
         returns device_code, user_code, verification_uri, and interval.
      2. Show the user ``verification_uri`` and ``user_code`` (hook ``prompt_user``).
      3. Poll ``token_endpoint`` with grant_type=
         urn:ietf:params:oauth:grant-type:device_code until an access_token
         arrives. Honor ``slow_down`` and ``authorization_pending``.
      4. Cache the access/refresh tokens in the OS secret store, never on disk
         in plaintext, and refresh before expiry.

    Supply ``fetch_token`` (a callable that performs steps 1-4 and returns an
    access token) to make this provider work. Without it, ``get_token``
    raises NotImplementedError. No vendor endpoints are preconfigured.
    """

    kind = "oauth_device_code"

    def __init__(self, client_id: str, device_authorization_endpoint: str, token_endpoint: str,
                 scope: str = "", fetch_token: Callable[["OAuthDeviceCodeProvider"], str] | None = None,
                 prompt_user: Callable[[str, str], None] | None = None):
        self.client_id = client_id
        self.device_authorization_endpoint = device_authorization_endpoint
        self.token_endpoint = token_endpoint
        self.scope = scope
        self._fetch = fetch_token
        self.prompt_user = prompt_user

    def get_token(self) -> str:
        if self._fetch is None:
            raise NotImplementedError(
                "OAuthDeviceCodeProvider is an interface stub: supply fetch_token= implementing RFC 8628 "
                "for your identity provider (see class docstring).")
        try:
            t = self._fetch(self)
        except NotImplementedError:
            raise
        except Exception as e:
            raise CredentialError(f"device-code flow failed: {type(e).__name__}") from e
        if not t:
            raise CredentialError("device-code flow returned no token")
        return t
