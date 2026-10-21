# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""Local Ollama judge (native /api/chat with format=json). No auth by default.

``local_weights`` defaults to True only when ``base_url`` is a loopback or
private-range address (two_key.netloc). An Ollama cloud model on ollama.com
or any other remote host defaults to False. Declaring ``local_weights: true``
on a remote host does not make the judge local: ``is_local()`` also requires
the host to be loopback or private, and ``is_cloud()`` ignores the flag. The
flag is a declaration, not an attestation, and ``weights_sha256`` is
recorded, not verified.

A model whose name ends in ``:cloud`` or ``-cloud`` (for example
``gpt-oss:120b-cloud``) is an Ollama cloud model: the local daemon forwards
the prompt to ollama.com. Such a judge is cloud and never local, even on
127.0.0.1.

``keep_alive`` asks Ollama not to unload the weights between ballots. It does
not change the ballot.
"""

from __future__ import annotations

from ..netloc import host_is_local, model_is_cloud, url_host
from .llm import LLMJudge


def is_ollama_cloud_model(model) -> bool:
    return isinstance(model, str) and model_is_cloud(model)


class OllamaJudge(LLMJudge):
    default_auth_header = "none"

    def __init__(self, *a, **kw):
        if len(a) < 4:
            kw.setdefault("base_url", "http://localhost:11434")
        base_url = a[3] if len(a) > 3 else kw["base_url"]
        model = kw.get("model", a[2] if len(a) > 2 else None)
        if kw.get("local_weights") is None:
            kw["local_weights"] = host_is_local(url_host(base_url)) and not is_ollama_cloud_model(model)
        super().__init__(*a, **kw)

    # is_cloud / is_local: LLMJudge treats a :cloud / -cloud model as cloud for every judge class.

    def _request(self, system: str, user: str):
        body = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "stream": False,
            "format": "json",
            "keep_alive": "10m",
            "options": {"temperature": 0},
        }
        return f"{self.base_url}/api/chat", body

    def _extract_text(self, resp: dict) -> str:
        return resp["message"]["content"]
