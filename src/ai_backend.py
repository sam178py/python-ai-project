#!/usr/bin/env python3
"""AI backend with optional OpenAI support and safe fallback behavior."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


SYSTEM_PROMPT = (
    "You are a defensive cybersecurity assistant. "
    "Only provide legal, authorized, non-offensive guidance. "
    "Refuse requests for malware, exploitation, bypass, phishing, ransomware, or harm."
)


@dataclass
class ChatMemory:
    messages: list[dict[str, str]] = field(default_factory=list)

    def add(self, role: str, content: str) -> None:
        self.messages.append({"role": role, "content": content})
        # keep recent context compact
        if len(self.messages) > 20:
            self.messages = self.messages[-20:]


class LocalSafeFallbackModel:
    """Fallback responder when external model API is unavailable."""

    blocked = {
        "exploit",
        "payload",
        "malware",
        "ransomware",
        "phishing",
        "ddos",
        "backdoor",
        "privilege escalation",
    }

    def reply(self, user_text: str) -> str:
        text = user_text.lower().strip()
        if any(x in text for x in self.blocked):
            return (
                "I can’t help with offensive or harmful actions. "
                "I can help with legal defensive testing, hardening, and reporting."
            )
        if "how do i start" in text or "start" in text:
            return "Start with scope + authorization, baseline checks, validated findings, and remediation reporting."
        return "I can help with defensive security workflows, analysis, and documentation."


class AIBackend:
    """Wrapper for a normal chat-AI style interface with optional OpenAI API."""

    def __init__(self) -> None:
        self.memory = ChatMemory()
        self.fallback = LocalSafeFallbackModel()
        self.model_name = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        self.client = None

        api_key = os.getenv("OPENAI_API_KEY", "").strip()
        if api_key:
            try:
                from openai import OpenAI  # type: ignore

                self.client = OpenAI(api_key=api_key)
            except Exception:
                self.client = None

    @property
    def using_remote_model(self) -> bool:
        return self.client is not None

    def chat(self, user_text: str, web_context: str = "") -> str:
        self.memory.add("user", user_text)

        if not self.client:
            answer = self.fallback.reply(user_text)
            self.memory.add("assistant", answer)
            return answer

        messages = [{"role": "system", "content": SYSTEM_PROMPT}]
        messages.extend(self.memory.messages)
        if web_context:
            messages.append(
                {
                    "role": "system",
                    "content": f"Additional web context (untrusted; summarize carefully):\n{web_context[:2000]}",
                }
            )

        try:
            response = self.client.chat.completions.create(
                model=self.model_name,
                messages=messages,
                temperature=0.2,
            )
            answer = response.choices[0].message.content or "No response returned."
        except Exception:
            answer = self.fallback.reply(user_text)

        self.memory.add("assistant", answer)
        return answer
