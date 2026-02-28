#!/usr/bin/env python3
"""Tkinter GUI for the defensive security assistant.

Includes optional voice input/output and simple internet URL fetch support.
"""

from __future__ import annotations

import threading
import urllib.error
import urllib.parse
import urllib.request
import tkinter as tk
from tkinter import messagebox, scrolledtext

from ai_backend import AIBackend
from app import EthicalHackingAssistant, SessionState

try:
    import pyttsx3  # type: ignore
except Exception:  # optional dependency
    pyttsx3 = None

try:
    import speech_recognition as sr  # type: ignore
except Exception:  # optional dependency
    sr = None


class AssistantGUI:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Ethical Hacking Assistant GUI")
        self.root.geometry("900x650")

        self.assistant = EthicalHackingAssistant(SessionState(user_name="GUI Analyst"))
        self.ai = AIBackend()
        self.voice_enabled = tk.BooleanVar(value=False)

        self._build_ui()
        backend = "OpenAI" if self.ai.using_remote_model else "Local fallback"
        self._append(
            "assistant",
            f"Welcome! GUI running locally. AI backend: {backend}. Use chat for normal AI behavior.",
        )

    def _build_ui(self) -> None:
        top = tk.Frame(self.root)
        top.pack(fill="x", padx=10, pady=8)

        tk.Label(top, text="Target (IP/Domain):").pack(side="left")
        self.target_entry = tk.Entry(top, width=30)
        self.target_entry.pack(side="left", padx=6)
        tk.Button(top, text="Set Target", command=self._set_target).pack(side="left")

        tk.Button(top, text="Ping Target", command=self._ping).pack(side="left", padx=6)
        tk.Button(top, text="Local Network", command=self._local_network).pack(side="left")

        mid = tk.Frame(self.root)
        mid.pack(fill="both", expand=True, padx=10)

        self.chat_box = scrolledtext.ScrolledText(mid, wrap="word", state="disabled")
        self.chat_box.pack(fill="both", expand=True)

        controls = tk.Frame(self.root)
        controls.pack(fill="x", padx=10, pady=8)

        self.input_entry = tk.Entry(controls)
        self.input_entry.pack(side="left", fill="x", expand=True)
        self.input_entry.bind("<Return>", lambda _: self._send())

        tk.Button(controls, text="Send", command=self._send).pack(side="left", padx=5)
        tk.Button(controls, text="Listen", command=self._listen).pack(side="left")
        tk.Checkbutton(controls, text="Voice reply", variable=self.voice_enabled).pack(side="left", padx=8)

        bottom = tk.Frame(self.root)
        bottom.pack(fill="x", padx=10, pady=(0, 10))
        tk.Button(bottom, text="Export Report", command=self._export_report).pack(side="left")
        tk.Button(bottom, text="Status", command=self._status).pack(side="left", padx=5)
        tk.Button(bottom, text="Checklist", command=self._checklist).pack(side="left")

    def _append(self, sender: str, text: str) -> None:
        self.chat_box.configure(state="normal")
        self.chat_box.insert("end", f"{sender.upper()}: {text}\n\n")
        self.chat_box.configure(state="disabled")
        self.chat_box.see("end")
        if sender == "assistant" and self.voice_enabled.get():
            self._speak(text)

    def _speak(self, text: str) -> None:
        if pyttsx3 is None:
            return

        def run_tts() -> None:
            engine = pyttsx3.init()
            engine.say(text)
            engine.runAndWait()

        threading.Thread(target=run_tts, daemon=True).start()

    def _set_target(self) -> None:
        self._append("assistant", self.assistant.set_target(self.target_entry.get()))

    def _ping(self) -> None:
        self._append("assistant", self.assistant.ping_target(self.target_entry.get()))

    def _local_network(self) -> None:
        self._append("assistant", self.assistant.local_network_summary())

    def _status(self) -> None:
        self._append("assistant", self.assistant.status())

    def _checklist(self) -> None:
        self._append("assistant", self.assistant.checklist())

    def _export_report(self) -> None:
        self._append("assistant", self.assistant.export_report())

    def _listen(self) -> None:
        if sr is None:
            messagebox.showinfo("Voice input unavailable", "Install speechrecognition and pyaudio for microphone input.")
            return

        def worker() -> None:
            recognizer = sr.Recognizer()
            try:
                with sr.Microphone() as source:
                    audio = recognizer.listen(source, timeout=5, phrase_time_limit=8)
                text = recognizer.recognize_google(audio)
            except Exception as exc:
                self.root.after(0, lambda: messagebox.showerror("Voice input error", str(exc)))
                return
            self.root.after(0, lambda: self._handle_prompt(text))

        threading.Thread(target=worker, daemon=True).start()

    @staticmethod
    def _fetch_url(url_or_host: str) -> str:
        raw = url_or_host.strip()
        if not raw:
            return "Usage: web <url>"
        if not raw.startswith(("http://", "https://")):
            raw = f"https://{raw}"

        try:
            parsed = urllib.parse.urlparse(raw)
            if not parsed.netloc:
                return "Invalid URL."
            with urllib.request.urlopen(raw, timeout=8) as resp:
                body = resp.read(5000).decode("utf-8", errors="ignore")
                return f"Fetched {raw} (status {resp.status}). Preview:\n{body[:500]}"
        except urllib.error.URLError as exc:
            return f"Could not fetch URL: {exc}"

    def _handle_prompt(self, prompt: str) -> None:
        text = prompt.strip()
        if not text:
            return
        self._append("you", text)

        lower = text.lower()
        if lower.startswith("web "):
            self._append("assistant", self._fetch_url(text[4:]))
            return

        if lower.startswith("webai "):
            payload = text[6:].strip()
            if "|" not in payload:
                self._append("assistant", "Usage: webai <url> | <question>")
                return
            url, question = [part.strip() for part in payload.split("|", 1)]
            web_context = self._fetch_url(url)
            response = self.ai.chat(question or "Summarize the page safely.", web_context=web_context)
            self._append("assistant", f"{web_context}\n\nAI summary:\n{response}")
            return

        if lower.startswith("explain "):
            response = self.assistant.explain(text[8:])
        elif lower.startswith("ask "):
            response = self.assistant.ask(text[4:])
        elif lower.startswith("note "):
            response = self.assistant.add_note(text[5:])
        elif lower == "plan":
            response = self.assistant.plan()
        elif lower == "help":
            response = self.assistant.help_text()
        else:
            response = self.ai.chat(text)

        self._append("assistant", response)

    def _send(self) -> None:
        self._handle_prompt(self.input_entry.get())
        self.input_entry.delete(0, "end")


def run_gui() -> None:
    root = tk.Tk()
    AssistantGUI(root)
    root.mainloop()


if __name__ == "__main__":
    run_gui()
