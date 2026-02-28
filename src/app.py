#!/usr/bin/env python3
"""Terminal-based ethical hacking assistant.

This tool is designed for authorized security work only.
It provides planning support, checklists, and defensive guidance.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from textwrap import dedent


BLOCKED_KEYWORDS = {
    "exploit",
    "payload",
    "ddos",
    "ransomware",
    "phishing",
    "bypass",
    "malware",
    "backdoor",
    "privilege escalation",
}


@dataclass
class SessionState:
    """Stores runtime state for the assistant session."""

    user_name: str
    target: str = ""
    authorization_confirmed: bool = False
    notes: list[str] = field(default_factory=list)


class EthicalHackingAssistant:
    """Simple terminal AI assistant focused on lawful security workflows."""

    def __init__(self, state: SessionState) -> None:
        self.state = state

    def welcome(self) -> str:
        return dedent(
            f"""
            ====================================
            Ethical Hacking Terminal Assistant
            ====================================
            Hello, {self.state.user_name}.

            This assistant supports defensive security tasks only.
            Use it only with explicit written authorization.
            Type 'help' to view commands.
            """
        ).strip()

    def help_text(self) -> str:
        return dedent(
            """
            Available commands:
              help                  Show this menu
              scope                 Set target and confirm authorization
              plan                  Generate a safe pentest plan
              checklist             Show pre-engagement checklist
              explain <topic>       Explain defensive security concepts
              ask <question>        Ask a security question
              note <text>           Save a session note
              notes                 Show notes
              exit                  Quit
            """
        ).strip()

    def set_scope(self) -> str:
        target = input("Target (company/system): ").strip()
        auth = input("Do you have written authorization? (yes/no): ").strip().lower()

        self.state.target = target
        self.state.authorization_confirmed = auth in {"yes", "y"}

        if not self.state.authorization_confirmed:
            return (
                "Authorization not confirmed. I can only provide high-level defensive "
                "guidance until authorization is verified."
            )

        return (
            f"Scope saved for '{self.state.target}'. Authorization confirmed. "
            "Proceed with responsible testing."
        )

    def checklist(self) -> str:
        return dedent(
            """
            Pre-engagement checklist:
              1. Written permission and legal approval obtained.
              2. Scope boundaries documented (IPs, domains, apps, dates).
              3. Out-of-scope assets listed.
              4. Emergency contacts and stop conditions defined.
              5. Logging enabled for all test actions.
              6. Data handling and disclosure plan agreed.
            """
        ).strip()

    def plan(self) -> str:
        target = self.state.target or "(no target set)"
        mode = "authorized" if self.state.authorization_confirmed else "unverified"

        return dedent(
            f"""
            Engagement plan for: {target}
            Authorization status: {mode}

            Phase 1 - Preparation
              - Confirm scope and rules of engagement.
              - Collect architecture and asset inventory.

            Phase 2 - Non-intrusive assessment
              - Passive recon from approved sources.
              - Security baseline review (patching, MFA, exposed services).

            Phase 3 - Controlled validation
              - Run approved scanners with safe settings.
              - Validate findings without service disruption.

            Phase 4 - Reporting and remediation
              - Prioritize findings by severity and business impact.
              - Propose fixes and compensating controls.
              - Re-test critical issues after remediation.
            """
        ).strip()

    def explain(self, topic: str) -> str:
        topic_lower = topic.lower()
        if any(word in topic_lower for word in BLOCKED_KEYWORDS):
            return (
                "I can't help with offensive or harmful instructions. "
                "I can explain defense, detection, and secure configuration instead."
            )

        library = {
            "owasp": "OWASP Top 10 is a list of common web app risks. Use it to prioritize secure coding and testing.",
            "nmap": "Use Nmap only on authorized targets to identify exposed ports/services and reduce attack surface.",
            "siem": "A SIEM collects and correlates logs to detect threats and support incident response.",
            "threat modeling": "Threat modeling helps teams identify abuse paths early and add mitigations during design.",
        }

        return library.get(
            topic_lower,
            "I can provide a high-level defensive explanation. Try topics like: OWASP, SIEM, Nmap, threat modeling.",
        )

    def ask(self, question: str) -> str:
        text = question.strip().lower()
        if not text:
            return "Please enter a question after 'ask'."

        if any(word in text for word in BLOCKED_KEYWORDS):
            return (
                "Request declined. I only support authorized, defensive cybersecurity guidance. "
                "Try asking about risk reduction, hardening, monitoring, or reporting."
            )

        if "start" in text or "begin" in text:
            return "Start with 'scope', then 'checklist', then 'plan'. Keep evidence and logs for every action."

        if "report" in text:
            return "A good report includes: summary, scope, methodology, findings, risk ratings, proof, and remediation steps."

        return (
            "High-level guidance: define scope, minimize impact, log actions, and focus on remediation outcomes. "
            "Use 'explain <topic>' for concept help."
        )

    def add_note(self, note: str) -> str:
        note = note.strip()
        if not note:
            return "Cannot save an empty note."
        stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.state.notes.append(f"[{stamp}] {note}")
        return "Note saved."

    def list_notes(self) -> str:
        if not self.state.notes:
            return "No notes yet."
        return "\n".join(self.state.notes)


def run() -> None:
    name = input("Your name: ").strip() or "Analyst"
    assistant = EthicalHackingAssistant(SessionState(user_name=name))
    print(assistant.welcome())

    while True:
        raw = input("\nethic-ai> ").strip()
        if not raw:
            continue

        command, *rest = raw.split(maxsplit=1)
        argument = rest[0] if rest else ""

        if command == "help":
            print(assistant.help_text())
        elif command == "scope":
            print(assistant.set_scope())
        elif command == "checklist":
            print(assistant.checklist())
        elif command == "plan":
            print(assistant.plan())
        elif command == "explain":
            print(assistant.explain(argument))
        elif command == "ask":
            print(assistant.ask(argument))
        elif command == "note":
            print(assistant.add_note(argument))
        elif command == "notes":
            print(assistant.list_notes())
        elif command == "exit":
            print("Goodbye. Stay legal, safe, and ethical.")
            break
        else:
            print("Unknown command. Type 'help'.")


if __name__ == "__main__":
    run()
