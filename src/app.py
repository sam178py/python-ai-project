#!/usr/bin/env python3
"""Terminal-based ethical hacking assistant.

This tool is designed for authorized security work only.
It provides planning support, checklists, and defensive guidance.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import ipaddress
import platform
import re
import shutil
import socket
import subprocess
from textwrap import dedent


NETWORK_COMMAND_CANDIDATES = {
    "arp": [["arp", "-a"], ["ip", "neigh"]],
    "ports": [["ss", "-tuln"], ["netstat", "-tuln"], ["lsof", "-i", "-P", "-n"]],
}


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

DOMAIN_REGEX = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$")


@dataclass
class SessionState:
    """Stores runtime state for the assistant session."""

    user_name: str
    target: str = ""
    authorization_confirmed: bool = False
    authorization_reference: str = ""
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
              help                          Show this menu
              scope                         Set target and confirm authorization
              target <ip-or-domain>         Set target quickly with validation
              status                        Show current session status
              ping <ip-or-domain>           Ping a host for basic reachability
              local-network                 Show local IPs, ARP neighbors, and open local ports
              plan                          Generate a safe pentest plan
              checklist                     Show pre-engagement checklist
              explain <topic>               Explain defensive security concepts
              ask <question>                Ask a security question
              note <text>                   Save a session note
              notes                         Show notes
              export-report [filename]      Export session report to data/
              exit                          Quit
            """
        ).strip()

    @staticmethod
    def _is_valid_target(value: str) -> bool:
        candidate = value.strip()
        if not candidate:
            return False

        try:
            ipaddress.ip_address(candidate)
            return True
        except ValueError:
            pass

        return bool(DOMAIN_REGEX.match(candidate))

    def set_target(self, target: str) -> str:
        target = target.strip()
        if not target:
            return "Please provide a target IP or domain, e.g. 'target 192.168.1.10'."

        if not self._is_valid_target(target):
            return "Invalid target format. Use a valid IPv4/IPv6 address or domain."

        self.state.target = target
        return f"Target set to '{target}'."

    def set_scope(self) -> str:
        target = input("Target (IP/domain/company): ").strip()
        auth = input("Do you have written authorization? (yes/no): ").strip().lower()
        reference = input("Authorization reference (ticket/email/contract): ").strip()

        if target:
            if not self._is_valid_target(target):
                return "Scope not saved: target must be a valid IP or domain."
            self.state.target = target

        self.state.authorization_confirmed = auth in {"yes", "y"}
        self.state.authorization_reference = reference

        if not self.state.authorization_confirmed:
            return (
                "Authorization not confirmed. I can only provide high-level defensive "
                "guidance until authorization is verified."
            )

        return (
            f"Scope saved for '{self.state.target or 'unspecified target'}'. Authorization confirmed. "
            "Proceed with responsible testing."
        )

    def status(self) -> str:
        return dedent(
            f"""
            Session status:
              User: {self.state.user_name}
              Target: {self.state.target or '(not set)'}
              Authorization: {'confirmed' if self.state.authorization_confirmed else 'unverified'}
              Authorization ref: {self.state.authorization_reference or '(not set)'}
              Notes saved: {len(self.state.notes)}
            """
        ).strip()

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

    def ping_target(self, target: str) -> str:
        host = target.strip() or self.state.target
        if not host:
            return "Provide a host with 'ping <ip-or-domain>' or set one using 'target'."

        if not self._is_valid_target(host):
            return "Invalid host format. Use a valid IPv4/IPv6 address or domain."

        if shutil.which("ping") is None:
            return "'ping' command is not available in this environment."

        count_flag = "-n" if platform.system().lower() == "windows" else "-c"
        try:
            result = subprocess.run(
                ["ping", count_flag, "4", host],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return f"Ping timed out for {host}."

        output = (result.stdout or result.stderr).strip()
        if not output:
            output = "No ping output was returned."

        title = f"Ping results for {host} (exit code {result.returncode}):"
        return f"{title}\n{output}"

    @staticmethod
    def _run_command(command: list[str]) -> str:
        if shutil.which(command[0]) is None:
            return f"- {command[0]} not available"
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=10)
        except subprocess.TimeoutExpired:
            return f"- {' '.join(command)} timed out"
        except OSError as exc:
            return f"- failed to execute {' '.join(command)}: {exc}"

        text = (result.stdout or result.stderr).strip()
        return text or "(no output)"

    def _run_first_available(self, candidates: list[list[str]]) -> str:
        outputs: list[str] = []
        for command in candidates:
            output = self._run_command(command)
            if not output.startswith(f"- {command[0]} not available"):
                return f"$ {' '.join(command)}\n{output}"
            outputs.append(output)
        return "\n".join(outputs)

    def local_network_summary(self) -> str:
        lines: list[str] = []

        hostname = socket.gethostname()
        lines.append(f"Hostname: {hostname}")

        try:
            host_ips = sorted({entry[4][0] for entry in socket.getaddrinfo(hostname, None) if entry[0] == socket.AF_INET})
            lines.append(f"Local IPv4: {', '.join(host_ips) if host_ips else '(none found)'}")
        except socket.gaierror:
            lines.append("Local IPv4: (resolution failed)")

        lines.append("\nARP neighbors:")
        lines.append(self._run_first_available(NETWORK_COMMAND_CANDIDATES["arp"]))

        lines.append("\nOpen local listening ports:")
        lines.append(self._run_first_available(NETWORK_COMMAND_CANDIDATES["ports"]))

        return "\n".join(lines)

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

        if "hack" in text:
            return "I can't help with hacking. I can help with legal security testing workflows and reporting."

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

    def export_report(self, filename: str = "") -> str:
        safe_name = (filename.strip() or f"report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.md").replace("/", "-")
        if not safe_name.endswith(".md"):
            safe_name += ".md"

        output_dir = Path("data")
        output_dir.mkdir(parents=True, exist_ok=True)
        path = output_dir / safe_name

        content = dedent(
            f"""
            # Ethical Security Session Report

            - Generated: {datetime.now().isoformat(timespec='seconds')}
            - Analyst: {self.state.user_name}
            - Target: {self.state.target or '(not set)'}
            - Authorization: {'confirmed' if self.state.authorization_confirmed else 'unverified'}
            - Authorization reference: {self.state.authorization_reference or '(not set)'}

            ## Notes
            {chr(10).join(f'- {n}' for n in self.state.notes) if self.state.notes else '- No notes recorded.'}

            ## Next Actions
            - Validate findings with approved tooling.
            - Prioritize remediation by risk.
            - Re-test after fixes.
            """
        ).strip() + "\n"

        path.write_text(content, encoding="utf-8")
        return f"Report exported: {path}"


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
        elif command == "target":
            print(assistant.set_target(argument))
        elif command == "status":
            print(assistant.status())
        elif command == "ping":
            print(assistant.ping_target(argument))
        elif command == "local-network":
            print(assistant.local_network_summary())
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
        elif command == "export-report":
            print(assistant.export_report(argument))
        elif command == "exit":
            print("Goodbye. Stay legal, safe, and ethical.")
            break
        else:
            print("Unknown command. Type 'help'.")


if __name__ == "__main__":
    run()
