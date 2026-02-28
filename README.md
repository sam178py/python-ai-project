# Python Ethical Hacking Assistant (CLI + Local GUI)

A Python **defensive security assistant** with both CLI and GUI modes.

> ⚠️ Legal use only. This project refuses harmful/offensive requests.

## Features

- Local GUI app (Tkinter) and CLI mode
- Target IP/domain capture and validation
- Ping checks and local network visibility
- Scope + authorization tracking
- Checklist, planning, notes, and report export
- "Normal AI" chat behavior in GUI:
  - Uses OpenAI chat model if `OPENAI_API_KEY` is set
  - Falls back to built-in local safe responses if no API key
- Optional voice input and voice output in GUI
- Basic internet tools in GUI chat:
  - `web <url>` fetch preview
  - `webai <url> | <question>` fetch + AI summary/Q&A

## Run locally

### CLI

```bash
python3 src/app.py
```

### GUI (local desktop app)

```bash
python3 src/gui_app.py
```

This starts a **local window on your machine** (Tkinter desktop GUI).

## Enable "normal AI" model responses

1. Install the OpenAI SDK:

```bash
pip install openai
```

2. Set your API key:

```bash
export OPENAI_API_KEY="your_key_here"
```

3. Optional model override (default: `gpt-4o-mini`):

```bash
export OPENAI_MODEL="gpt-4o-mini"
```

If you skip this setup, the app still works with the local safe fallback model.

## Optional voice dependencies

```bash
pip install speechrecognition pyaudio pyttsx3
```

If these are not installed, voice controls degrade gracefully.

## Reports

Reports are exported to the `data/` folder as markdown files.
