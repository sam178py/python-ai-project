# python-ai-project
My AI project using Python and Codex
# Python Ethical Hacking Assistant (Unified Core)

A Python **defensive security assistant** with CLI and local GUI, both powered by one unified core file: `src/app.py`.

> ⚠️ Legal use only. This assistant refuses offensive/harmful cybersecurity requests.

## What is unified now

- AI engine + security workflow logic are in `src/app.py`
- CLI mode runs from `src/app.py`
- GUI mode also runs from `src/app.py --gui`
- `src/gui_app.py` is now only a small compatibility launcher

## Install dependencies

```bash
python3 -m pip install -r requirements.txt
```

Voice dependencies included in `requirements.txt`:
- `SpeechRecognition`
- `pyttsx3`
- `pyaudio`

AI dependency included in `requirements.txt`:
- `openai`

## Set ChatGPT API key

```bash
export OPENAI_API_KEY="your_key_here"
```

Optional model override:

```bash
export OPENAI_MODEL="gpt-4o-mini"
```

If the key is set and `openai` is installed, ChatGPT is used. Otherwise local safe fallback is used.

## Run

### CLI mode

```bash
python3 src/app.py
```

### GUI mode (local desktop)

```bash
python3 src/app.py --gui
```

(Compatibility command also works: `python3 src/gui_app.py`.)

## Useful commands

- `help`
- `scope`
- `target 192.168.1.10`
- `status`
- `ping 8.8.8.8`
- `local-network`
- `ask <question>` / `ai <question>`
- `note <text>` / `notes`
- `export-report`

## Internet-enabled prompts in GUI chat

- `web <url>` (fetch preview)
- `webai <url> | <question>` (fetch and answer with context)

## Reports

Reports are exported to `data/` as markdown files.