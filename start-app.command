#!/bin/bash
# Double-click this file in Finder to start the nmap-triage web app.
# The first run creates .venv and installs the requirements; after that it
# starts straight away and opens the page in your browser.

cd "$(dirname "$0")" || exit 1

pause_on_error() {
  echo
  read -r -p "$1 Press Return to close this window."
  exit 1
}

if [ ! -x .venv/bin/python ]; then
  echo "First run: setting up a Python environment (about a minute)..."
  python3 -m venv .venv || pause_on_error "Couldn't create .venv. Is Python 3 installed?"
fi

if ! .venv/bin/python -c "import flask, defusedxml, requests, dotenv" 2>/dev/null; then
  echo "Installing requirements..."
  .venv/bin/python -m pip install -q -r requirements.txt || pause_on_error "Installing requirements failed."
fi

.venv/bin/python app.py
status=$?
if [ "$status" -ne 0 ] && [ "$status" -ne 130 ]; then
  pause_on_error "nmap-triage stopped with an error."
fi
