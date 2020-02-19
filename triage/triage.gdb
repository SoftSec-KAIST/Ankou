shell rm -rf triage.txt
shell rm -rf hash.txt
set pagination off
set logging file triage.txt
set logging on
source triage.py
triage 5
q