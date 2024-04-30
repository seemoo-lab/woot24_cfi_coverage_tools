#!/bin/sh

cwd=$(pwd)

/opt/ghidra/support/analyzeHeadless /tmp "$3" -import "$1" -scriptPath "$cwd" -readOnly -deleteProject -analysisTimeoutPerFile 1200 -postScript internal_analysis_ghidra.py "$2"
