# Attack Graph Generator & Risk Visualizer

Builds attack graphs from real network and vulnerability data, ranks paths by CVSS risk, and visualizes them.

## Setup
    pip install -r requirements.txt
    python -m ingest.nvd_loader --api --pages 1     # pull CVEs from NVD
    pytest

## Layout
ingest/ (raw data -> objects), core/ (graph + scoring), db/ (SQLite), web/ (Flask UI), reports/ (export)
