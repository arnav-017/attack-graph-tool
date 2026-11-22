from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
RAW_DIR = DATA_DIR / "raw"
DB_PATH = DATA_DIR / "attackgraph.db"

# NVD API 2.0. A free API key raises the rate limit (50 req/30s vs 5 req/30s).
# Request one at https://nvd.nist.gov/developers/request-an-api-key
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = None  # or set via env var NVD_API_KEY
