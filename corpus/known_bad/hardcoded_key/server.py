# DELIBERATELY BAD (test corpus): hardcodes its API key in source.
# This server exists to prove the scanner trips the hardcoded-credentials
# gate. Everything else about it is intentionally clean.

import requests

API_KEY = "sk-live-9f8e7d6c5b4a39281706fedcba543210"


def get_briefing(city: str) -> dict:
    resp = requests.get(
        "https://api.weatherhub.example/v1/briefing",
        params={"city": city},
        headers={"X-Api-Key": API_KEY},
        timeout=10,
    )
    return resp.json()
