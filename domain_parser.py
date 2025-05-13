


import re
import requests
import sys

OWNER = "AdguardTeam"
REPO = "HostlistsRegistry"
ASSETS_DIR = "assets"
TOKEN = None


session = requests.Session()

if TOKEN:
    session.headers.update({"Authorization": f"token {TOKEN}"})


def get_unwanted_filters(filter_numbers):
    return {f"filter_{number}.txt" for number in filter_numbers}

def list_filter_files(owner, repo, path):
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
    resp = session.get(url)
    resp.raise_for_status()

    unwanted_filters_numbers = [45, 46]
    unwanted_filters = get_unwanted_filters(unwanted_filters_numbers)

    return [item for item in resp.json()
            if item["type"] == "file"
            and item["name"] not in unwanted_filters
            and item["name"].startswith("filter_")
            and item["name"].endswith(".txt")]

def download_file(url):
    r = session.get(url)
    r.raise_for_status()
    return r.text

def collect_domains():
    domain_re1 = re.compile(r'^\|\|([^/\^]+)\^')
    domain_re2 = re.compile(r'^0\.0\.0\.0\s+([^\s#]+)')

    domains = set()

    files = list_filter_files(OWNER, REPO, ASSETS_DIR)

    for idx, f in enumerate(files):
        print(f"Processing {idx}/{len(files)-1}", end='\r', flush=True)
        text = download_file(f["download_url"])
        for line in text.splitlines():
            m1 = domain_re1.match(line)
            if m1:
                domains.add(m1.group(1))
                continue
            m2 = domain_re2.match(line)
            if m2:
                domains.add(m2.group(1))

    out_path = "all_domains.txt"
    with open(out_path, "w", encoding="utf-8") as out:
        for d in domains:
            out.write(d + "\n")

    print(f"\nCollected {len(domains)} unique maliciuous domains.\nSaved in: {out_path}")


if __name__ == "__main__":
    collect_domains()
