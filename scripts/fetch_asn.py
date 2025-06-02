import requests
import os

ASN_LIST = {
    "Apple": ["AS714", "AS6185", "AS36561"],
    "Akamai": ["AS20940", "AS12222"],
    "Amazon": ["AS16509"],
    "Fastly": ["AS54113"]
}

OUTPUT_DIR = "data"
os.makedirs(OUTPUT_DIR, exist_ok=True)

def fetch_asn_prefixes(asn):
    url = f"https://ipinfo.io/{asn}/json"
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            return data.get("prefixes", []) + data.get("ipv6_prefixes", [])
    except Exception as e:
        print(f"Failed to fetch {asn}: {e}")
    return []

def write_ip_list(org, asns):
    v4_list, v6_list = set(), set()
    for asn in asns:
        prefixes = fetch_asn_prefixes(asn)
        for entry in prefixes:
            prefix = entry.get("netblock")
            if not prefix:
                continue
            if ":" in prefix:
                v6_list.add(prefix)
            else:
                v4_list.add(prefix)

    with open(f"{OUTPUT_DIR}/{org}_ipv4.txt", "w") as f4:
        for ip in sorted(v4_list):
            f4.write(ip + "\n")

    with open(f"{OUTPUT_DIR}/{org}_ipv6.txt", "w") as f6:
        for ip in sorted(v6_list):
            f6.write(ip + "\n")

if __name__ == "__main__":
    for org, asns in ASN_LIST.items():
        write_ip_list(org, asns)
