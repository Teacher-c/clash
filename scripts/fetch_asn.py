import requests
import os

ASN_LIST = {
    "Apple": ["714", "6185", "36561"],
    "Akamai": ["20940", "12222"],
    "Amazon": ["16509"],
    "Fastly": ["54113"]
}

OUTPUT_DIR = "data"
os.makedirs(OUTPUT_DIR, exist_ok=True)

def fetch_prefixes_from_bgpview(asn):
    url = f"https://api.bgpview.io/asn/{asn}/prefixes"
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            v4 = [item['prefix'] for item in data['data']['ipv4_prefixes']]
            v6 = [item['prefix'] for item in data['data']['ipv6_prefixes']]
            return v4, v6
        else:
            print(f"[ERROR] Failed to fetch ASN {asn}, status {resp.status_code}")
    except Exception as e:
        print(f"[ERROR] Exception fetching ASN {asn}: {e}")
    return [], []

def write_ip_list(org, asn_list):
    v4_total, v6_total = set(), set()
    for asn in asn_list:
        v4, v6 = fetch_prefixes_from_bgpview(asn)
        v4_total.update(v4)
        v6_total.update(v6)

    with open(f"{OUTPUT_DIR}/{org}_ipv4.txt", "w") as f4:
        f4.writelines(line + "\n" for line in sorted(v4_total))

    with open(f"{OUTPUT_DIR}/{org}_ipv6.txt", "w") as f6:
        f6.writelines(line + "\n" for line in sorted(v6_total))

if __name__ == "__main__":
    for org, asns in ASN_LIST.items():
        write_ip_list(org, asns)
