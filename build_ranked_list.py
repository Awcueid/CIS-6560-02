import argparse
import csv
import glob
import json
import os
import re
import time
import xml.etree.ElementTree as ET

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CACHE_FILE = "nvd_cache.json"
CVSS_KEYS = ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]
FIELDS = [
    "rank", "host", "hostname", "port", "cve_id", "cvss", "cvss_source",
    "severity", "scanner_cvss", "nvd_cvss", "nvd_cvss_version",
    "nvt_name", "solution_type",
]


def child_text(parent, path):
    if parent is None:
        return ""
    node = parent.find(path)
    return "" if node is None or node.text is None else node.text.strip()


def to_float(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def severity_label(score):
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0:
        return "Low"
    return "None"


def result_cves(result):
    found = set()
    for node in result.iter():
        if node.tag == "cve" and node.text:
            found.update(m.upper() for m in CVE_RE.findall(node.text))
        elif node.tag == "ref" and node.get("type", "").lower() == "cve":
            found.update(m.upper() for m in CVE_RE.findall(node.get("id", "")))
    return sorted(found)


def parse_report(xml_path):
    rows = []
    root = ET.parse(xml_path).getroot()

    for result in root.iter("result"):
        host_node = result.find("host")
        host = (host_node.text or "").strip() if host_node is not None else ""
        hostname = child_text(host_node, "hostname")
        port = child_text(result, "port")

        nvt = result.find("nvt")
        nvt_name = child_text(nvt, "name") or child_text(result, "name")
        scanner_cvss = to_float(child_text(nvt, "cvss_base")) or to_float(child_text(result, "severity"))
        solution = nvt.find("solution") if nvt is not None else None
        solution_type = solution.get("type", "") if solution is not None else ""

        for cve in result_cves(result) or ["N/A"]:
            rows.append({
                "host": host or "unknown",
                "hostname": hostname,
                "port": port,
                "cve_id": cve,
                "scanner_cvss": scanner_cvss,
                "nvd_cvss": None,
                "nvd_cvss_version": "",
                "nvt_name": nvt_name,
                "solution_type": solution_type,
            })

    return rows


def dedupe(rows):
    best = {}
    for row in rows:
        ident = row["cve_id"] if row["cve_id"] != "N/A" else row["nvt_name"]
        key = (row["host"], row["port"], ident)
        if key not in best or row["scanner_cvss"] > best[key]["scanner_cvss"]:
            best[key] = row
    return list(best.values())


def load_cache():
    if os.path.exists(NVD_CACHE_FILE):
        with open(NVD_CACHE_FILE, "r", encoding="utf-8") as fh:
            return json.load(fh)
    return {}


def save_cache(cache):
    with open(NVD_CACHE_FILE, "w", encoding="utf-8") as fh:
        json.dump(cache, fh, indent=2)


def extract_nvd_cvss(payload):
    vulnerabilities = payload.get("vulnerabilities", [])
    if not vulnerabilities:
        return {"score": None, "version": ""}

    metrics = vulnerabilities[0].get("cve", {}).get("metrics", {})
    for key in CVSS_KEYS:
        records = metrics.get(key, [])
        if not records:
            continue
        cvss_data = records[0].get("cvssData", {})
        return {
            "score": to_float(cvss_data.get("baseScore"), None),
            "version": key.replace("cvssMetric", "CVSS "),
        }

    return {"score": None, "version": ""}


def enrich_with_nvd(rows):
    import requests

    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass

    api_key = (os.getenv("NVD_API_KEY") or "").strip("'\" ")
    delay = 0.7 if api_key else 6.5
    headers = {"apiKey": api_key} if api_key else {}
    cache = load_cache()
    session = requests.Session()

    wanted = sorted({row["cve_id"] for row in rows if row["cve_id"] != "N/A"})
    missing = [cve for cve in wanted if cve not in cache]
    print(f"NVD: {len(wanted)} unique CVEs, {len(missing)} to fetch ({len(wanted) - len(missing)} cached)")

    for index, cve in enumerate(missing, 1):
        for attempt in range(3):
            try:
                response = session.get(NVD_URL, headers=headers, params={"cveId": cve}, timeout=20)
            except requests.RequestException as exc:
                print(f"  {cve}: network error ({exc})")
                break

            if response.status_code == 200:
                cache[cve] = extract_nvd_cvss(response.json())
                break
            if response.status_code in (403, 429):
                time.sleep(6 * (attempt + 1))
                continue
            print(f"  {cve}: HTTP {response.status_code}")
            break

        if index % 20 == 0:
            save_cache(cache)
        time.sleep(delay)

    save_cache(cache)

    for row in rows:
        hit = cache.get(row["cve_id"])
        if hit and hit.get("score") is not None:
            row["nvd_cvss"] = hit["score"]
            row["nvd_cvss_version"] = hit["version"]


def rank_rows(rows):
    for row in rows:
        if row["nvd_cvss"] is not None:
            row["cvss"] = row["nvd_cvss"]
            row["cvss_source"] = "NVD"
        else:
            row["cvss"] = row["scanner_cvss"]
            row["cvss_source"] = "Greenbone"
        row["severity"] = severity_label(row["cvss"])

    rows.sort(key=lambda row: (-row["cvss"], row["host"], row["cve_id"]))

    prev_score = None
    prev_rank = 0
    for position, row in enumerate(rows, 1):
        if row["cvss"] != prev_score:
            prev_rank = position
            prev_score = row["cvss"]
        row["rank"] = prev_rank

    return rows


def collect_xml_paths(items):
    paths = []
    for item in items:
        if os.path.isdir(item):
            paths.extend(glob.glob(os.path.join(item, "*.xml")))
        else:
            paths.extend(glob.glob(item))
    return sorted(set(paths))


def main():
    parser = argparse.ArgumentParser(description="Build the CVSS-ranked per-finding list")
    parser.add_argument("inputs", nargs="*", default=["scan_reports"], help="XML files or folders (default: scan_reports)")
    parser.add_argument("--nvd", action="store_true", help="enrich with per-CVE NVD scores")
    parser.add_argument("--out", default="prioritized_list_v1", help="output file prefix")
    parser.add_argument("--top", type=int, default=15, help="rows to print (default 15)")
    args = parser.parse_args()

    paths = collect_xml_paths(args.inputs)
    if not paths:
        raise SystemExit(f"No XML reports found in: {args.inputs}")

    rows = []
    for path in paths:
        try:
            found = parse_report(path)
        except ET.ParseError as exc:
            print(f"Skipping {path}: XML parse error ({exc})")
            continue
        print(f"{path}: {len(found)} findings")
        rows.extend(found)

    rows = dedupe(rows)
    if args.nvd:
        enrich_with_nvd(rows)
    rows = rank_rows(rows)

    csv_path = f"{args.out}.csv"
    json_path = f"{args.out}.json"

    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)

    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump([{key: row.get(key) for key in FIELDS} for row in rows], fh, indent=2)

    print(f"\n{len(rows)} unique findings -> {csv_path} / {json_path}\n")
    print(f"{'Rank':<5}{'Host':<16}{'Port':<13}{'CVE':<17}{'CVSS':<6}{'Sev':<9}Source")
    for row in rows[:args.top]:
        print(
            f"{row['rank']:<5}{row['host']:<16}{row['port']:<13}{row['cve_id']:<17}"
            f"{row['cvss']:<6}{row['severity']:<9}{row['cvss_source']}"
        )


if __name__ == "__main__":
    main()