#!/usr/bin/env python3
"""
build_ranked_list.py - Prioritized List V1 (CVSS-only, per finding)

Reads Greenbone/OpenVAS XML reports and produces one row per
(host, port, CVE), ranked by CVSS base score (highest first).

Usage:
    python build_ranked_list.py                      # all XML in scan_reports/
    python build_ranked_list.py scan_reports/a.xml   # specific file(s)/folder(s)
    python build_ranked_list.py --nvd                # enrich with per-CVE NVD scores
    python build_ranked_list.py --out my_list --top 25

Outputs: <out>.csv and <out>.json  (default: prioritized_list_v1.*)

Ranking score ("cvss"):
    NVD base score for that CVE if --nvd was used and one exists,
    otherwise the scanner's NVT-level cvss_base.
Note: a Greenbone NVT can cover many CVEs but carries ONE cvss_base, so
scanner scores are less precise per CVE. That is why --nvd is recommended.
"""
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


# ---------------------------------------------------------------- helpers
def child_text(parent, path):
    """Stripped text of parent/path, or '' if missing."""
    if parent is None:
        return ""
    node = parent.find(path)
    return (node.text or "").strip() if node is not None else ""


def to_float(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def severity_label(score):
    """CVSS v3-style qualitative rating."""
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0:
        return "Low"
    return "None"


# ---------------------------------------------------------------- parsing
def result_cves(result):
    """All CVE IDs on one <result>: <cve> text and <ref type="cve"> attrs."""
    found = set()
    for node in result.iter():
        if node.tag == "cve" and node.text:
            found.update(m.upper() for m in CVE_RE.findall(node.text))
        elif node.tag == "ref" and node.get("type", "").lower() == "cve":
            found.update(m.upper() for m in CVE_RE.findall(node.get("id", "")))
    return sorted(found)


def parse_report(xml_path):
    """One row per (result, CVE). Results with no CVE get cve_id 'N/A'."""
    rows = []
    root = ET.parse(xml_path).getroot()
    for result in root.iter("result"):
        host_node = result.find("host")
        # IP is the text directly inside <host>; child tags (asset, hostname) follow it
        host = (host_node.text or "").strip() if host_node is not None else ""
        hostname = child_text(host_node, "hostname")
        port = child_text(result, "port")

        nvt = result.find("nvt")
        nvt_name = child_text(nvt, "name") or child_text(result, "name")
        scanner_cvss = to_float(child_text(nvt, "cvss_base")) or to_float(
            child_text(result, "severity")
        )
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
    """Collapse repeats of the same finding across NVTs/reports; keep the highest score."""
    best = {}
    for r in rows:
        ident = r["cve_id"] if r["cve_id"] != "N/A" else r["nvt_name"]
        key = (r["host"], r["port"], ident)
        if key not in best or r["scanner_cvss"] > best[key]["scanner_cvss"]:
            best[key] = r
    return list(best.values())


# ---------------------------------------------------------------- NVD enrichment
def load_cache():
    if os.path.exists(NVD_CACHE_FILE):
        with open(NVD_CACHE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_cache(cache):
    with open(NVD_CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2)


def extract_nvd_cvss(payload):
    """Best available CVSS (newest version first) -> {'score', 'version'} or empty."""
    vulns = payload.get("vulnerabilities", [])
    if not vulns:
        return {"score": None, "version": ""}
    metrics = vulns[0].get("cve", {}).get("metrics", {})
    for key in CVSS_KEYS:
        records = metrics.get(key, [])
        if records:
            data = records[0].get("cvssData", {})
            return {
                "score": to_float(data.get("baseScore"), None),
                "version": key.replace("cvssMetric", "CVSS "),
            }
    return {"score": None, "version": ""}


def enrich_with_nvd(rows):
    import requests  # imported here so the script runs without it when --nvd is off

    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass

    api_key = (os.getenv("NVD_API_KEY") or "").strip("'\" ")
    delay = 0.7 if api_key else 6.5          # NVD rate limits
    headers = {"apiKey": api_key} if api_key else {}
    cache = load_cache()
    session = requests.Session()

    wanted = sorted({r["cve_id"] for r in rows if r["cve_id"] != "N/A"})
    todo = [c for c in wanted if c not in cache]
    print(f"NVD: {len(wanted)} unique CVEs, {len(todo)} to fetch "
        f"({len(wanted) - len(todo)} cached)")

    for i, cve in enumerate(todo, 1):
        for attempt in range(3):             # bounded retries (no recursion)
            try:
                resp = session.get(NVD_URL, headers=headers,
                    params={"cveId": cve}, timeout=20)
            except requests.RequestException as exc:
                print(f"  {cve}: network error ({exc})")
                break
            if resp.status_code == 200:
                cache[cve] = extract_nvd_cvss(resp.json())
                break
            if resp.status_code in (403, 429):
                time.sleep(6 * (attempt + 1))
                continue
            print(f"  {cve}: HTTP {resp.status_code}")
            break
        if i % 20 == 0:
            save_cache(cache)
        time.sleep(delay)
    save_cache(cache)

    for r in rows:
        hit = cache.get(r["cve_id"])
        if hit and hit.get("score") is not None:
            r["nvd_cvss"] = hit["score"]
            r["nvd_cvss_version"] = hit["version"]


# ---------------------------------------------------------------- ranking
def rank_rows(rows):
    for r in rows:
        if r["nvd_cvss"] is not None:
            r["cvss"], r["cvss_source"] = r["nvd_cvss"], "NVD"
        else:
            r["cvss"], r["cvss_source"] = r["scanner_cvss"], "Greenbone"
        r["severity"] = severity_label(r["cvss"])

    rows.sort(key=lambda r: (-r["cvss"], r["host"], r["cve_id"]))

    # competition ranking: equal scores share a rank (1,1,3,...)
    prev_score, prev_rank = None, 0
    for pos, r in enumerate(rows, 1):
        if r["cvss"] != prev_score:
            prev_rank, prev_score = pos, r["cvss"]
        r["rank"] = prev_rank
    return rows


def collect_xml_paths(inputs):
    paths = []
    for item in inputs:
        if os.path.isdir(item):
            paths += glob.glob(os.path.join(item, "*.xml"))
        else:
            paths += glob.glob(item)
    return sorted(set(paths))


def main():
    ap = argparse.ArgumentParser(description="Build the CVSS-ranked per-finding list")
    ap.add_argument("inputs", nargs="*", default=["scan_reports"],
                    help="XML files or folders (default: scan_reports)")
    ap.add_argument("--nvd", action="store_true", help="enrich with per-CVE NVD scores")
    ap.add_argument("--out", default="prioritized_list_v1", help="output file prefix")
    ap.add_argument("--top", type=int, default=15, help="rows to print (default 15)")
    args = ap.parse_args()

    paths = collect_xml_paths(args.inputs)
    if not paths:
        raise SystemExit(f"No XML reports found in: {args.inputs}")

    rows = []
    for p in paths:
        try:
            found = parse_report(p)
        except ET.ParseError as exc:
            print(f"Skipping {p}: XML parse error ({exc})")
            continue
        print(f"{p}: {len(found)} findings")
        rows += found

    rows = dedupe(rows)
    if args.nvd:
        enrich_with_nvd(rows)
    rows = rank_rows(rows)

    with open(f"{args.out}.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    with open(f"{args.out}.json", "w", encoding="utf-8") as f:
        json.dump([{k: r.get(k) for k in FIELDS} for r in rows], f, indent=2)

    print(f"\n{len(rows)} unique findings -> {args.out}.csv / {args.out}.json\n")
    print(f"{'Rank':<5}{'Host':<16}{'Port':<13}{'CVE':<17}{'CVSS':<6}{'Sev':<9}Source")
    for r in rows[:args.top]:
        print(f"{r['rank']:<5}{r['host']:<16}{r['port']:<13}{r['cve_id']:<17}"
            f"{r['cvss']:<6}{r['severity']:<9}{r['cvss_source']}")


if __name__ == "__main__":
    main()