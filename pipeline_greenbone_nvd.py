import json
import os
import re
import xml.etree.ElementTree as ET


class SecurityDataPipeline:
    def __init__(self, xml_path):
        self.xml_path = xml_path

    def extract_cve_ids(self):
        """
        Extract unique CVE identifiers from a Greenbone XML report.

        The report may store CVE values as ordinary text, for example:

        Closed CVE
        CVE-2000-0071, CVE-2000-0097, CVE-2000-0098

        Therefore, this method searches all element text and attributes
        instead of looking only for a specific XML tag.
        """
        if not os.path.isfile(self.xml_path):
            print(f"Error: File not found: {self.xml_path}")
            return []

        try:
            with open(
                self.xml_path,
                "r",
                encoding="utf-8",
                errors="replace"
            ) as file:
                xml_text = file.read()

        except OSError as error:
            print(f"Error: Could not read XML file: {error}")
            return []

        print(f"Reading XML file: {os.path.abspath(self.xml_path)}")
        print(f"Characters read: {len(xml_text):,}")

        # Match CVE identifiers such as:
        # CVE-2000-0071
        # CVE-2021-44228
        # CVE-2024-12345
        cve_pattern = re.compile(
            r"\bCVE[-_–—\s]+\d{4}[-_–—\s]+\d{4,}\b",
            re.IGNORECASE
        )

        matches = cve_pattern.findall(xml_text)

        unique_cves = set()

        for match in matches:
            # Normalize different separators and whitespace.
            normalized_cve = re.sub(
                r"[-_–—\s]+",
                "-",
                match.upper().strip()
            )

            unique_cves.add(normalized_cve)

        return sorted(unique_cves)

    def extract_cve_records(self):
        """
        Extract CVE identifiers and return structured records.

        Each record includes:
        - cve_id
        - source_text
        """
        if not os.path.isfile(self.xml_path):
            print(f"Error: File not found: {self.xml_path}")
            return []

        try:
            with open(
                self.xml_path,
                "r",
                encoding="utf-8",
                errors="replace"
            ) as file:
                xml_text = file.read()

        except OSError as error:
            print(f"Error: Could not read XML file: {error}")
            return []

        cve_pattern = re.compile(
            r"\bCVE[-_–—\s]+\d{4}[-_–—\s]+\d{4,}\b",
            re.IGNORECASE
        )

        records = {}
        lines = xml_text.splitlines()

        for line_number, line in enumerate(lines, start=1):
            matches = cve_pattern.findall(line)

            for match in matches:
                normalized_cve = re.sub(
                    r"[-_–—\s]+",
                    "-",
                    match.upper().strip()
                )

                if normalized_cve not in records:
                    records[normalized_cve] = {
                        "cve_id": normalized_cve,
                        "source_line": line_number,
                        "source_text": line.strip()
                    }

        return [
            records[cve_id]
            for cve_id in sorted(records)
        ]

    def extract_cve_records_from_xml(self):
        """
        Extract CVE records from parsed XML text nodes and attributes.

        This method is included as a second extraction path. The raw-text
        method is the primary method because this report stores CVEs in
        result text fields.
        """
        if not os.path.isfile(self.xml_path):
            print(f"Error: File not found: {self.xml_path}")
            return []

        try:
            tree = ET.parse(self.xml_path)
            root = tree.getroot()

        except ET.ParseError as error:
            print(f"Warning: XML parsing failed: {error}")
            return []

        cve_pattern = re.compile(
            r"\bCVE[-_–—\s]+\d{4}[-_–—\s]+\d{4,}\b",
            re.IGNORECASE
        )

        unique_cves = set()

        for element in root.iter():
            values_to_search = []

            if element.text:
                values_to_search.append(element.text)

            if element.tail:
                values_to_search.append(element.tail)

            values_to_search.extend(element.attrib.values())

            for value in values_to_search:
                for match in cve_pattern.findall(value):
                    normalized_cve = re.sub(
                        r"[-_–—\s]+",
                        "-",
                        match.upper().strip()
                    )

                    unique_cves.add(normalized_cve)

        return sorted(unique_cves)


if __name__ == "__main__":
    # Use the actual XML report path.
    xml_file = (
        "scan_reports/"
        "report-8839e21d-2514-45e4-bdc7-e89c5311ee77.xml"
    )

    # Output file containing the extracted CVE records.
    output_file = "normalized_results.json"

    pipeline = SecurityDataPipeline(xml_file)

    # Extract CVE identifiers from the complete raw XML text.
    cve_records = pipeline.extract_cve_records()

    print(f"\nFound {len(cve_records)} unique CVE IDs.")

    for record in cve_records:
        print(
            f"{record['cve_id']} "
            f"(line {record['source_line']})"
        )

    try:
        with open(output_file, "w", encoding="utf-8") as file:
            json.dump(
                cve_records,
                file,
                indent=4,
                ensure_ascii=False
            )

        print(f"\nSaved CVE records to: {output_file}")

    except OSError as error:
        print(f"Error: Could not save JSON file: {error}")