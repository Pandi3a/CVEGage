import requests
import time
import json
import os
from datetime import datetime, timedelta

class CVEGage:
    def __init__(self, api_key=None):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.cisa_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        self.cache_file = "cisa_cache.json"
        self.headers = {"apiKey": api_key} if api_key else {}
        # Here you can specify your stack
        self.stack = ["kubernetes", "docker", "terraform", "aws", "gcp", "azure", "ibm cloud", "mongodb", "ssl", "tls", "mtls"]

    def get_cisa_catalog(self):
        """Fetches CISA catalog with 24-hour local caching."""
        if os.path.exists(self.cache_file):
            file_age = datetime.now() - datetime.fromtimestamp(os.path.getmtime(self.cache_file))
            if file_age < timedelta(hours=24):
                with open(self.cache_file, 'r') as f:
                    data = json.load(f)
                    return {v['cveID']: v for v in data.get('vulnerabilities', [])}

        try:
            r = requests.get(self.cisa_url, timeout=10)
            if r.status_code == 200:
                with open(self.cache_file, 'w') as f:
                    json.dump(r.json(), f)
                return {v['cveID']: v for v in r.json().get('vulnerabilities', [])}
        except:
            return {}

    def get_cves_for_tech(self, tech):
        """Fetches CVEs for a technology from the last 5 days."""
        start_date = (datetime.utcnow() - timedelta(days=5)).isoformat()
        params = {"keywordSearch": tech, "pubStartDate": start_date, "pubEndDate": datetime.utcnow().isoformat()}
        if not self.headers: time.sleep(6)
        try:
            response = requests.get(self.base_url, headers=self.headers, params=params, timeout=20)
            return response.json().get('vulnerabilities', []) if response.status_code == 200 else []
        except: return []

    def run_full_scan(self):
        cisa_catalog = self.get_cisa_catalog()
        all_results = {}
        priority_matches = []

        print(f"🚀 CVEGage starting full stack scan for: {', '.join(self.stack)}...\n")

        for tech in self.stack:
            raw_data = self.get_cves_for_tech(tech)
            for item in raw_data:
                cve = item.get('cve', {})
                cve_id = cve.get('id')
                metrics = cve.get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {})
                score = metrics.get('baseScore', 'N/A')
                desc = cve.get('descriptions', [{}])[0].get('value', 'No description available.')[:100] + "..."

                is_cisa = cve_id in cisa_catalog

                # Format Technical Log Output
                if is_cisa:
                    print(f"🚨 [CISA EXPLOITED] {cve_id} ({tech.upper()}) | Score: {score}")
                    print(f"   🔥 CISA ALERT: ACTIVELY EXPLOITED")
                else:
                    severity_icon = "🔴" if str(score) != 'N/A' and float(score) >= 7.0 else "🟡"
                    print(f"{severity_icon} {cve_id} ({tech.upper()}) | Score: {score}")

                print(f"   Tech Impact: {tech.upper()}")
                print(f"   Summary: {desc}")
                print(f"   🔗 Detail: https://nvd.nist.gov/vuln/detail/{cve_id}\n")

                if is_cisa:
                    priority_matches.append({"id": cve_id, "tech": tech, "info": cisa_catalog[cve_id]})

        # FINAL SUMMARY SECTION
        print("-" * 80)
        print(f"🔥 CVEGage FINAL SUMMARY: CISA MUST-FIX LIST")
        print("-" * 80)

        if not priority_matches:
            print("✅ No actively exploited vulnerabilities found in your stack today.")
        else:
            for item in priority_matches:
                print(f"ID: {item['id']} | Affected Stack: {item['tech'].upper()}")
                print(f"Action Required: {item['info'].get('requiredAction')}")
                print(f"Remediation Due: {item['info'].get('dueDate')}")
                print("-" * 80)

if __name__ == "__main__":
    watcher = CVEGage()
    watcher.run_full_scan()
