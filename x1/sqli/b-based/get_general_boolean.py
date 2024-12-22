import re
from urllib.parse import urlparse, parse_qs

class GetBooleanBasedSQLI:
    def __init__(self, url):
        self.url = url
        self.sql_payload_patterns = [
            r"(?:')\\s*(?:or|and)\\s+[^\\s]+(?:--|#|$)",
            r"(?:')\\s*(?:or|and)\\s+\\d+=\\d+",
            r"(?:')\\s*(?:or|and)\\s+'.+?'",
            r"(?:--|#|\\/\\*)",
            r"(?i)\\b(select|union|where|join|like|group by)\\b"
        ]

    def analyze_url(self):
        """
        Analisis URL untuk parameter dan payload yang mencurigakan.
        """
        print(f"Memeriksa URL: {self.url}")

        parsed_url = urlparse(self.url)
        params = parse_qs(parsed_url.query)

        if not params:
            print("Tidak ada parameter ditemukan dalam URL.")
            return

        for param, values in params.items():
            for value in values:
                if self.is_sql_injection_payload(value):
                    print(f"Potensi SQL Injection Boolean Based terdeteksi pada parameter '{param}' dengan nilai '{value}'")
                    return

        print("Tidak ditemukan payload SQL Injection yang mencurigakan.")

    def is_sql_injection_payload(self, payload):
        """
        Periksa apakah payload cocok dengan pola SQL Injection.
        """
        for pattern in self.sql_payload_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                return True
        return False

if __name__ == "__main__":
    target_url = input("Masukkan URL target untuk dianalisis: ")
    sql_injection_analyzer = GetBooleanBasedSQLI(target_url)

    sql_injection_analyzer.analyze_url()
