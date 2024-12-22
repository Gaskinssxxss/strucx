import re
from urllib.parse import urlparse, parse_qs

class GetErrorBasedReqSQLI:
    def __init__(self, url):
        self.url = url
        self.sql_payload_patterns = [
            r"(\bor\b.*?=)|(--|#|\/\*)",        
            r"\b(SELECT|UNION|UPDATE|DELETE|INSERT|DROP|CREATE)\b", 
            r"'\s*(OR|AND)\s*'.*?=.*?('|\\d+)",  
            r"(\bUNION\b.*?\bSELECT\b)|(\bAND\b\s+\d+\s*=\s*\d+)",  
            r"\bWAITFOR\s+DELAY\b|SLEEP\s*\(",  
            r"\bLOAD_FILE\b|\bINTO\s+OUTFILE\b"  
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
                    print(f"Potensi SQL Injection terdeteksi pada parameter '{param}' dengan nilai '{value}'")
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
    sql_injection_analyzer = GetErrorBasedReqSQLI(target_url)

    sql_injection_analyzer.analyze_url()
