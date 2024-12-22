import re

class PostErrorBasedReqSQLI:
    def __init__(self, url, post_data):
        self.url = url
        self.post_data = post_data
        self.sql_payload_patterns = [
            r"(\bor\b.*?=)|(--|#|\/\*)",        
            r"\b(SELECT|UNION|UPDATE|DELETE|INSERT|DROP|CREATE)\b", 
            r"'\s*(OR|AND)\s*'.*?=.*?('|\\d+)",  
            r"(\bUNION\b.*?\bSELECT\b)|(\bAND\b\s+\d+\s*=\s*\d+)",  
            r"\bWAITFOR\s+DELAY\b|SLEEP\s*\(",
            r"\bLOAD_FILE\b|\bINTO\s+OUTFILE\b"
        ]

    def analyze_post(self):
        """
        Analisis data POST untuk parameter dan payload yang mencurigakan.
        """
        print(f"Memeriksa URL: {self.url} dengan metode POST")

        if not self.post_data:
            print("Tidak ada data POST yang diberikan.")
            return

        for param, value in self.post_data.items():
            if self.is_sql_injection_payload(value):
                print(f"Potensi SQL Injection Boolean Based terdeteksi pada parameter '{param}' dengan nilai '{value}'")
                return

        print("Tidak ditemukan payload SQL Injection yang mencurigakan.")

    def is_sql_injection_payload(self, payload):
        """
        Periksa apakah payload cocok dengan pola SQL Injection.
        """
        for pattern in self.sql_payload_patterns:
            if re.search(pattern, str(payload), re.IGNORECASE):
                return True
        return False

if __name__ == "__main__":
    target_url = input("Masukkan URL target untuk dianalisis: ")
    print("Masukkan data POST dalam format kunci=nilai, dipisahkan dengan & (misalnya, id=1&username=test):")
    raw_post_data = input("Data POST: ")
    
    try:
        post_data = {}
        for pair in raw_post_data.split("&"):
            key, value = pair.split("=", 1)
            post_data[key.strip()] = value.strip() 
    except ValueError:
        print("Kesalahan: Pastikan data POST dalam format kunci=nilai, dipisahkan dengan &.")
        exit(1)

    sql_injection_analyzer = PostErrorBasedReqSQLI(target_url, post_data)
    sql_injection_analyzer.analyze_post()
