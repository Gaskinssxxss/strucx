import re
import requests

class ErrorBasedSQLInjectionTemplate:
    def __init__(self, url, data=None):
        self.method = "POST"
        self.url = url
        self.headers = {
            "User-Agent": "Mozilla/5.0",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        self.data = data if data else {}
        self.regex_patterns = [
            "SQL syntax.*?MySQL|MariaDB",
            "Warning.*?\\Wmysqli?_",
            "MySQLSyntaxErrorException",
            "valid MySQL result",
            "check the manual that (corresponds to|fits) your MySQL server version",
            "Unknown column '[^ ]+' in 'field list'",
            "MySqlClient\\.",
            "com\\.mysql\\.jdbc",
            "Zend_Db_(Adapter|Statement)_Mysqli_Exception",
            "Pdo[./_\\\\]Mysql",
            "MySqlException",
            "SQLSTATE\\[\\d+\\]: Syntax error or access violation",
            "PostgreSQL.*?ERROR",
            "Warning.*?\\Wpg_",
            "valid PostgreSQL result",
            "Npgsql\\.",
            "PG::SyntaxError:",
            "org\\.postgresql\\.util\\.PSQLException",
            "ERROR:\\s\\ssyntax error at or near",
            "ERROR: parser: parse error at or near",
            "PostgreSQL query failed",
            "Driver.*? SQL[\\-\\_\\ ]*Server",
            "OLE DB.*? SQL Server",
            "\\bSQL Server[^&lt;&quot;]+Driver",
            "Warning.*?\\W(mssql|sqlsrv)_"
        ]

    def send_request(self):
        """
        Kirim permintaan HTTP POST untuk menguji potensi kerentanannya.
        """
        response = requests.post(self.url, headers=self.headers, data=self.data)

        if response.status_code == 200:
            print("Status 200 OK: Memeriksa apakah ada potensi SQL Injection berbasis error...")
            self.match_response(response.text)
        else:
            print(f"Status {response.status_code}: Memeriksa apakah ada potensi SQL Injection berbasis error...")
            self.match_error_in_non_200_response(response)

    def match_response(self, body):
        """
        Periksa apakah body respons mengandung pola SQL error.
        """
        if "Adminer" not in body:
            self.apply_regex(body)
        else:
            print("False positive detected: 'Adminer' found in response body.")

    def match_error_in_non_200_response(self, response):
        """
        Memeriksa jika respons selain status 200 mengandung pola SQL error.
        """
        if response.status_code != 200:
            print(f"Memeriksa respons dengan status {response.status_code} untuk potensi SQL Injection...")
            self.apply_regex(response.text)

    def apply_regex(self, body):
        """
        Mencocokkan respons dengan regex untuk menemukan indikasi SQL error.
        """
        for pattern in self.regex_patterns:
            matches = re.findall(pattern, body)
            if matches:
                print(f"SQL error detected dengan pola: {pattern}")
                return
        print("Tidak ditemukan kesalahan SQL yang mencurigakan.")

if __name__ == "__main__":
    target_url = input("Masukkan URL target untuk diuji: ")
    data = input("Masukkan data POST (format: key1=value1&key2=value2): ")
    data_dict = dict(item.split("=") for item in data.split("&"))
    
    sql_injection_tester = ErrorBasedSQLInjectionTemplate(target_url, data_dict)
    sql_injection_tester.send_request()
