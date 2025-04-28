import socket
import ssl
import json
import time


class MCAPI():

    def __init__(self, *args):
        self.HOST = args[0]
        self.PORT = args[1]
        self.policy_name = args[2]
        self.api_key = args[3]
        self.all_policy = '/api/policies'


    def do_GET(self, path):
        __get = f"GET {path} HTTP/1.1\r\n" \
                f"HOST: {self.HOST}:{self.PORT}\r\n" \
                f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36\r\n" \
                f"X-Auth-Token: {self.api_key}\r\n" \
                f"\r\n"
        self.ssl_socket.send(__get.encode())
        self.https_handler()

    def get_socket(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as self.sock:
            self.sock.connect((self.HOST, self.PORT))
            self.do_SSLhandshake()

    def get_policy(self):
        path = f"/api/policies/{self.uuid}/content/{self.version}"
        self.do_GET(path)

    def get_uuid(self, parsed_json):
        # /api/policies is parsed as a LIST type
        if isinstance(parsed_json, list):
            for item in parsed_json:
                if isinstance(item, dict) and "name" in item:
                    if item["contentType"] == "vpm":
                        if item["name"] == self.policy_name:
                            self.uuid = item["uuid"]
                            self.name = item["name"]
        else:
            print(f"Unexpected JSON structure: {parsed_json}")


    def dump_policy_content(self, parsed_json):
        # /api/policies/<uuid>/content os a DICT type
        if isinstance(parsed_json, dict):
            content = parsed_json.get("content")
            if content is not None:
                with open(f"{self.name}_{self.uuid}_content_version_{self.version}.json", 'a+') as f:
                    json.dump(parsed_json, f, indent=2)


    def http_body_parser(self, body):
        self.body_decoded = body.decode('UTF-8')
        print("=== BODY ===")
        try:
            parsed_json = json.loads(self.body_decoded)
            print(f"Successfully parsed JSON of type {type(parsed_json)}")
            return parsed_json
        except json.JSONDecodeError as e:
            print(f"JSON parsing failed: {e}")
            print("Raw body:\n", self.body_decoded)


    def http_header_parser(self, headers_bytes):
        headers = headers_bytes.decode('utf-8').split("\r\n")
        print("=== HEADERS ===")
        for line in headers:
            print(line)
            if "HTTP/1.1" in line:
                self.http_status = line.split(" ")[1]
        is_chunked = any("transfer-encoding: chunked" in line.lower() for line in headers)
        is_content_length = any('content-length' in line.lower() for line in headers)
        return headers, is_chunked, is_content_length

    def https_handler(self):
        response_bytes = b''
        while b'\r\n\r\n' not in response_bytes:
            response_bytes += self.ssl_socket.recv(1024)
        headers_bytes, body = response_bytes.split(b'\r\n\r\n', 1)
        headers, is_chunked, is_content_length = self.http_header_parser(headers_bytes)
        if is_content_length:
            for line in headers:
                if 'content-length' in line.lower():
                    content_length = int(line.split(':', 1)[1].strip())
                    break
            while len(body) < content_length:
                body += self.ssl_socket.recv(1024)
            self.parsed_json = self.http_body_parser(body)


        elif is_chunked:
            buffer = body
            full_body = b''
            while True:
                while b'\r\n' not in buffer:
                    buffer += self.ssl_socket.recv(1024)
                chunk_size_line, buffer = buffer.split(b'\r\n', 1)
                try:
                    chunk_size = int(chunk_size_line.strip(), 16)
                except ValueError:
                    print(f"Invalid chunk size line: {chunk_size_line}")
                    break
                if chunk_size == 0:
                    # Read and discard the next \r\n
                    if b'\r\n' not in buffer:
                        buffer += self.ssl_socket.recv(1024)
                    if buffer.startswith(b'\r\n'):
                        buffer = buffer[2:]
                    break
                while len(buffer) < chunk_size + 2:
                    buffer += self.ssl_socket.recv(1024)
                chunk_data = buffer[:chunk_size]
                full_body += chunk_data
                buffer = buffer[chunk_size + 2:]  # skip chunk and trailing CRLF
            self.parsed_json = self.http_body_parser(full_body)

    def do_SSLhandshake(self):
        ssl_context = ssl._create_unverified_context()  # disables cert validation
        self.ssl_socket = ssl_context.wrap_socket(self.sock, server_hostname=self.HOST)
        self.do_GET(self.all_policy)
        self.get_uuid(self.parsed_json)
        ver = 0
        while self.http_status == "200":
            self.version = f"1.{ver}"
            self.get_policy()
            self.dump_policy_content(self.parsed_json)
            ver += 1
            time.sleep(10)


if __name__ == '__main__':
    api = MCAPI("<MC IP>", 8082, "<POLICY_NAME>", "<API Key>")
    api.get_socket()
