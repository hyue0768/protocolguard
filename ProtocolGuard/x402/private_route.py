"""Loopback-only CONNECT relay for this project's approved OpenAI route.

TLS stays end-to-end. No request bodies, headers or credential values are logged.
"""
import socket
import socketserver
import selectors


def destination(authority):
    host,separator,port=authority.rpartition(':')
    host=host.lower().rstrip('.')
    allowed=any(host==domain or host.endswith('.'+domain)
                for domain in ['chatgpt.com','openai.com','oaistatic.com','oaiusercontent.com'])
    if not separator or port!='443' or not allowed or any(x in host for x in ['@','/','\\','[',']']):
        raise ValueError('CONNECT destination not allowed')
    return host,443


class Relay(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(20)
        try:
            line=self.rfile.readline(8193)
            if len(line)>8192:raise ValueError('request line too long')
            method,authority,version=line.decode('ascii').strip().split()
            if method!='CONNECT' or version not in ['HTTP/1.0','HTTP/1.1']:raise ValueError('CONNECT only')
            target=destination(authority)
            total=0
            while True:
                header=self.rfile.readline(8193);total+=len(header)
                if total>32768 or not header:raise ValueError('invalid header size')
                if header in [b'\r\n',b'\n']:break
            upstream=socket.create_connection(target,timeout=20)
        except (ValueError,OSError,UnicodeError):
            self.connection.sendall(b'HTTP/1.1 502 Connection unavailable\r\nContent-Length: 0\r\n\r\n');return
        with upstream:
            self.connection.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            self.connection.settimeout(None);upstream.settimeout(None)
            with selectors.DefaultSelector() as select:
                select.register(self.connection,selectors.EVENT_READ,upstream)
                select.register(upstream,selectors.EVENT_READ,self.connection)
                while True:
                    events=select.select(timeout=650)
                    if not events:return
                    for key,mask in events:
                        try:
                            data=key.fileobj.recv(65536)
                            if not data:return
                            key.data.sendall(data)
                        except OSError:return


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address=True
    daemon_threads=True
    def handle_error(self,request,address):pass


if __name__=='__main__':
    with Server(('127.0.0.1',18870),Relay) as server:server.serve_forever()
