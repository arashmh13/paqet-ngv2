import socket
import time

resolver = '8.8.8.8'
domain = 'test3.tunnel.paqet-ngv2.example'
labels = domain.split('.')
qname = b''
for l in labels:
    qname += bytes([len(l)]) + l.encode()
qname += bytes([0])

hdr = bytes([0xAA, 0x55, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
trailer = bytes([0x00, 0x10, 0x00, 0x01])  # TXT, IN
query = hdr + qname + trailer

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(6.0)

start_t = time.time()
s.sendto(query, (resolver, 53))
print("CLIENT_QUERY_SENT_TO_8.8.8.8")

try:
    resp, addr = s.recvfrom(2048)
    elapsed = (time.time() - start_t) * 1000.0
    ancount = int.from_bytes(resp[6:8], 'big')
    print(f"CLIENT_SUCCESS_RECV: len={len(resp)}, rtt={elapsed:.2f}ms, ancount={ancount}")
    if b'AUTHENTICATED_PAQET' in resp:
        print(">>> SUCCESS: AUTHENTICATED EMERGENCY TXT PAYLOAD RETURNED VIA 8.8.8.8 RECURSIVE LOOKUP! <<<")
        print(f"Raw answer bytes: {resp[-50:]}")
    else:
        print("No payload string in response. Resp:", resp)
except Exception as e:
    print("CLIENT_ERR:", e)
finally:
    s.close()
