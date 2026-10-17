import socket
import sys

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('0.0.0.0', 53))
s.settimeout(20.0)

log_lines = ['AUTHORITATIVE_SERVER_RUNNING']

try:
    data, addr = s.recvfrom(2048)
    log_lines.append(f'RECV_QUERY_FROM_{addr[0]}_{addr[1]}_LEN_{len(data)}')

    txid = data[:2]
    offset = 12
    labels = []
    while offset < len(data):
        l = data[offset]
        offset += 1
        if l == 0:
            break
        labels.append(data[offset:offset+l].decode('latin1', errors='ignore'))
        offset += l
    qname = '.'.join(labels)
    log_lines.append(f'QNAME_{qname}')

    hdr = txid + bytes([0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00])
    question_sec = data[12:offset+4]

    txt_payload = b'AUTHENTICATED_PAQET_DNS_RECURSIVE_TRAVERSAL_OK'
    ans_hdr = bytes([0xc0, 0x0c, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00])
    rdlen = (1 + len(txt_payload)).to_bytes(2, 'big')
    ans_body = rdlen + bytes([len(txt_payload)]) + txt_payload

    resp = hdr + question_sec + ans_hdr + ans_body
    s.sendto(resp, addr)
    log_lines.append(f'SENT_TXT_RESPONSE_TO_{addr[0]}')
except Exception as e:
    log_lines.append(f'SERVER_EXCEPTION_{e}')
finally:
    s.close()
    with open('/tmp/dns_srv_log.txt', 'w') as f:
        for line in log_lines:
            f.write(line + '\n')
