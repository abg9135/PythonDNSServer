import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.rdtypes
import dns.rdtypes.ANY
from dns.rdtypes.ANY.MX import MX
from dns.rdtypes.ANY.SOA import SOA
import dns.rdata
import socket
import threading
import signal
import os
import sys

import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

def generate_aes_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32
    )
    key = kdf.derive(password.encode('utf-8'))
    key = base64.urlsafe_b64encode(key)
    return key

def encrypt_with_aes(input_string, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    encrypted_data = f.encrypt(input_string.encode('utf-8'))
    return encrypted_data

def decrypt_with_aes(encrypted_data, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    decrypted_data = f.decrypt(encrypted_data).decode('utf-8')
    return decrypted_data

salt = encode('Tandon')
password = 'abg9135@nyu.edu'
secret_data = "AlwaysWatching"
encrypted_value = encrypt_with_aes(secret_data, password, salt)

# A dictionary containing DNS records mapping hostnames to different types of DNS data.
dns_records = {
    'example.com.': {
        dns.rdatatype.A: '192.168.1.101',
        dns.rdatatype.AAAA: '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
        dns.rdatatype.MX: [(10, 'mail.example.com.')],  # List of (preference, mail server) tuples
        dns.rdatatype.CNAME: 'www.example.com.',
        dns.rdatatype.NS: 'ns.example.com.',
        dns.rdatatype.TXT: ('This is a TXT record',),
        dns.rdatatype.SOA: (
            'ns1.example.com.', #mname
            'admin.example.com.', #rname
            2023081401, #serial
            3600, #refresh
            1800, #retry
            604800, #expire
            86400, #minimum
        ),
    },
    'safebank.com.': {
        dns.rdatatype.A: '192.168.1.102',
    },
    'google.com.': {
        dns.rdatatype.A: '192.168.1.103',
    },
    'legitsite.com.': {
        dns.rdatatype.A: '192.168.1.104',
    },
    'yahoo.com.': {
        dns.rdatatype.A: '192.168.1.105',
    },
    'nyu.edu.': {
        dns.rdatatype.A: '192.168.1.106',
        dns.rdatatype.TXT: (encrypted_value,),
        dns.rdatatype.MX: [(10, 'mxa-00256a01.gslb.pphosted.com.')],
        dns.rdatatype.AAAA: '2001:0db8:85a3:0000:0000:8a2e:0373:7312',
        dns.rdatatype.NS: 'ns1.nyu.edu.',
    }
}

def run_dns_server():
    # Create a UDP socket and bind it to the local IP address and port 53 (standard port for DNS)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(('localhost', 53))

    while True:
        try:
            data, addr = server_socket.recvfrom(1024)
            request = dns.message.from_wire(data)
            response = dns.message.make_response(request)

            question = request.question[0]
            qname = question.name.to_text()
            qtype = question.rdtype

            if qname in dns_records and qtype in dns_records[qname]:
                answer_data = dns_records[qname][qtype]
                if qtype == dns.rdatatype.MX:
                    for pref, server in answer_data:
                        rdata = MX(dns.rdataclass.IN, dns.rdatatype.MX, pref, server)
                        response.answer.append(dns.rrset.RRset(question.name, dns.rdataclass.IN, qtype))
                        response.answer[-1].add(rdata)
                elif qtype == dns.rdatatype.SOA:
                    # Handle SOA record format
                    # ...
                    mname, rname, serial, refresh, retry, expire, minimum = answer_data
                    rdata = SOA(
                        dns.rdataclass.IN,
                        dns.rdatatype.SOA,
                        mname,
                        rname,
                        serial,
                        refresh,
                        retry,
                        expire,
                        minimum
                    )
                    response.answer.append(dns.rrset.RRset(question.name, dns.rdataclass.IN, qtype))
                    response.answer[-1].add(rdata)
                else:
                    rdata = dns.rdata.from_text(dns.rdataclass.IN, qtype, answer_data)
                    response.answer.append(dns.rrset.RRset(question.name, dns.rdataclass.IN, qtype))
                    response.answer[-1].add(rdata)

                response.flags |= dns.flags.AA

            server_socket.sendto(response.to_wire(), addr)

        except KeyboardInterrupt:
            print('\nExiting...')
            server_socket.close()
            sys.exit(0)

def run_dns_server_user():
    print("Input 'q' and hit 'enter' to quit")
    print("DNS server is running...")

    def user_input():
        while True:
            cmd = input()
            if cmd.lower() == 'q':
                print('Quitting...')
                os.kill(os.getpid(), signal.SIGINT)

    input_thread = threading.Thread(target=user_input)
    input_thread.daemon = True
    input_thread.start()
    run_dns_server()

if __name__ == '__main__':
    run_dns_server_user()
