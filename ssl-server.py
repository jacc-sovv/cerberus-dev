from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1
from cryptography.hazmat.primitives.asymmetric.ec import ECDH
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import KeySerializationEncryption
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

import socket


HOST = "127.0.0.1"  # Standard loopback interface address (localhost)
PORT = 5572  # Port to listen on (non-privileged ports are > 1023)
SHARED_SECRET_LEN = 32
DER_LEN = 91    #length of der encoding for this message
MSG_SIZE = 128
IV_SIZE = 12
TAG_SIZE = 16
server_private_key = ec.generate_private_key(ec.SECP256R1)
server_public_key = server_private_key.public_key()
print(f"Server X value : {server_public_key.public_numbers().x}\nServer y value : {server_public_key.public_numbers().y}")
server_public_der = server_public_key.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
server_private_der = server_private_key.private_bytes(encoding=serialization.Encoding.DER, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption())

server_public_pem = server_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
server_private_pem = server_private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption())
# print(server_public_der)

#Ex secret key - 2\t\xdb\x8a\xb4%D\xb3\x07\x1f\xdb\x00$\x02\xbe\xeco\xad\xbd\xc7\x8c\xe7\xad\x14\xedVLh\xecZ\x89\xcf
#server_public_der = b'0Y0\x13\x06\x07*\x86H\xce=\x02\x01\x06\x08*\x86H\xce=\x03\x01\x07\x03B\x00\x04\xe4Mn\xcc\x83O\xc0Fm&\x9b\xb2\x7f\xb3\xdf\xb6E\xcd\xcd\x8b\x15\x02\xb3[\xac5\xc9V\xa8\x9db1\x07\xb9\xf6\x89\xc5\x9f\xb6e\x1f\x8f\x10e\xf1\x99\x0c\xb83g\x89%\x80\x1d\x1as\xef\xe2q\x91\xaf\xd1\'\xeb'

raw_client_pub_key = None;

# with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, PORT))
s.listen()
print("listening")
conn, addr = s.accept()
print("accepted")

print(f"Connected by {addr}")

#Set up vars
client_public_key = None;
# data = conn.recv(5)
# print(data)
# if(data[:4] == b"lock"):
data = conn.recv(DER_LEN)
raw_client_pub_key = data
client_public_key = load_der_public_key(data)

print(f"Client X value : {client_public_key.public_numbers().x}\nClient y value : {client_public_key.public_numbers().y}")

conn.sendall(server_public_der)
conn.close()
s.close()

##Start of changes
print()
print("Generating shared secret...")
shared_secret = server_private_key.exchange(ec.ECDH(), client_public_key)

# #Encrypt a product ID, send it over
s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s2.bind((HOST, 5574))
s2.listen()
print("listening")
conn_pid, addr_pid = s2.accept()

iv = conn_pid.recv(IV_SIZE)

PID = b"ABCDEFGHIJKLMNOP"
aes_pid = AESGCM(shared_secret)
ePID = aes_pid.encrypt(iv, PID, None)
pid_tag = ePID[-16:]
ePID = ePID[:-16]

conn_pid.sendall(ePID)
conn_pid.sendall(pid_tag)
s2.close()

##End of changes


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, 5573))
s.listen()
print("listening")
conn, addr = s.accept()
print("accepted")
print(f"Connected by {addr}")  
client_otp = conn.recv(MSG_SIZE)
print(f"[DEMO]: Encrypted client message : {client_otp}\n")
iv = conn.recv(IV_SIZE)
client_tag = conn.recv(TAG_SIZE)






aesgcm = AESGCM(shared_secret)
#16 byte tag gets appended to the encrypted data
decrypted_client_message = aesgcm.decrypt(iv, client_otp + client_tag, None)

# print(f"Is decrypted client msg same as the original otp? (should be true) {client_og_otp == decrypted_client_message}")
with open("OTP", "wb") as f:
    f.write(decrypted_client_message)
print("[DEMO(1)]: Decrypting OTP to showcase it is the same on the client and server. Original OTP is")
os.system("cat OTP")
print()




difference = 128 - len(client_otp)
full_message = client_otp + (b'\0' * difference)
aes_send = AESGCM(shared_secret)
ct = aes_send.encrypt(iv, full_message, None)
serv_tag = ct[-16:]
serv_encrypted_data = ct[:-16]
serv_decrypted_data_with_tag = aes_send.decrypt(iv, serv_encrypted_data + serv_tag, None)
serv_decrypted_data = serv_decrypted_data_with_tag[:-16]

print(f"[DEMO(2)]: Performing an AES encryption of OTPs (will be used between user and server in reality)...")
print(f"[DEMO(2)]: Server's encrypted OTPs is : {serv_encrypted_data}\n")

print(f"[DEMO(3)]: Performing decryption on previously encrypted OTPs (will be used between user and server in reality)...")
print(f"[DEMO(3)]: Server's decrypted OTPs (should be original OTPs) is : {serv_decrypted_data_with_tag}\n")

print(f"[DEMO(3)]: Was the server able to encrypt OTPs and decrypt it successfully? {serv_decrypted_data_with_tag == client_otp}\n")


print(f"[DEMO(4)]: Server (will be user in reality) sending OTPs back to client for validation...")



conn.sendall(client_otp)
conn.sendall(client_tag)
s.close()


client_public_key_pem = client_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

f = open("client_key.der", "wb")
f.write(raw_client_pub_key)
f.close()

f = open("client_key.pem", "wb")
f.write(client_public_key_pem)
f.close()

f2 = open("server_key.der", "wb")
f2.write(server_public_der)
f2.close()

f = open("server_private_key.der", "wb")
f.write(server_private_der)
f.close()

f5 = open("server_private_key.pem", "wb")
f5.write(server_private_pem)
f5.close()

f6 = open("server_shared_secret", "wb")
f6.write(shared_secret)
f6.close()

 


print(f"\nOpenssl attempting to read the client's public key : \n")
os.system("openssl pkey -inform DER -pubin -in client_key.der -text -noout")
print(f"\nOpenssl attempting to read the server's public key\n")
os.system("openssl pkey -inform DER -pubin -in server_key.der -text -noout")
print(f"\nOpenssl attempting to read the server's private key\n")
os.system("openssl pkey -inform DER -in server_private_key.der -text -noout")

print(f"\nUsing openssl to derive shared secret : ")
os.system("openssl pkeyutl -derive -inkey server_private_key.pem -peerkey client_key.pem -out secret1.bin")
os.system("cat secret1.bin")
print("\n\n")
print(f"Using the server to derive shared secret : ")
os.system("cat server_shared_secret")
print("\n\n")


with open("secret1.bin", "rb") as f:
    openssl_secret = f.read()


print(f"\nIs this shared secret the same as the one generated by client AND the same as the one generated by server? {openssl_secret == shared_secret}")


