import requests
import base64
import hashlib
import urllib.request
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

url = 'http://192.168.1.21:8000'

# Getting first task.

r = requests.get(url + "/opdracht1")
result = r.text
print(result)

# Opdracht 1

r = requests.post(url + "/opdracht2", json={"nr1": "Eerste regel",
                                            "nr2": "Tweede regel",
                                            "nr3": "Derde regel"})
result = r.text
print(result)

# Opdracht 2

my_string = "opdracht 3"
my_bytes = my_string.encode("utf-8")
# print(my_bytes)

r = requests.post(url + "/opdracht3/" + my_bytes.hex())
result = r.text
print(result)

# Opdracht 3

my_string = "opdracht 4 lijkt heel erg op opdracht 3"
my_bytes = my_string.encode("utf-8")

# print(base64.b64encode(my_bytes))
# print(base64.b64encode(my_bytes).decode("utf-8"))

r = requests.post(url + "/opdracht4/" + base64.b64encode(my_bytes).decode("utf-8"))

result = r.text
print(result)

# Opdracht 4

file = "response.txt"  # Location of the file (can be set a different way)
BLOCK_SIZE = 65536  # The size of each read from the file

file_hash = hashlib.sha512()  # Create the hash object, can use something other than `.sha512()` if you wish
with open(file, 'rb') as f:  # Open the file to read it's bytes
    fb = f.read(BLOCK_SIZE)  # Read from the file. Take in the amount declared above
    while len(fb) > 0:  # While there is still data being read from the file
        file_hash.update(fb)  # Update the hash
        fb = f.read(BLOCK_SIZE)  # Read the next block from the file

# print(file_hash.hexdigest())  # Get the hexadecimal digest of the hash

r = requests.post(url + "/opdracht5",
                  json={"sha512": file_hash.hexdigest(), "relatieve_url": "/static/opdracht4"})

result = r.text
print(result)

# Opdracht 5

real_checksum = "5f2a5c31a292cc46bacf546c961a8424"

files = ["/static/opdracht5/applicatie_jos.exe",
         "/static/opdracht5/applicatie_jef.exe",
         "/static/opdracht5/applicatie_odilon.exe",
         "/static/opdracht5/applicatie_george.exe",
         "/static/opdracht5/applicatie_mariette.exe",
         "/static/opdracht5/applicatie_ivonne.exe"]

for file in files:
    file_name = file[18:]
    urllib.request.urlretrieve(url + file,
                               os.getcwd() + "/" + file_name)  # Download file and store it in current directory.
    hasher = hashlib.md5()
    with open(file_name, 'rb') as open_file:
        content = open_file.read()
        hasher.update(content)
    if hasher.hexdigest() == real_checksum:
        correct_file = file_name

correct_file_url = "/static/opdracht5/" + correct_file
r = requests.post(url + "/opdracht6", json={"relatieve_url": correct_file_url})
result = r.text
print(result)

# Opdracht 6


data = b"Geheim bericht bestemd voor de docenten IoT aan de KdG"
# print(data)
key = get_random_bytes(32)  # Creating a 256 bit key (32 * 8 = 256)
# print(key.hex())
cipher = AES.new(key, AES.MODE_EAX)
ciphertext, tag = cipher.encrypt_and_digest(data)
# print(ciphertext.hex())
# print(cipher.nonce.hex())

r = requests.post(url + "/opdracht7", json={"bericht_versleuteld": ciphertext.hex(),
                                            "sleutel": key.hex(),
                                            "nonce": cipher.nonce.hex()})
result = r.text
print(result)
