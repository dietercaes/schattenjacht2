import requests
import base64
import hashlib
import urllib.request
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

url = 'http://185.115.217.205:1234/opdracht2'

r = requests.post('http://185.115.217.205:1234/opdracht2', json={"nr1": "Eerste regel",
                                                                 "nr2": "Tweede regel",
                                                                 "nr3": "Derde regel"})
result = r.text
# print(result)

# Opdracht 2
my_string = "opdracht 3"
my_bytes = my_string.encode("utf-8")
# print(my_bytes)

r = requests.post('http://185.115.217.205:1234/opdracht3/' + my_bytes.hex())

# Opdracht 3

my_string = "opdracht 4 lijkt heel erg op opdracht 3"
my_bytes = my_string.encode("utf-8")

# print(base64.b64encode(my_bytes))
# print(base64.b64encode(my_bytes).decode("utf-8"))

r = requests.post('http://185.115.217.205:1234/opdracht4/' + base64.b64encode(my_bytes).decode("utf-8"))

result = r.text
# print(result)

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

r = requests.post('http://185.115.217.205:1234/opdracht5',
                  json={"sha512": file_hash.hexdigest(), "relatieve_url": "/static/opdracht4"})

result = r.text
# print(result)

# Opdracht 5
real_checksum = "5f2a5c31a292cc46bacf546c961a8424"

files = ["/static/opdracht5/applicatie_jos.exe",
         "/static/opdracht5/applicatie_jef.exe",
         "/static/opdracht5/applicatie_odilon.exe",
         "/static/opdracht5/applicatie_george.exe",
         "/static/opdracht5/applicatie_mariette.exe",
         "/static/opdracht5/applicatie_ivonne.exe"]

#print('Beginning file download with urllib2...')

for file in files:
    url = 'http://185.115.217.205:1234' + file
    file_name = file[18:]
    urllib.request.urlretrieve(url, os.getcwd() + "/" + file_name)

    hasher = hashlib.md5()
    with open(file_name, 'rb') as open_file:
        content = open_file.read()
        hasher.update(content)
    if hasher.hexdigest() == real_checksum:
        correct_file = file_name
        #print(file_name)

correct_file_url = "/static/opdracht5/" + correct_file
r = requests.post('http://185.115.217.205:1234/opdracht6', json={"relatieve_url": correct_file_url})
result = r.text
# print(result)

# Opdracht 6

data = "Geheim bericht bestemd voor de docenten IoT aan de KdG"

key = get_random_bytes(32)  # Creating a 256 bit key (32 * 8 = 256)
print(key)
cipher = AES.new(key, AES.MODE_EAX)
ciphertext, tag = cipher.encrypt_and_digest(data)

file_out = open("encrypted.bin", "wb")
[file_out.write(x) for x in (cipher.nonce, tag, ciphertext)]
file_out.close()

r = requests.post('http://185.115.217.205:1234/opdracht6', json={"bericht_versleuteld": "...",
                                                                 "sleutel": "...",
                                                                 "nonce": "..."})
result = r.text
# print(result)
