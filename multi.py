import hashlib, hmac, sys, struct
from concurrent.futures import ThreadPoolExecutor, as_completed

# Default Values
hashline = None
passlist_src = "passlist.txt"
found = False  # To break all threads once a password is found

# Pull values from hashline if given (hc22000)
if len(sys.argv) > 1:
    hashline = sys.argv[1]
    hl = hashline.split("*")
    mic = bytes.fromhex(hl[2])
    mac_ap = bytes.fromhex(hl[3])
    mac_cl = bytes.fromhex(hl[4])
    essid = bytes.fromhex(hl[5])
    nonce_ap = bytes.fromhex(hl[6])
    nonce_cl = bytes.fromhex(hl[7][34:98])
    eapol_client = bytes.fromhex(hl[7])

if len(sys.argv) > 2:
    passlist_src = sys.argv[2]

# Read passlist
with open(passlist_src, 'r', encoding="UTF-8") as f:
    passlist = f.read().splitlines()

# Print info
print('\033[95m')
print("MIC:                      ", mic.hex())
print("SSID:                     ", essid.decode())
print("AP MAC Address:           ", "%02x:%02x:%02x:%02x:%02x:%02x" % struct.unpack("BBBBBB", mac_ap))
print("Client MAC Address:       ", "%02x:%02x:%02x:%02x:%02x:%02x" % struct.unpack("BBBBBB", mac_cl))
print("AP Nonce:                 ", nonce_ap.hex())
print("Client Nonce:             ", nonce_cl.hex())
print("\nEAPoL Client:           ", "\n" + eapol_client.hex())
print('\x1b[0m')

proceed = input("Attempt crack with these settings? (y/n): ")
if proceed.lower() not in ["y", ""]:
    sys.exit()

print('\033[1m' + '\33[33m' + "Attempting to crack password...\n" + '\x1b[0m')


# Helper to sort bytes
def min_max(a, b):
    if len(a) != len(b): raise Exception('Unequal byte string lengths')
    for entry in zip(a, b):
        if entry[0] < entry[1]:
            return (a, b)
        elif entry[1] < entry[0]:
            return (b, a)
    return (a, b)


macs = min_max(mac_ap, mac_cl)
nonces = min_max(nonce_ap, nonce_cl)
ptk_inputs = b''.join([
    b'Pairwise key expansion\x00', macs[0], macs[1], nonces[0], nonces[1], b'\x00'
])


# Crack function for a single password
def try_password(password):
    global found
    if found: return None
    password_bytes = password.encode()
    pmk = hashlib.pbkdf2_hmac('sha1', password_bytes, essid, 4096, 32)
    ptk = hmac.new(pmk, ptk_inputs, hashlib.sha1).digest()
    try_mic = hmac.new(ptk[:16], eapol_client, hashlib.sha1).digest()[:16]

    if try_mic == mic:
        found = True
        return password
    else:
        print(try_mic.hex())
        return None


# Run multithreaded cracking
with ThreadPoolExecutor(max_workers=20) as executor:
    futures = {executor.submit(try_password, pw): pw for pw in passlist}
    for future in as_completed(futures):
        result = future.result()
        if result:
            print('\033[92m' + "\nPassword Cracked!" + '\x1b[0m')
            print("SSID:     ", essid.decode())
            print("Password: ", result)
            break
    else:
        print('\033[91m' + "\nFailed to crack password. Try a different passlist." + '\x1b[0m')
