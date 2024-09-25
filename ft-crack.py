import hashlib
import hmac
import struct
import argparse
import sys
import os
from Crypto.Hash import CMAC
from Crypto.Cipher import AES


def print_banner():
	'''
	Function to just pretty print a banner
	'''

	banner = '''\033[95m
	░        ░░        ░░░░░░░░░      ░░░       ░░░░      ░░░░      ░░░  ░░░░  ░
	▒  ▒▒▒▒▒▒▒▒▒▒▒  ▒▒▒▒▒▒▒▒▒▒▒  ▒▒▒▒  ▒▒  ▒▒▒▒  ▒▒  ▒▒▒▒  ▒▒  ▒▒▒▒  ▒▒  ▒▒▒  ▒▒
	▓      ▓▓▓▓▓▓▓  ▓▓▓▓▓▓▓▓▓▓▓  ▓▓▓▓▓▓▓▓       ▓▓▓  ▓▓▓▓  ▓▓  ▓▓▓▓▓▓▓▓     ▓▓▓▓
	█  ███████████  ███████████  ████  ██  ███  ███        ██  ████  ██  ███  ██
	█  ███████████  ████████████      ███  ████  ██  ████  ███      ███  ████  █
	\033[0m	by: liimbo
	'''
	print(banner)



def print_hash_info(mic, mac_ap, mac_cl, ssid, nonce_ap, nonce_cl, mdid, r0kh, r1kh):
	'''
	Function to display the information from the provided hash
	'''

	print("\033[92mSSID:\033[0m\n", ssid.decode())
	print("\033[92mAP MAC:\033[0m\n", "%02x:%02x:%02x:%02x:%02x:%02x" \
		% struct.unpack("BBBBBB", mac_ap))
	print("\033[92mClient:\033[0m\n", "%02x:%02x:%02x:%02x:%02x:%02x" \
		% struct.unpack("BBBBBB", mac_cl))
	print("\033[92mAP Nonce:\033[0m\n", nonce_ap.hex())
	print("\033[92mClient Nonce:\033[0m\n", nonce_cl.hex())
	print("\033[92mMobility ID:\033[0m\n", mdid.hex())
	print("\033[92mR0KH-ID:\033[0m\n", r0kh.hex())
	print("\033[92mR1KH-ID:\033[0m\n", r1kh.hex())
	print("\033[92mMIC:\033[0m\n", mic.hex() + "\n")



def get_hash(hashfile):
	'''
	Used to assign the appropriate parts of the hash into the variables needed
	'''

	if os.path.isfile(hashfile):
		with open(sys.argv[1], 'r', encoding='utf-8') as f:
			ft_hash = f.readline()
		split_hash = ft_hash.split('*')
		f.close()
	elif isinstance(hashfile, str):
                split_hash = hashfile.split('*')
	else:
		raise argparse.ArgumentTypeError("Please check hash to make sure it is correct.")
		sys.exit()

	mic = bytes.fromhex(split_hash[2])
	mac_ap = bytes.fromhex(split_hash[3])
	mac_cl = bytes.fromhex(split_hash[4])
	ssid = bytes.fromhex(split_hash[5])
	nonce_ap = bytes.fromhex(split_hash[6])
	nonce_cl = bytes.fromhex(split_hash[7][34:98])
	eapol_client = bytes.fromhex(split_hash[7])
	mdid = bytes.fromhex(split_hash[9])
	r0kh = bytes.fromhex(split_hash[10])
	r1kh = bytes.fromhex(split_hash[11])

	return mic, mac_ap, mac_cl, ssid, nonce_ap, nonce_cl, eapol_client, mdid, r0kh, r1kh



def sha256_prf(key,A,B,size):
	'''
	New implementation of the SHA256 PRF needed to generate the correct keys for FT
	'''

	blen = int(size / 8)
	num_iter = round((blen / 32))

	counter = 1
	R = b''

	for i in range(num_iter):
		hmacsha256 = hmac.new(key,counter.to_bytes(2,'little')+A+B+size.to_bytes(2,'little'),hashlib.sha256)
		counter+=1
		R = R+hmacsha256.digest()

	return R[:blen]



def crack_handshake(mic, mac_ap, mac_cl, ssid, nonce_ap, nonce_cl, eapol, mdid, r0kh, r1kh):
	'''
	Main logic for the script. Calculates the MIC for each word in a wordlist, compares
	it with the value in the hash.
	'''

	if not args.quiet:
		print_hash_info(mic, mac_ap, mac_cl, ssid, nonce_ap, nonce_cl, mdid, r0kh, r1kh)

	print("Attempting to crack...\n")

	for word in args.wordlist:
		password = word.strip().encode()

		pmk = hashlib.pbkdf2_hmac('sha1', password, ssid, 4096, 32)

		r0_key_data = sha256_prf(pmk, b"FT-R0", len(ssid).to_bytes() + ssid + mdid + len(r0kh).to_bytes() + r0kh + mac_cl, 384)
		pmkr0 = r0_key_data[:32]

		# We won't really use this, so I'm not going to spend time working on it.
		# But the names are started to be derived from the first PRF
		pmkr0_name_salt = r0_key_data[32:]
		pmkr0_name = hashlib.sha256(b"FT-R0N"+pmkr0_name_salt).digest()[:16]

		pmkr1 = sha256_prf(pmkr0, b"FT-R1", r1kh + mac_cl, 256)

		# Same idea here; may use it in the future for something, but for now ignoring
		# (because I'm not confident these are correct)
		pmkr1_name = hashlib.sha256(b"FT-R1N"+pmkr0_name+r1kh+mac_cl).digest()[:16]

		ptk_name = hashlib.sha256(pmkr1_name + b"FT-PTKN" + nonce_cl+nonce_ap+mac_ap+mac_cl).digest()[:16]

		ptk = sha256_prf(pmkr1,b"FT-PTK",nonce_cl+nonce_ap+mac_ap+mac_cl,384)

		calc_mic = CMAC.new(ptk[:16],msg=eapol,ciphermod=AES).hexdigest()

		if args.verbose:
			line_up = '\033[1A'
			line_clear = '\x1b[2K'

			print("PMK:\t\t\t%s\n" % pmk.hex())
			print("PMK-R0:\t\t\t%s" % pmkr0.hex())
			print("PMK-R1:\t\t\t%s\n" % pmkr1.hex())
			print("KCK:\t\t\t%s" % ptk[:16].hex())
			print("KEK:\t\t\t%s" % ptk[16:32].hex())
			print("\nCalculated MIC:\t\t%s" % calc_mic)

			if calc_mic == mic.hex():
                                print("\n\033[93mFOUND!\033[0m")
       	                        print("Password:\t\t", password.decode())
               	                sys.exit()

			for i in range(9):
				print(line_up, end=line_clear)

		elif calc_mic == mic.hex():
			print("\n\033[93mFOUND!\033[0m")
			print("Password:\t\t", password.decode())
			sys.exit()

	print("\n\033[93mUNABLE TO CRACK!\033[0m")
	sys.exit()


if __name__ == '__main__':

	parser = argparse.ArgumentParser(prog='ft-crack.py', description='Script to crack FT-PSK handshakes for WPA. Takes in a hash on the command line or from a file. Currently supports single hash.')
	parser.add_argument('hashfile', help='File or string containing the hash to crack')
	parser.add_argument('-w','--wordlist', help='File containing the wordlist to use', required=True, type=argparse.FileType('r',encoding='utf-8'))
	parser.add_argument('-v','--verbose', help='Prints out addtional information while crack is running', required=False, action='store_true')
	parser.add_argument('-q','--quiet', help='Flag to disable printing of extra information', required=False, action='store_true')
	args = parser.parse_args()

	if not args.quiet:
		print_banner()

	mic, mac_ap, mac_cl, ssid, nonce_ap, nonce_cl, eapol, mdid, r0kh, r1kh = get_hash(args.hashfile)
	crack_handshake(mic, mac_ap, mac_cl, ssid, nonce_ap, nonce_cl, eapol, mdid, r0kh, r1kh)
