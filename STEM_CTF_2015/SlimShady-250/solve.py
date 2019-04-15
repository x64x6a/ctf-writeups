'''
>python solve.py
It's me, Eminem.Attached is a passcode
MCA-4df66734
Wassup, Its me, Eminem.Attached is my password
MCA-38292305
Yo, It's me, Double M.I heard you needed my password
MCA-e92d9a25
Yo, Its me, Double M.Attached is the passcode
MCA-9cf27728
Hey, Its me, Double M.I got you the pw
MCA-c37a3273
>

# flag was MCA-9cf27728
'''
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
import BeautifulSoup
rsa_keys_txt = [
	'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDgGg6YJuFsNE7hvkHQcdhGih7lhzDj7pXt6bBwr9BjYLSB4ry/iPKpfsXxoU3WsjUz6UsLfan7AcPrnqLm8zVtDS2m4qBVBVZwLIifSWM1U+dSMn7nGU4qzrRqZ+57+mSRsxYM8r20GkBvudFSNStRqOvoOtCBTDQCs7dXydtFOw==',
	'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDJ+d5ES0TscW7OeGBIUtCNNo5/1Iy0p2tNXVVA2hPMGpBh6yyhIOn5y8aNlcQ/l13gCXy8yxuK9FlX3aelE0t8n6dXHWT4SAQ57mDaITYFY3imZ1pqnrqM22gnACnHDmatIaCbWBK01gRN4g3dDBI6oL5b4KPUvEdB8wEGs0Rz+Q==',
	'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC5KL/gNbl6pvcHEAadjebsQRd8MNj4pqi6/XFE++/h7Ymi9uTZJQFHP+7Gucpo+NQtXToTqH2226CKb4rXGk6xxX9HtQcCJQVHhHucUlym9kxHmff2PC+mDIqx1oiGsEnMHSJpaiqulbhKJrxAFFtSOF1XjmqR2KrR34icTIqyAw==',
	'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQCbT3x5Uk2aQuExM/mozvXZvoZ3HC5hsHgG18FLAmb2mESHm2ZvPveqDt/dqOop+5hSoY5L5zsfi61Xec9kCKTn6AgVDWMG7EHyr4jyQ5bL6je+jdcIEVgCL+WqkWR16RNZzPIkdkPzxl+6h5DF1vplWggStvZOv5DVvkpFWHMLMQ==',
	'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQCrEy+uuFhtugMlOIeMy1slvKbutz4hAOHT50l9x56UCz9Cql2E6fxx/OheyC7CBygPcbKpucpyYWawWxyBwfbBVAWQogpyf+oSZXuAB/zzvu+dLiXm508iJnYEK2Ha+8XaoLcxbdaZGxykEa2sBBLu0LPtHFVSBF/YDwK8tsx0LQ==',
]
rsa_keys = [RSA.importKey(key) for key in rsa_keys_txt]


with open('email.xml') as f:
	y=BeautifulSoup.BeautifulSoup(f.read())

emails = y.findAll('email')

for key in rsa_keys:
	for email in emails:
		text = email.message.text
		hash = SHA256.new(text).digest()
		signature = (int(email.signature.text),)
		if key.verify(hash, signature):
			print email.message.text
