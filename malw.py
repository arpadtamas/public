import pefile, ssdeep, psycopg2
from datetime import datetime
from filehash import FileHash

connection = psycopg2.connect(user="postgres",
                              password="pwd",
                              host="127.0.0.1",
                              port="5432",
                              database="malw_db")
cursor = connection.cursor()

file = "/home/dev/Desktop/emotet3.exe"
malware = pefile.PE(file)

time = malware.FILE_HEADER.TimeDateStamp
imphash = malware.get_imphash()
file_md5 = FileHash("md5").hash_file(file)
file_sha1 = FileHash("sha1").hash_file(file)
file_sha256 = FileHash("sha256").hash_file(file)
file_sha512 = FileHash("sha512").hash_file(file)
ssdeep_hash = ssdeep.hash_from_file(file)
section_num = int(malware.FILE_HEADER.NumberOfSections)


print("File name: ", file)
print("Compilation timestamp: ", datetime.fromtimestamp(time))
print("MD5: ", file_md5)
print("sha1: ", file_sha1)
print("sha256: ", file_sha256)
print("sha512: ", file_sha512)
print("Imphash: ", imphash)
print("Ssdeep: ", ssdeep_hash)

cursor.execute("SELECT * FROM malware WHERE imphash = %s OR file_md5 = %s OR file_sha1 = %s OR file_sha256 = %s OR file_sha512 = %s", (imphash, file_md5, file_sha1, file_sha256, file_sha512,))
result_set = cursor.fetchall()
print("-----------\nFound", len(result_set),"matches: ")
for row in result_set:
    print(row[5])
    
print("-----------\nssdeep compare:")
cursor.execute("SELECT ssdeep, file_sha256 FROM malware")
result_set = cursor.fetchall()
for row in result_set:
	percentage = ssdeep.compare(ssdeep_hash, row[0])
	if (percentage) > 0:
		print(percentage, "% match with", row[1])
    
    
cursor.execute('INSERT INTO malware (time, imphash, file_md5, file_sha1, file_sha256, file_sha512, ssdeep, section_num) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)', (time, imphash, file_md5, file_sha1, file_sha256, file_sha512, ssdeep_hash, section_num))
connection.commit()


print("-----------\nNumberOfSections: ", section_num)

for x in range(0, section_num):
	name = malware.sections[x].Name.decode(errors='replace',).rstrip('\x00')
	section_md5 = malware.sections[x].get_hash_md5()
	section_sha1 = malware.sections[x].get_hash_sha1()
	section_sha256 = malware.sections[x].get_hash_sha256()
	section_sha512 = malware.sections[x].get_hash_sha512()
	print("-----------\nSection name:", name)
	print("\tEntropy (Min=0.0, Max=8.0):", malware.sections[x].get_entropy())
	print("\tMD5 hash: ", section_md5)
	print("\tSHA1 hash: ", section_sha1)
	print("\tSHA256 hash: ", section_sha256)
	print("\tSHA512 hash: ", section_sha512)
	print("\tVirtual size: ", malware.sections[x].Misc_VirtualSize)
	print("\tSizeOfRawData: ", malware.sections[x].SizeOfRawData)
	print("\tFlags: ", malware.sections[x].Characteristics)
	cursor.execute("SELECT file_sha256, name FROM sections WHERE section_md5 = %s OR section_sha1 = %s OR section_sha256 = %s OR section_sha512 = %s", (section_md5, section_sha1, section_sha256, section_sha512,))
	result_set = cursor.fetchall()
	print("\tFound", len(result_set)," matches: ")
	for row in result_set:
	    print("\t\tSection", row[1], "matches in", row[0])
	cursor.execute('INSERT INTO sections (file_sha256, name, section_md5, section_sha1, section_sha256, section_sha512) VALUES (%s, %s, %s, %s, %s, %s)', (file_sha256, name, section_md5, section_sha1, section_sha256, section_sha256))
	connection.commit()
	
	
"""
RESULT EXAMPLE

File name:  /home/dev/Desktop/emotet3.exe
Compilation timestamp:  2022-07-01 13:47:26
MD5:  b2e8a93629044e790dff4d779dcbcd0d
sha1:  d880badbb5b3041e401db1000079f4b06bb875d3
sha256:  258bb2b23c6ea7434eb8c965a168e7eb87257f5d3e4c4272c5ab29e873d6fbd3
sha512:  ceb3d3e761a1dc88651b63703f728313c515f2e06feec686c1b1e05f424c9fb828345d88cb93ee54fd98c1345429edfb6b774e33e4b4a4f10f2d92290e938d6c
Imphash:  311fcea8519089f91be16d46a87cbd88
Ssdeep:  12288:QolWKutgKC7t1DtuANCqKLvr+U4rG2a/FviAzPVC5Go3DHeFP8ge/wgS0yXD:QolJutQnCqWB5ztqL6x
-----------
Found 2 matches: 
791c0f3e7e6d9c570ad29269ec3bc3f78fadc3c1952f35eb7ac694f3e31551aa
258bb2b23c6ea7434eb8c965a168e7eb87257f5d3e4c4272c5ab29e873d6fbd3
-----------
ssdeep compare:
99 % match with 791c0f3e7e6d9c570ad29269ec3bc3f78fadc3c1952f35eb7ac694f3e31551aa
100 % match with 258bb2b23c6ea7434eb8c965a168e7eb87257f5d3e4c4272c5ab29e873d6fbd3
-----------
NumberOfSections:  6
-----------
Section name: .text
	Entropy (Min=0.0, Max=8.0): 6.44235674698389
	MD5 hash:  cef6e1d01ba2bb6b3398e1569f2d9e71
	SHA1 hash:  008c9593118af992c4e5bccf3850876d8ffee396
	SHA256 hash:  8eed84c3d665fbd725baac9197e5aeb07709f7962366ba0fa719aa7176347ec4
	SHA512 hash:  c950d476c1d83a5ad4b9b9e9f2c9c67d80846cd34e94b21f81b1d0d234a4daa58ad1f1b6e2832f74fe793a79b5b722f24d0efcdb3315589a2ec9f783b533150c
	Virtual size:  148238
	SizeOfRawData:  148480
	Flags:  1610612768
	Found 2  matches: 
		Section .text matches in 791c0f3e7e6d9c570ad29269ec3bc3f78fadc3c1952f35eb7ac694f3e31551aa
		Section .text matches in 258bb2b23c6ea7434eb8c965a168e7eb87257f5d3e4c4272c5ab29e873d6fbd3
-----------
Section name: .rdata
	Entropy (Min=0.0, Max=8.0): 4.593279359686581
	MD5 hash:  45071407a9b88730d94d6bfffa8a3f1d
	SHA1 hash:  e5a069b79076636f963bac200067866eedb173f4
	SHA256 hash:  e6f8b674d8ac3cf69d5cb0c9f6372de7f8132ee1dc5f03d1f4bf7835f6cd2f74
	SHA512 hash:  9a2077224d824d1dfa37b1182d1596ef3c43a1060c6982474699099e29fa00bd65cf9737fc83d799f91bfd837fc6ee3387147266a450928cfdbaa03cb41bce43
	Virtual size:  42962
	SizeOfRawData:  43008
	Flags:  1073741888
	Found 1  matches: 
		Section .rdata matches in 258bb2b23c6ea7434eb8c965a168e7eb87257f5d3e4c4272c5ab29e873d6fbd3
-----------
Section name: .data
	Entropy (Min=0.0, Max=8.0): 3.502583975677695
	MD5 hash:  4ef0e1e3e0bfe5ca04b01ac006835166
	SHA1 hash:  dcf92fe25c8de4b48f8c288c59fc0f4c2908dc82
	SHA256 hash:  5133dba5c6203cc136aee4ba0944bc8eff5cbee512b4f96ecf7b5d368389f30d
	SHA512 hash:  1b41ea18e3de8936e729180720115555322f28866876fb7fbf16425fe6f4a5f5eb298d4d6e1d72cb99add486a41efa294abbedbe734d15e31aa72f4ce3b32be4
	Virtual size:  19492
	SizeOfRawData:  9216
	Flags:  3221225536
	Found 2  matches: 
		Section .data matches in 791c0f3e7e6d9c570ad29269ec3bc3f78fadc3c1952f35eb7ac694f3e31551aa
		Section .data matches in 258bb2b23c6ea7434eb8c965a168e7eb87257f5d3e4c4272c5ab29e873d6fbd3
-----------
Section name: .pdata
	Entropy (Min=0.0, Max=8.0): 5.17276425766517
	MD5 hash:  980b4ee87837daf081d2d6a0f888a29c
	SHA1 hash:  7574e910cdac3fbd46bbfda1e8a166edd016e667
	SHA256 hash:  768da0771a681c4159d3cbc084873864840a5d786b724254d65a5efb9d241e12
	SHA512 hash:  4e1edcf6b156d97f4a7219a4061074772797876225f995d8d6f38e22de049ff01aac335695bb09f4f588a4b5fe1f48893f909826fe583279cbd7b82b389cf9c5
	Virtual size:  7404
	SizeOfRawData:  7680
	Flags:  1073741888
	Found 2  matches: 
		Section .pdata matches in 791c0f3e7e6d9c570ad29269ec3bc3f78fadc3c1952f35eb7ac694f3e31551aa
		Section .pdata matches in 258bb2b23c6ea7434eb8c965a168e7eb87257f5d3e4c4272c5ab29e873d6fbd3
-----------
Section name: .rsrc
	Entropy (Min=0.0, Max=8.0): 7.924545690560659
	MD5 hash:  3c7589095e092441151889a6a17aa4f8
	SHA1 hash:  d6e19244a66c6a16fafabdffcf317819a8ee242f
	SHA256 hash:  3703ab7e6f7646fac074a3de2fb0cc4efcdb2a29c3dd5c0e34ae0c7d7205110e
	SHA512 hash:  bbb06a2d6813d8168c1701dfde3879ee9b7b171c7868f30bc4a5d70cad5ec676cf3990ef629b5c255c3a0d461b489b32296f14cf683210661d4da9d451e72f4f
	Virtual size:  538108
	SizeOfRawData:  538112
	Flags:  1073741888
	Found 2  matches: 
		Section .rsrc matches in 791c0f3e7e6d9c570ad29269ec3bc3f78fadc3c1952f35eb7ac694f3e31551aa
		Section .rsrc matches in 258bb2b23c6ea7434eb8c965a168e7eb87257f5d3e4c4272c5ab29e873d6fbd3
-----------
Section name: .reloc
	Entropy (Min=0.0, Max=8.0): 3.0740959788330127
	MD5 hash:  8265cb79bd9c479f27dd85010440d841
	SHA1 hash:  552a0b20a7fe1c78ea7c0276c831686f41baa9ee
	SHA256 hash:  d4bc750b1ac9130bd4c360fdf51ae5efc51f3b0b921fe4dcf01765ddda7949b6
	SHA512 hash:  44fe7a48a03b4e4c6bb771a7163259ed855f3dc05358feed5518b3eb3bf7d16158aa36ea66a26f45cc33a9f44312a1abe1ee05b74ae3686b396ca43fec8c8085
	Virtual size:  3382
	SizeOfRawData:  3584
	Flags:  1107296320
	Found 2  matches: 
		Section .reloc matches in 791c0f3e7e6d9c570ad29269ec3bc3f78fadc3c1952f35eb7ac694f3e31551aa
		Section .reloc matches in 258bb2b23c6ea7434eb8c965a168e7eb87257f5d3e4c4272c5ab29e873d6fbd3
"""
