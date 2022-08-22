import pefile, ssdeep, psycopg2
from datetime import datetime
from filehash import FileHash

connection = psycopg2.connect(user="postgres",
                              password="pwd",
                              host="127.0.0.1",
                              port="5432",
                              database="malw_db")
cursor = connection.cursor()

file = "/home/dev/Desktop/emotet.exe"
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
    print(row[6])
    
print("-----------\nssdeep compare:")
cursor.execute("SELECT ssdeep, file_sha512 FROM malware")
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
	cursor.execute("SELECT file_sha512, name FROM sections WHERE section_md5 = %s OR section_sha1 = %s OR section_sha256 = %s OR section_sha512 = %s", (section_md5, section_sha1, section_sha256, section_sha512,))
	result_set = cursor.fetchall()
	print("\tFound", len(result_set)," matches: ")
	for row in result_set:
	    print("\t\tSection", row[1], "matches in", row[0])
	cursor.execute('INSERT INTO sections (file_sha512, name, section_md5, section_sha1, section_sha256, section_sha512) VALUES (%s, %s, %s, %s, %s, %s)', (file_sha512, name, section_md5, section_sha1, section_sha256, section_sha512))
	connection.commit()

"""
RESULT EXAMPLE
File name:  /home/dev/Desktop/emotet.exe
Compilation timestamp:  2015-11-12 18:44:45
MD5:  f46760dde255ede0893d16da99853479
sha1:  a5eff59f9e6b521ef26993aabe9fde7c1891eba2
sha256:  d6a29fd9aa6e32884e5319ccc5780b04fc95436311f83e7a857a731c7c42157f
sha512:  a155df2a2f52cfc1a1c2602d0e7407b8a53bb9ed745a3c75ea98a0a47ec8db773a50c2eac6112d79cd403941bd34a597f56fa3b3e57e1749c05ba0d883ab1703
Imphash:  f7eedf970238bb516041f4bd90f41d32
Ssdeep:  6144:jXXe6AlgKhwpyy3DeGoOqnAh/cMJQMuVuZQQQQQQQQQQQQQQQQQQBvgZXn:jnouTSGoOqMkMJQMguZQQQQQQQQQQQQq
-----------
Found 1 matches: 
a155df2a2f52cfc1a1c2602d0e7407b8a53bb9ed745a3c75ea98a0a47ec8db773a50c2eac6112d79cd403941bd34a597f56fa3b3e57e1749c05ba0d883ab1703
-----------
ssdeep compare:
100 % match with a155df2a2f52cfc1a1c2602d0e7407b8a53bb9ed745a3c75ea98a0a47ec8db773a50c2eac6112d79cd403941bd34a597f56fa3b3e57e1749c05ba0d883ab1703
-----------
NumberOfSections:  3
-----------
Section name: .text
	Entropy (Min=0.0, Max=8.0): 7.549989525536801
	MD5 hash:  83ecf2c7b214a650c6410e626104f034
	SHA1 hash:  330358ecff4ed91cad7ed5b0b94b8fc8c84bd905
	SHA256 hash:  f2f50043d8c5233f7ce3d44264acfd6fb329ae4d0a81dea006b8e071771b1511
	SHA512 hash:  972a05c7d70d4d245a29747c84e341a53e27d7663c60b52755e13e88be1fdb50b481d7c3728ee49297c39e2184268de9ff958dabcc438ec388539bd19841f1e4
	Virtual size:  259776
	SizeOfRawData:  262144
	Flags:  1610612768
	Found 1  matches: 
		Section .text matches in a155df2a2f52cfc1a1c2602d0e7407b8a53bb9ed745a3c75ea98a0a47ec8db773a50c2eac6112d79cd403941bd34a597f56fa3b3e57e1749c05ba0d883ab1703
-----------
Section name: .data
	Entropy (Min=0.0, Max=8.0): 0.0
	MD5 hash:  620f0b67a91f7f74151bc5be745b7110
	SHA1 hash:  1ceaf73df40e531df3bfb26b4fb7cd95fb7bff1d
	SHA256 hash:  ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7
	SHA512 hash:  2d23913d3759ef01704a86b4bee3ac8a29002313ecc98a7424425a78170f219577822fd77e4ae96313547696ad7d5949b58e12d5063ef2ee063b595740a3a12d
	Virtual size:  8632
	SizeOfRawData:  4096
	Flags:  3221225536
	Found 1  matches: 
		Section .data matches in a155df2a2f52cfc1a1c2602d0e7407b8a53bb9ed745a3c75ea98a0a47ec8db773a50c2eac6112d79cd403941bd34a597f56fa3b3e57e1749c05ba0d883ab1703
-----------
Section name: .rsrc
	Entropy (Min=0.0, Max=8.0): 2.1005310015699044
	MD5 hash:  8c3ff9780a45759f62fe015ed1783875
	SHA1 hash:  95059ebab0e0ab91dd6ff8a994baeefc4487bf85
	SHA256 hash:  83fe9a9bdb0107cf1a4134c8f278da851afd5492fc3b37b532034b775040ae0e
	SHA512 hash:  cc4d3c36bddf49285b80cc99b7aad2ee4dab8f031a7aecbc8560315b2238c54b8f5eaa8dd4eeeee189a6a37ec4f5edb1f48d641f1cd1a5855d032ab0464481c3
	Virtual size:  2388
	SizeOfRawData:  4096
	Flags:  1073741888
	Found 1  matches: 
		Section .rsrc matches in a155df2a2f52cfc1a1c2602d0e7407b8a53bb9ed745a3c75ea98a0a47ec8db773a50c2eac6112d79cd403941bd34a597f56fa3b3e57e1749c05ba0d883ab1703


"""


