import pefile, ssdeep, psycopg2
from datetime import datetime
from filehash import FileHash

connection = psycopg2.connect(user="postgres",
                              password="pwd",
                              host="127.0.0.1",
                              port="5432",
                              database="malw_db")
cursor = connection.cursor()


#CREATE DATABASE malw_db;
#create table sections (file_sha512 varchar(128), name varchar(255), section_md5 varchar(32), section_sha1 varchar(40), section_sha256 varchar(64), section_sha512 varchar(128)); 
#create table malware(id serial PRIMARY KEY, time varchar(40), imphash varchar(32), file_md5 varchar(32), file_sha1 varchar(40), file_sha256 varchar(64), file_sha512 varchar(128), ssdeep varchar(255), section_num int); 

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
