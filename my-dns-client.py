from socket import *
import sys
import random


if len(sys.argv)<2 or len(sys.argv)>2: 
	sys.exit('Invalid Input')
	#We are checking if the user has given an argument or not and the user cannot proide more than one argument


string_id=""
for i in range(16):
	string_id=string_id+str(random.randint(0,1))
hex_id=hex(int(string_id,2))

field_in_binary="0000000100000000"#binary, 0|0000|0010|000|0000
fields_in_hex="0100"#hex, 0|0000|0010|000|0000(binary respresentation)
qdcount="0001"#hex
ancount="0000"#hex
nscount="0000"#hex
arcount="0000"#hex

name=sys.argv[1]
host=name.split(".")
qname=""
for i,domain in enumerate(host):
	j=0
	buffer_string=""
	for c in domain:
		j=j+1
		buffer_string=buffer_string+hex(ord(c)).replace("0x","")
	dd=hex(j).replace("0x","")
	if(len(dd)== 1):
		qname=qname+"0"+dd+buffer_string
	elif(len(dd)==2):
		qname=qname+dd+buffer_string
qname=qname+"00"#Qname field ends with '00'
qtype="0001"# for type A record, its '1'

final_query=str(hex_id).replace("0x","")+fields_in_hex+qdcount+ancount+nscount+arcount+qname+qtype+"0001"
#we added '0001' at the end of the string to define QCLASS as 1, for internet
print("Preparing DNS query..")

serverName = '8.8.8.8'
serverPort = 53
clientSocket = socket(AF_INET, SOCK_DGRAM)
clientSocket.settimeout(5)
#Setting timeout as 5
print("Preparing DNS query..")
message = final_query
result=bytes.fromhex(message)
flag=1
retry_count=0
clientSocket.sendto(result,(serverName, serverPort))
print("Sending DNS query..")

try:
	modifiedMessage, serverAddress = clientSocket.recvfrom(2048)
	#our output is stored in modifiedmessage
except :
	print("Waiting for response(5 seconds have elapsed)")
	retry_count=retry_count+1
	flag=0
if flag == 0:
	try:
		modifiedMessage, serverAddress = clientSocket.recvfrom(2048)
	except :
		print("Waiting for response(10 seconds have elapsed)")
		retry_count=retry_count+1
		flag=0
if flag == 0:
	try:
		modifiedMessage, serverAddress = clientSocket.recvfrom(2048)
	except :
		retry_count=retry_count+1
		sys.exit('No response received. Exiting program.')		

print("DNS response received (attempt "+str(retry_count+1)+" of 3)")
data=bytearray(modifiedMessage)
#We are converting our output data to bytearray
packet=""
packet_hex=""
for test in data:
	#iterating theough the byte objects in Bytearray
	bin_str=bin(test).replace("0b","")#converting byte object to binary
	blen=len(bin_str)
	#packet_hex=packet_hex+hex(test).replace("0x","")#converting byte object to hex, There is no use of this line
	while(blen != 8):
		#We are converting all binary input to a standard 8 digit form
		bin_str="0"+bin_str
		blen=blen+1	
	packet=packet+bin_str#concatenating the binaries
print("Processing DNS response..")

#Segregating fields
header_id=packet[0:16]
header_fields=packet[16:32]
header_qdcount=packet[32:48]
header_ancount=packet[48:64]
header_nscount=packet[64:80]
header_arcount=packet[80:96]
a=96
b=a+8
while (packet[a:b] != "00000000"):
	a=a+8
	b=a+8
header_qname=packet[96:a]
c=b+16
header_qtype=packet[b:c]
b=c
c=b+16
header_qclase=packet[b:c]
b=c
c=b+16
answer_name=packet[b:c]
b=c
c=b+16
answer_type=packet[b:c]
b=c
c=b+16
answer_class=packet[b:c]
b=c
c=b+32
answer_ttl=packet[b:c]
b=c
c=b+16
answer_len=packet[b:c]
answer_data=packet[c:]
print("--------------------------")


print("header.ID = "+str(hex(int(str(header_id),2))).strip("0x"))#Input is converted from binary to hex
print("header.QR = "+str(header_fields[0]))
print("header.OPCODE = "+str(header_fields[1:5]))

print("header.AA = "+str(header_fields[5]))
print("header.TC = "+str(header_fields[6]))
print("header.RD = "+str(header_fields[7]))
print("header.RA = "+str(header_fields[8]))
print("header.Z = "+str(header_fields[9:12]))
print("header.RCODE = "+str(header_fields[12:]))
print("header.qdcount = "+str(int(str(header_qdcount),2)))#Inputs are binary, they are being converted to int and being printed
print("header.ancount = "+str(int(str(header_ancount),2)))
print("header.nscount = "+str(int(str(header_nscount),2)))
print("header.arcount = "+str(int(str(header_arcount),2)))
print("QNAME = "+ name)
print("QTYPE = "+str(int(str(header_qtype),2)))
print("QCLASS = "+ str(int(str(header_qclase),2)))
answer_counter=int(str(header_ancount),2)
print("")
print("Answers:")
print("")
next_data=""
while answer_counter:
	if(int(str(answer_type),2) == 1):
		#We check here if Answer Type is A or not. If the type is A, the value would be 1. 
		print("NAME 		= "+name)
		print("TYPE 		= "+str(int(str(answer_type),2)))
		print("CLASS 		= "+str(int(str(answer_class),2)))
		print("TTL 		= "+str(int(str(answer_ttl),2)))
		print("RDLENGTH	= "+str(int(str(answer_len),2)))
		out_ip=str(int(str(answer_data[0:8]),2))+"."+str(int(str(answer_data[8:16]),2))+"."+str(int(str(answer_data[16:24]),2))+"."+str(int(str(answer_data[24:32]),2))
		print("RDATA		= "+out_ip)
		print("")
		#We are intializing our inputs for next step
		next_data=answer_data[32:]
		answer_name=next_data[0:16]
		answer_type=next_data[16:32]
		answer_class=next_data[32:48]
		answer_ttl=next_data[48:80]
		answer_len=next_data[80:96]
		answer_data=next_data[96:]
	else:
		#If the answer type is not A, we jump a number of bits
		if not next_data:
			#if the first input is not A
			temp=int(str(answer_len),2)*8
			next_data=answer_data[temp:]
		else:	
			temp=int(str(answer_len),2)*8
			temp=temp+96
			#temp is storing the adress space for an answer which is not of type A
			next_data=next_data[temp:]
		answer_name=next_data[0:16]
		answer_type=next_data[16:32]
		answer_class=next_data[32:48]
		answer_ttl=next_data[48:80]
		answer_len=next_data[80:96]
		answer_data=next_data[96:]

	answer_counter=answer_counter-1


clientSocket.close()
