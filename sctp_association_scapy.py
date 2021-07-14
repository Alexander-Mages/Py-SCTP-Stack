from scapy.all import *
from threading import Thread
import sys
import time
#from scapy.layers.ssl_tls import *
#from __future__ import print_function
#from __future__ import with_statement
#reads params from user input, easier to change ports
dstip = input("destination IP (IPv4)\n>>")
srcip = input("source IP (IPv4)\n>>")
dstprt = int(input("destination port\n>>"))
srcprt = int(input("source port\n>>"))
	
#network and transport level, remains relatively static (excepting verification tag)
lv1 = IP(dst=dstip,src=srcip,id=0x0000,flags=0x4000)
lv2 = SCTP(dport=dstprt,sport=srcprt,tag=0x0)

#advertised receiver window credit
arwnd = 106496



#ASSOCIATION INITIALIZATION



#INIT


#InitChunk, most values randomly chosen within RFC spec (at least thats the intention)
Init = SCTPChunkInit(flags=0x0,init_tag=0x766832f,a_rwnd=arwnd,n_out_streams=10,n_in_streams=65535,init_tsn=0x5be51d3a)

#sends combined layers. Saves state cookie and verificiation tag to variable.
initAck = sr1(lv1/lv2/Init)
verificationTag = initAck[SCTPChunkInitAck].init_tag
stateCookie = initAck[SCTPChunkParamStateCookie].cookie
print("Response To Init:")
initAck.show()


#COOKIE_ECHO


#cookie echo chunk
CookieEcho = SCTPChunkCookieEcho(flags=0x0,cookie=stateCookie)

#set chunk len param
stateCookieLen = len(CookieEcho)
CookieEcho.len=stateCookieLen

#set verification tag param to init_tag in init_ack
lv2.tag=verificationTag

#send cookie echo with new lv1/2 params
cookieAck = sr1(lv1/lv2/CookieEcho)
print("Reponse To Cookie_Echo:")
cookieAck.show()




#ASSOCIATION ESTABLISHED

#Answering Machines
#match and send correct request/response pairs

#HEARTBEAT ACK


class heartbeatAck(AnsweringMachine):
	def is_request(self, request):
		return request.haslayer('SCTPChunkHeartbeatReq')
	
	def make_reply(self, request):
		#Save HeartbeatInfo to variable
		heartBeatInfo = request[SCTPChunkParamHearbeatInfo].data
		heartBeatAck = SCTPChunkHeartbeatAck(params=SCTPChunkParamHearbeatInfo(data=heartBeatInfo))
		#Transmit ACK
		print("Heartbeat Request recieved, sending heartbeat ack")
		response = (lv1/lv2/heartBeatAck)
		
		return response


#SACK


class SACK(AnsweringMachine):
	def is_request(self, request):
		return request.haslayer('SCTPChunkData') and request[SCTP].dport == srcprt
	
	def make_reply(self, request):
		#print data recieved from server
		print("\nServer Data Chunk: " + str(request[SCTPChunkData].data))
		#set cumulative tsn ack to request tsn
		cumultsnack = request[SCTPChunkData].tsn
		ngapack = 0
		nduptsn = 0
		#form packet, combine layers, and transmit
		SACK = SCTPChunkSACK(cumul_tsn_ack=cumultsnack,a_rwnd=arwnd,n_gap_ack=ngapack,n_dup_tsn=nduptsn)
		response = (lv1/lv2/SACK)

		return response
	
	
#ABORT


class Abort(AnsweringMachine):
	def is_request(self, request):
		return request.haslayer('SCTPChunkAbort')

	def make_reply(self, request):
		#should exit the script, will most likely render it unfunctional
		print('Abort Chunk Recieved, ignoring, association will likely persist')
		#not sure why this doesnt exit
		return



#SHUTDOWN PROCESS


class ShutdownAck(AnsweringMachine):
	def is_request(self, request):
		return request.haslayer('SCTPChunkShutdown')

	def make_reply(self, request):
		#create and send shutdown ack
		print("Shutdown Chunk Recieved, Sending Shutdown Ack")
		shutdownack = SCTPChunkShutdownAck(flags=0x0,len=4)
		response = sr1(lv1/lv2/shutdownack)
		return response
		
	def is_request(self, response):
		return response.haslayer('SCTPChunkShutdownComplete')
	
	def make_reply(self, response):
		#if server replied with shutdown complete chunk, script (in theory) exits
		print("Shutdown Completed")
		return exit()


#ERROR


class Error(AnsweringMachine):
	def is_request(self, request):
		return request.haslayer('SCTPChunkError')

	def make_reply(self, request):
		#returns error data from request
		print(request[SCTPChunkError].error_causes)
		return


#OUTBOUND DATA

	
def listenData():
	while True:
		#reads input, exits loop if q is entered
		datainput = input("(q to quit)\nSend Data Chunk>>")
		if datainput == "q":
			break
		#combines layers, sends data with valid parameters
		datachunk = SCTPChunkData(beginning=1,ending=1,tsn=2541741882,stream_id=0x0000,stream_seq=0,data=datainput)
		response = sr1(lv1/lv2/datachunk)
		response.show()




#THREAD INITIALIZATION

#name thread for SACK
selective_ack = Thread(target=SACK())
selective_ack.start()
#name thread for shutdownack
shutdown_ack = Thread(target=ShutdownAck())
shutdown_ack.start()
#Name thread for heartbeat
heartbeat_ack = Thread(target=heartbeatAck())
heartbeat_ack.start()
#name thread for abort 
abort = Thread(target=Abort())
abort.start()
#name thread for listenData
listen_data = Thread(target=listenData())
listen_data.start()
#run threads in parallel
heartbeat_ack.join()
selective_ack.join()
abort.join()
shutdown_ack.join()
listen_data.join()



#SSL attempt, modified version of code on github. Does not work, either a simple reason, or something to do with multistreaming. (RFC says that one should complete the TLS handshake over every bidirectional stream. Seems like there has to be a better way.)

"""
tls_version = TLSVersion.TLS_1_2
ciphers = [TLSCipherSuite.ECDHE_RSA_WITH_AES_128_GCM_SHA256]

extensions = [TLSExtension() / TLSExtECPointsFormat(),
              TLSExtension() / TLSExtSupportedGroups()]


def tls_client(ip):
    with TLSSocket(client=True) as tls_socket:
        try:
            tls_socket.connect(ip)
            print("Connected to server: %s" % (ip,))
        except socket.timeout:
            print("Failed to open connection to server: %s" % (ip,), file=sys.stderr)
        else:
            try:
                server_hello, server_kex = tls_socket.do_handshake(tls_version, ciphers, extensions)
                server_hello.show()
            except TLSProtocolError as tpe:
                print("Got TLS error: %s" % tpe, file=sys.stderr)
                tpe.response.show()
            else:
                resp = tls_socket.do_round_trip(TLSPlaintext(data="GET / HTTP/1.1\r\nHOST: localhost\r\n\r\n"))
                print("Got response from server")
                resp.show()
            finally:
                print(tls_socket.tls_ctx)


if __name__ == "__main__":
    if len(sys.argv) > 2:
        server = (sys.argv[1], int(sys.argv[2]))
    else:
        server = ("127.0.0.1", 8443)
    tls_client(server)
"""
