from encrypted_package_pb2 import EncryptedPackage
import socket
import select
import argparse
import struct
import logging
import binascii


def main():
	logging.basicConfig(level=logging.INFO)

	parser = argparse.ArgumentParser()

	parser.add_argument('-p', '--port', dest='port', help='port', type=int, required=True)
	args = parser.parse_args()

	listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	listen_socket.bind(('', args.port))
	listen_socket.listen(1)  # specify the "backlog" for this socket

	connected_clients = []
	client_map = {}

	while True:
		read_list = [listen_socket] + connected_clients
		(ready_list, _, _) = select.select(read_list, [], [])
		for ready in ready_list:
			if ready is listen_socket:
				conn, addr = ready.accept()  # accept the connection
				logging.info('accepted new client connection from %s' % str(addr))
				connected_clients += [conn]
				client_map[conn] = str(addr)
			else:
				try:
					data_len_packed = ready.recv(4, socket.MSG_WAITALL)
					if len(data_len_packed) == 0:
						logging.info('client (%s) disconnected' % client_map[ready])
						connected_clients.remove(ready)
						del client_map[ready]
					else:
						data_len = struct.unpack('!L', data_len_packed)[0]
						logging.info('client (%s) is sending %d-byte long protobuf' %
									 (client_map[ready], data_len))
						protobuf = ready.recv(data_len, socket.MSG_WAITALL)
						try:
							encrypted_package = EncryptedPackage()
							encrypted_package.ParseFromString(protobuf)
							logging.info('iv is %s' %
										 binascii.hexlify(encrypted_package.iv))
							for other_socket in connected_clients:
								if other_socket == ready: continue
								other_socket.send(data_len_packed)
								other_socket.send(protobuf)
						except Exception as e:
							logging.warn('cannot decode EncryptedPackage: %s' % e)
				except ConnectionResetError:
					logging.info('client (%s) threw a connectionResetError. Removing.'
								 % client_map[ready])
					connected_clients.remove(ready)
					del client_map[ready]


if __name__ == '__main__':
	main()
