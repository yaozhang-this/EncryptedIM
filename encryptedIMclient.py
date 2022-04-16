import argparse
import binascii
import logging
import socket
import select
import struct
import sys
from base64 import b64encode, b64decode
from encrypted_package_pb2 import EncryptedPackage, PlaintextAndMAC, IM
from Crypto.Hash import HMAC, SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def toIM(src, message):
    msg = IM()
    msg.nickname = src
    msg.message = message
    return msg.SerializeToString()


def toPMAC(IM, akey):
    h = HMAC.new(akey, IM, digestmod=SHA256)
    PMAC = PlaintextAndMAC()
    PMAC.mac = h.digest()
    PMAC.paddedPlaintext = pad(IM, AES.block_size)
    return PMAC.SerializeToString()


def toE(PMAC, ckey):
    # if not specified, the iv will be randomly generated automatically by the AES package
    cipher = AES.new(ckey, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(PMAC, AES.block_size))
    # iv sent in clear
    #ct = b64encode(ct_bytes).decode('utf-8')
    ep = EncryptedPackage()
    ep.encryptedMessage = ct_bytes
    ep.iv = cipher.iv
    #print(binascii.hexlify(cipher.iv))
    return ep.SerializeToString()


def rehash(ckey, akey):
    # hash the provided key to forced 256 bits (32bytes) strings to be used by the standard
    h = SHA256.new()
    h.update(str.encode(ckey))
    ckey_res = h.digest()
    h.update(str.encode(akey))
    akey_res = h.digest()
    return ckey_res, akey_res


def parse():
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '-servername', dest='server', help='server address', required=True)
    parser.add_argument('-p', '-port', type=int, dest='port', help='port to connect', required=True)
    parser.add_argument('-n', '-nickname', dest='nickname', help='nickname to be used in chat', required=True)
    parser.add_argument('-c', '-confidentialitykey', dest='ckey', help='confidentiality key for encryption', required=True)
    parser.add_argument('-a', '-authenticitykey', dest='akey', help='authenticity key for encryption', required=True)
    args = parser.parse_args()
    ckey, akey = rehash(args.ckey, args.akey)
    print("Welcome.")
    print(f"You are connecting to server {args.server} with port {args.port} and nickname {args.nickname}")

    return args.server, args.port, args.nickname, ckey, akey


def establish(server, port, nickname, ckey, akey):
    global s
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_address = (server, port)
        s.connect(server_address)
        read_handles = [sys.stdin, s]
        write_handles = []
        error_handles = []
        while True:
            readable, writable, error = select.select(read_handles, write_handles, error_handles)
            if sys.stdin in readable:
                userInput = input()
                im = toIM(nickname, userInput)
                PMAC = toPMAC(im, akey)
                payload = toE(PMAC, ckey)
                length_of_encrypted_package = len(payload)
                packed_length_of_encrypted_package = struct.pack('!L', length_of_encrypted_package)
                # get the length, partition them into parts, then read them one by one and concatenate
                s.send(packed_length_of_encrypted_package)
                s.send(payload)
            if s in readable:
                data_len_packed = s.recv(4, socket.MSG_WAITALL)
                if len(data_len_packed) == 0:
                    read_handles.remove(s)
                    print("[INFO] Disconnected from server")
                    break
                else:
                    data_len = struct.unpack('!L', data_len_packed)[0]
                    protobuf = s.recv(data_len, socket.MSG_WAITALL)
                    try:
                        encrypted_package = EncryptedPackage()
                        encrypted_package.ParseFromString(protobuf)
                        #logging.info('iv is %s' % binascii.hexlify(encrypted_package.iv))
                        # decryption steps
                        try:
                            iv = encrypted_package.iv
                            ct = encrypted_package.encryptedMessage
                            cipher = AES.new(ckey, AES.MODE_CBC, iv)
                            PMAC = PlaintextAndMAC()
                            PMAC.ParseFromString(unpad(cipher.decrypt(ct), AES.block_size))
                            pt = unpad(PMAC.paddedPlaintext, AES.block_size)
                            mac = PMAC.mac
                            # mac authentication
                            secret = akey
                            h = HMAC.new(secret, pt, digestmod=SHA256)
                            try:
                                h.verify(mac)
                                # print("INFO: The message is authentic, showing results...")
                                im = IM()
                                im.ParseFromString(pt)
                                msg = im.message
                                nn = im.nickname
                                print(f'{nn}:{msg}')
                            except ValueError:
                                print("INFO: Received message that could not be authenticated!")

                        except Exception as e:
                            print('Confidential Key Error: Cannot decrypt message!')
                    except Exception as e:
                        print('Cannot decode EncryptedPackage: %s' % e)

    # handles keyboard input for closing the server socket
    except KeyboardInterrupt:
        s.close()
        print("[INFO]Connection closed by interrupt")


def main():
    server, port, nickname, ckey, akey = parse()
    establish(server, port, nickname, ckey, akey)


if __name__ == '__main__':
    main()

