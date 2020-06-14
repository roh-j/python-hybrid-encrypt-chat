from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import socket
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
import base64
from Crypto.Cipher import AES
from Crypto import Random


# Author: 노재희
# 하이브리드 암호화/복호화 모듈
# 암호화/복호화 과정에서 파일 저장 없이 처리
# Date  : 2018. 12. 19. -


ENC_SESSION_KEY_SIZE = 256


def Generate_Key(priKey_filename, pubKey_filename, keySize=2048):
    privatekey = RSA.generate(keySize)

    f = open(priKey_filename, 'wb')
    f.write(bytes(privatekey.exportKey('PEM')))
    f.close()

    publickey = privatekey.publickey()

    f = open(pubKey_filename, 'wb')
    f.write(bytes(publickey.exportKey('PEM')))
    f.close()

    return


def Send_Key(host_name, port_Num, send_filename):
    port = port_Num
    host = host_name

    res = []

    server_socket = socket.socket()
    server_socket.bind((host, port))
    server_socket.listen(15)

    res.append('listening...')

    while True:
        client_socket, addr = server_socket.accept()

        res.append('Got connection from ' + str(addr))
        data = client_socket.recv(1024)
        res.append('Server received ' + str(repr(data)))

        filename = send_filename
        f = open(filename, 'rb')
        l = f.read(1024)

        while (l):
            client_socket.send(l)
            l = f.read(1024)

        f.close()
        res.append('Done sending!')
        client_socket.send(b'')

        break

    res.append('File (Sent): '+ send_filename)
    client_socket.close()
    server_socket.close()

    return res


def Receive_Key(host_name, port_Num, receive_filename):
    port = port_Num
    host = host_name

    res = []

    client_socket = socket.socket()
    client_socket.connect((host, port))
    client_socket.send(b'Ready!')

    f = open(receive_filename, 'wb')

    while True:
        data = client_socket.recv(1024)
        if not data:
            break
        f.write(data)

        res.append('File (Receive): ' +receive_filename)
    f.close()
    client_socket.close()

    return res


def PGP_Encrypt(plaintext, sender_prikey_filename, receiver_pubkey_filename):
    # AES Init
    sessionkey = Random.new().read(32)
    iv = Random.new().read(16)

    res_log = []

    res_log.append('Session Key: ' + str(base64.b64encode(sessionkey)))
    res_log.append('IV: ' + str(base64.b64encode(iv)))

    sigVal = Generate_Signature(plaintext, sender_prikey_filename)
    res_log += sigVal['log']

    cipherMessage = AES_Encrypt(sigVal['signature'], sessionkey, iv)

    publickey = RSA.importKey(open(receiver_pubkey_filename, 'rb').read())
    cipherRSA = PKCS1_OAEP.new(publickey)
    enc_sessionkey = cipherRSA.encrypt(sessionkey)

    return {'log' : res_log, 'message' : enc_sessionkey + iv + cipherMessage}


def PGP_Decrypt(ciperMessage, receiver_prikey_filename, sender_pubkey_filename):

    privatekey = RSA.importKey(open(receiver_prikey_filename, 'rb').read())
    cipherRSA = PKCS1_OAEP.new(privatekey)

    res_log = []
    sessionkey = cipherRSA.decrypt(ciperMessage[:ENC_SESSION_KEY_SIZE])

    res_log.append('Decrypted Session Key: ' + str(base64.b64encode(sessionkey)))
    ciphertext = ciperMessage[ENC_SESSION_KEY_SIZE:]

    iv = ciphertext[:16]
    res_log.append('Extracted IV: ' + str(base64.b64encode(iv)))

    message = AES_Decrypt(ciphertext[16:], sessionkey, iv)
    res_log.append('Verify: ' + str(Verify_signature(message, sender_pubkey_filename)))

    return {'log' : res_log, 'message' : message[ENC_SESSION_KEY_SIZE:]}


def Generate_Signature(plaintext, sender_prikey_filename):
    privatekey = RSA.importKey(open(sender_prikey_filename, 'rb').read())

    res_log = []

    myhash = SHA.new(plaintext)
    signature = PKCS1_v1_5.new(privatekey)

    sigVal = signature.sign(myhash)
    res_log.append('Length of Signature: ' + str(len(sigVal)))
    res_log.append('Signature: ' + str(base64.b64encode(sigVal)))

    res = sigVal + plaintext

    return {'log' : res_log, 'signature' : res}


def Verify_signature(message, sender_pubkey_filename):
    publickey = RSA.importKey(open(sender_pubkey_filename, 'rb').read())
    cipherRSA = PKCS1_v1_5.new(publickey)

    myhash = SHA.new(message[ENC_SESSION_KEY_SIZE:])
    res = cipherRSA.verify(myhash, message[:ENC_SESSION_KEY_SIZE])

    return res


def AES_Encrypt(message, sessionkey, iv):
    obj = AES.new(sessionkey, AES.MODE_CFB, iv)
    ciphertext = obj.encrypt(message)

    return ciphertext


def AES_Decrypt(message, sessionkey, iv):
    obj = AES.new(sessionkey, AES.MODE_CFB, iv)
    plaintext = obj.decrypt(message)

    return plaintext