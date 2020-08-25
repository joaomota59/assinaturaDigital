from Crypto.Hash import SHA256 #Gerar Hash
from Crypto import Random #Números aleatórios para o par de chaves
from Crypto.PublicKey import RSA #Geração do par de chaves
from base64 import b64decode
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
import binascii
import io #leitura de arquivo txt
from os import path
import os

message = ""

'''
/**
 * Método responsável por gerar chaves pública e privada.
 * Gera dois arquivos binários contendo respectivamente a chave privada
 * e pública.

 * Retorna caminho até os arquivos gerados.
 */
'''
def key():
	try:
		key = RSA.generate(2048)
		private_key = key.export_key()
		file_out = open("private.pem", "wb")
		file_out.write(private_key)
		file_out.close()

		public_key = key.publickey().export_key()
		file_out = open("public.pem", "wb")
		file_out.write(public_key)
		file_out.close()

		return os.path.dirname(os.path.abspath(__file__))+'/private.pem', os.path.dirname(os.path.abspath(__file__))+'/public.pem'
	except Exception as e:
		print('Falha na execução da geração das chaves : ' + str(e))

'''
/**
 * Função responsável por assinar mensagem.
 * Recebe uma mensagem clara e o caminho para a chave privada.
 * Retorna a assinatura da mensagem.
 */
'''
def digitalSignature(message, privateKey):
	encoded_key = open(privateKey, "rb").read()
	try:
		key = RSA.import_key(encoded_key)

		# print(key.publickey().export_key())
		mensagem = bytes(message, 'utf-8')# transforma a mensagem(string utf-8 para bytes)
		hash_ = SHA256.new(mensagem)# cria o hash da mensagem
		signer = PKCS115_SigScheme(key)# instancia o objeto para a assinatura
		signature = signer.sign(hash_)# faz assinatura digital em binascii

		file_out = open("signature.pem", "wb")
		file_out.write(binascii.hexlify(signature))
		file_out.close()

		return os.path.dirname(os.path.abspath(__file__))+'/signature.pem'
	except Exception as e:
		print('Falha na execução da assinatura : ' + str(e))

'''
/**
 * Função responsável por verificar assinatura digital.
 * Recebe como parametros a mensagem clara, o caminho para a chave pública e a assinatura.
 * Retorna a verificação (é ou não é válida).
 *
 */
'''
def verifySignature(message, publicKey, signature):
	encoded_key = open(publicKey, "rb").read()
	file_signature = open(signature, "rb").read()
	try:
		key = RSA.import_key(encoded_key)
		assinatura = binascii.unhexlify(file_signature.decode('utf-8'))# transforma de hexadecimal para binascii
		#print(assinatura)
		mensagem = bytes(message, 'utf-8')# transforma a mensagem(string utf-8 para bytes)
		hash_ = SHA256.new(mensagem)
		verifier = PKCS115_SigScheme(key)
		try:
			verifier.verify(hash_, assinatura)
			print("Assinatura Digital é válida.")
		except:
			print("Assinatura Digital é inválida.")
	except Exception as e:
		print('Falha na execução da verificação da assinatura : ' + str(e))



while 1 == 1:

	# menu
	print("\nAtividade 1 - sistema de assinatura digital")
	print("\nUtilize os números no menu para acessar a função desejada")
	print("\n")
	print("1 - Gerar chaves (privada e pública)\n")
	print("2 - Assinar mensagem\n")
	print("3 - Verificar assinatura\n")
	print("0 - Sair")
	
	opt = int(input("Qual opção deseja executar? "))

	if opt == 1:
		pathPrivate, pathPublic = key()
		print("------------------------------------------------------------")
		print('* caminho da chave privada: \n\n' + pathPrivate + "\n")
		print('* caminho da chave pública: \n\n' + pathPublic + "\n")
		print("------------------------------------------------------------")
	elif opt == 2:
		message = input("Digite a mensagem que deseja assinar: ")
		pathPrivate = input("Digite o caminho do arquivo da chave privada: ")
		print("\n------------------------------------------------------------\n")
		print('* caminho da assinatura digital: \n\n' + digitalSignature(message, pathPrivate) + "\n")
		print("------------------------------------------------------------\n")
	elif opt == 3:
		msg_ = input("Digite a mensagem original utilizada na assinatura: ")
		pathPublic = input("Digite o caminho do arquivo da chave pública: ")
		pathSignature = input("Digite o caminho do arquivo da assinatura: ")
		verifySignature(msg_, pathPublic, pathSignature)
	elif opt == 0:
		print("Tchau\n")
		break
	else:
		print("Opção não encontrada\n")