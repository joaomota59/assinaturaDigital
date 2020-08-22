from Crypto.Hash import SHA256 #Gerar Hash
from Crypto import Random #Números aleatórios para o par de chaves
from Crypto.PublicKey import RSA #Geração do par de chaves
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
import binascii
import io #leitura de arquivo txt
from os import path

def key(mensagem):#Gera a chave pública + chave privada + assinatura digital
    random_seed = Random.new().read #Criou-se uma semente randômica para gerar o par chave privada/pública.
    keyPair = RSA.generate(1024,random_seed)#criou-se o par de chave privada/pública.
    # print("\n")
    # print(f"Public key:  (n={hex(keyPair.n)}, e={hex(keyPair.e)})\n")
    # print(f"Private key: (n={hex(keyPair.n)}, d={hex(keyPair.d)})\n")
    pubKey = keyPair.publickey()#Geração da chave pública
    
    privateKey = "Private key: " + f"(n={hex(keyPair.n)}, d={hex(keyPair.d)})"
    #publicKey = "Public key: " + f"(n={hex(keyPair.n)}, e={hex(keyPair.e)})"
    publicKey = repr(pubKey.exportKey().decode("utf-8")).replace('-----BEGIN PUBLIC KEY-----','').replace('-----END PUBLIC KEY-----','')
    publickeyReal = keyPair.publickey()
    message = mensagem
    # print(pubKey)
    return privateKey, publicKey, publickeyReal, message, criptografiaHash(keyPair,mensagem)
    
def criptografiaHash(keyPair,mensagem):#Gera o hash da assinatura digital
    mensagem = bytes(mensagem, 'utf-8')#transforma a mensagem(string utf-8 para bytes)
    hash_ = SHA256.new(mensagem)#cria o hash da mensagem
    signer = PKCS115_SigScheme(keyPair)#instancia o objeto para a assinatura
    signature = signer.sign(hash_)#faz assinatura digital em binascii
    # print("\n")
    # print("Assinatura Digital:",binascii.hexlify(signature))#assinatura em hexadecimal
    return signature

def descriptografiaHash(pubKey,mensagem,assinatura):
    assinatura = binascii.unhexlify(assinatura)#transforma de hexadecimal para binascii
    #print(assinatura)
    mensagem = bytes(mensagem, 'utf-8')#transforma a mensagem(string utf-8 para bytes)
    hash_ = SHA256.new(mensagem)
    verifier = PKCS115_SigScheme(pubKey)
    try:
    	verifier.verify(hash_, assinatura)
    	print("Assinatura Digital é válida.")
    except:
    	print("Assinatura Digital é inválida.")

privateKey = ""
publicKey = ""
publicKeyReal = ""
assignatureGenerate = ""
message = ""

while 1 == 1:

	# menu
	print("\nAtividade 1 - sistema de assinatura digital")
	print("\nUtilize os números no menu para acessar a função desejada")
	print("\n")
	print("1 - Mostrar chaves (privada e pública)\n")
	print("2 - Criptografar mensagem\n")
	print("3 - Descriptografar (verificar) assinatura\n")
	print("0 - Sair")
	
	opt = int(input("Qual opção deseja executar? "))

	if opt == 1:
		if privateKey == "":
			print("\n - Ainda não foi gerado nenhuma chave privada, utilize a opção 2 para iniciar a criação de uma")
		else:
			print(" - " + privateKey)

		if publicKey == "":
			print(" - Ainda não foi gerado nenhuma chave pública, utilize a opção 2 para iniciar a criação de uma")
		else:
			print(" - Chave Pública: " + publicKey)

		if assignatureGenerate == "":
			print("Ainda não foi gerado uma assinatura da mensagem, utilize a opção 2 para iniciar a criação de uma")
		else:
			print(" - Assignature: " , binascii.hexlify(assignatureGenerate).decode('utf-8'))

		if message == "":
			print(" - Ainda não foi inserido uma mensagem para assinatura, utiliza a opção 2 para iniciar a criação de uma\n")
		else:
			print(" - Message: " + message)
	elif opt == 2:
		msg = input("Digite a mensagem que deseja usar para a assinar: ")
		privateKey, publicKey, publicKeyReal, message, assignatureGenerate = key(msg)
	elif opt == 3:
		if assignatureGenerate == "":
			print("Ainda não foi gerado uma assinatura da mensagem, utilize a opção 2 para iniciar a criação de uma")
		else:
			ass_ = binascii.hexlify(assignatureGenerate).decode('utf-8')
			descriptografiaHash(publicKeyReal, message, ass_)
	elif opt == 0:
		print("Tchau\n")
		break
	else:
		print("Opção não encontrada\n")
