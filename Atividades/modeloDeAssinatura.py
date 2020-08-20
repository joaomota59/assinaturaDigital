from Crypto.Hash import SHA256 # biblioteca para usar a função de HASH
from Crypto.PublicKey import RSA # biblioteca para gerar as chaves
from Crypto import Random

#####
# GERANDO ASSINATURA
#####

# criando uma semente para gerar o par chave privada/pública
random_seed = Random.new().read

# criando par de chave privada/pública
keyPair = RSA.generate(1024, random_seed)
pubKey = keyPair.publickey()

# textos usados para verificar integridade da assinatura
True_text = 'Hello Bob'
Fake_text = 'Bye Bob'

# gerando a assinatura digital usando HASH256 aplicado ao conteúdo do texto
hashA = SHA256.new(True_text.encode('utf-8')).digest()
digitalSign = keyPair.sign(hashA, '')

print("Hash A : " + repr(hashA) + "\n")
print("Digital signature : " + repr(digitalSign) + "\n")

#####
# VERIFICANDO ASSINATURA
#####

# o receptor recebe (para fim de testes) dois texto, e para analisar qual é
# o autentico, deve-se utilizar a assinatura digital recebida. Primeiramente ele
# gera o HASH SHA256 para cada um dos trecho de textos (True_text e Fake_text)
hashB = SHA256.new(True_text.encode('utf-8')).digest()
hashC = SHA256.new(Fake_text.encode('utf-8')).digest()

# Posteriormente ele utiliza a assinatura digital recebida para validar
# a autenticidade dos textos
print("HashB : " + repr(hashB) + "\n")
print("HashC : " + repr(hashC) + "\n")

if(pubKey.verify(hashB, digitalSign)):
	print("O texto autentico é " + True_text)
elif(pubKey.verify(hashC, digitalSign)):
	print("O texto autentico é " + Fake_text)
else:
	print("Nenhum dos textos é autentico")

