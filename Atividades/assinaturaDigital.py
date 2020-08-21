from tkinter import * #Interface Gráfica
import tkinter.ttk as ttk #Interface Gráfica
from tkinter import filedialog #Interface Gráfica
from tkinter import messagebox #Interface Gráfica
from Crypto.Hash import SHA256 #Gerar Hash
from Crypto import Random #Números aleatórios para o par de chaves
from Crypto.PublicKey import RSA #Geração do par de chaves
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
import binascii
import io #leitura de arquivo txt
from os import path


def arquivo(msg):
    formats= [("Arquivo","*.txt")]
    arquivo = filedialog.askopenfilename(filetypes=formats,title='Selecione o arquivo para criptografia')
    try:
        linha = io.open(arquivo,"r", encoding="utf8")
    except:
        return
    texto=""
    for i in linha:
        texto+=i
    linha.close()
    messagebox.showinfo('Arquivo','Aquivo selecionado: '+str(path.basename(arquivo)))
    msg.append(texto)

def key(mensagem):#Gera a chave pública + chave privada + assinatura digital
    random_seed = Random.new().read #Criou-se uma semente randômica para gerar o par chave privada/pública.
    keyPair = RSA.generate(1024,random_seed)#criou-se o par de chave privada/pública.
    print(f"Public key:  (n={hex(keyPair.n)}, e={hex(keyPair.e)})\n")
    print(f"Private key: (n={hex(keyPair.n)}, d={hex(keyPair.d)})\n")
    pubKey = keyPair.publickey()#Geração da chave pública
    print(pubKey)
    criptografiaHash(keyPair,mensagem)
    
   
def criptografiaHash(keyPair,mensagem):#Gera o hash da assinatura digital
    mensagem = bytes(mensagem, 'utf-8')#transforma a mensagem(string utf-8 para bytes)
    hash_ = SHA256.new(mensagem)#cria o hash da mensagem
    signer = PKCS115_SigScheme(keyPair)#instancia o objeto para a assinatura
    signature = signer.sign(hash_)#faz assinatura digital em binascii
    print()
    print("Assinatura Digital:",binascii.hexlify(signature))#assinatura em hexadecimal
    return signature #retorna a assinatura digital em binascii

def descriptografiaHash(pubKey,mensagem,assinatura):
    assinatura = binascii.unhexlify(assinatura)#transforma de hexadecimal para binascii
    print(assinatura)
    mensagem = bytes(mensagem, 'utf-8')#transforma a mensagem(string utf-8 para bytes)
    hash_ = SHA256.new(mensagem)
    verifier = PKCS115_SigScheme(pubKey)
    try:
        verifier.verify(hash_, assinatura)
        print("Assinatura Digital é válida.")
    except:
        print("Assinatura Digital é inválida.")

def criptografia():#TELA 1 
    limpaTela()
    msg=[]
    texto = Label(window, text='Criptografia de texto',font='arial 12 normal')
    texto.pack()
    botaoArquivo = Button(window, text="Selecionar Arquivo",cursor="hand2",relief=RIDGE,command = lambda : arquivo(msg))
    botaoArquivo.pack()
    botaoEnviar = ttk.Button(window, text="Enviar",command = lambda : key(msg[0]))
    botaoEnviar.pack()
    
def descriptografia():#TELA 2
    limpaTela()
    msg=[]
    texto = Label(window, text='Descriptografia de texto',font='arial 12 normal')
    texto.pack()
    frame = Frame(window)
    frame.pack()
    hashmsg = Label(frame, text='Hash da Mensagem:',font='arial 12 bold')
    hashmsg.grid(row = 0,column = 0)
    entrada3 = Entry(frame, font="arial 15 bold")
    entrada3.grid(row=0,column=1)
    pubKey = Label(frame, text='pubKey:',font='arial 12 bold')
    pubKey.grid(row = 1,column = 0)
    entrada = Entry(frame, font="arial 15 bold")
    entrada.grid(row=1,column=1)
    assinatura = Label(frame, text='Assinatura:',font='arial 12 bold')
    assinatura.grid(row = 2,column = 0)
    entrada2 = Entry(frame, font="arial 15 bold")
    entrada2.grid(row=2,column=1)
    botaoEnviar = ttk.Button(window, text="Enviar",command = lambda: descriptografiaHash(entrada.get(),msg[0],entrada2.get()))
    botaoEnviar.pack()

def all_children (window) :
    _list = window.winfo_children()
    for item in _list :
        if item.winfo_children() :
            _list.extend(item.winfo_children())
    return _list

def limpaTela():
    widget_list = all_children(window)
    for item in widget_list:
        item.pack_forget()
    
#############MAIN#####################
window = Tk()
menu = Menu(window)
window.config(menu=menu)
menu.add_cascade(label='Criptografia',command=criptografia)
menu.add_cascade(label='Descriptografia',command=descriptografia)
window.title('Assinatura Digital - Filipe / João Lucas / Rodrigo')
window.geometry('800x600+200+100')#altura x largura + eixo_x + eixo_y
window.mainloop()
################################
