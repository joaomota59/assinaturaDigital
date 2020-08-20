from tkinter import * #Interface Gráfica
import tkinter.ttk as ttk #Interface Gráfica
from tkinter import filedialog #Interface Gráfica
from Crypto.Hash import SHA256 #Gerar Hash
from Crypto import Random #Números aleatórios para o par de chaves
from Crypto.PublicKey import RSA #Geração do par de chaves
import io #leitura de arquivo txt


def arquivo():
    formats= [("Arquivo","*.txt")]
    arquivo = filedialog.askopenfilename(filetypes=formats,title='Selecione o arquivo para criptografia')
    linha = f= io.open(arquivo,"r", encoding="utf8")
    k=""
    for i in linha:
        k+=i
    print(k)
    linha.close()

def key(mensagem):
    random_seed = Random.new().read #Criou-se uma semente randômica para gerar o par chave privada/pública.
    keyPair = RSA.generate(1024, random_seed)#criou-se o par de chave privada/pública.
    pubKey = keyPair.publickey()#Geração da chave pública
    criptografiaHash(keyPair,mensagem)
    
   
def criptografiaHash(keyPair,mensagem):#Gera o hash da assinatura
    hash_ = SHA256.new()
    hash_.update(bytes(mensagem, encoding = 'utf-8'))#passa a mensagem para fazer o hash
    hashMensagem = hash_.digest() #transforma a mensagem em hash
    digitalSign = keyPair.sign(hashMensagem, '')#retorna o hash da assinatura digital(chave privada + mensagem)
    return signature

def criptografia():#TELA 1 
    limpaTela()
    texto = Label(window, text='Criptografia de texto',font='arial 12 normal')
    texto.pack()
    botaoArquivo = Button(window, text="Selecionar Arquivo",cursor="hand2",relief=RIDGE,command = arquivo)
    botaoArquivo.pack()
    botaoEnviar = ttk.Button(window, text="Enviar",command = arquivo)
    botaoEnviar.pack()
    
def descriptografia():#TELA 2
    limpaTela()
    texto = Label(window, text='Descriptografia de texto',font='arial 12 normal')
    texto.pack()
    botaoArquivo = Button(window, text="Selecionar Arquivo",cursor="hand2",relief=RIDGE,command = arquivo)
    botaoArquivo.pack()
    frame = Frame(window)
    frame.pack()
    ass = Label(frame, text='Assinatura:',font='arial 12 bold')
    ass.grid(row = 0,column = 0)
    entrada = Entry(frame, font="arial 15 bold")
    entrada.grid(row=0,column=1)
    botaoEnviar = ttk.Button(window, text="Enviar",command = arquivo)
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
    
##################################
window = Tk()
menu = Menu(window)
window.config(menu=menu)
menu.add_cascade(label='Criptografia',command=criptografia)
menu.add_cascade(label='Descriptografia',command=descriptografia)

window.title('Assinatura Digital - Filipe / João Lucas / Rodrigo')
window.geometry('800x600+200+100')#altura x largura + eixo_x + eixo_y
window.mainloop()
################################
