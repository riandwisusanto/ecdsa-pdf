import ecdsa
import PyPDF2 as pdf
from hashlib import blake2b

# encrypt pdf
def encrypt(private_key, text):
    sk     = ecdsa.SigningKey.from_string(bytes.fromhex(private_key), curve=ecdsa.NIST521p, hashfunc=blake2b)
    enkrip = sk.sign(text.encode('utf-8'))

    return enkrip.hex()

# decrypt pdf
def decrypt(public_key, signature, text):
    try:
        vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(public_key), curve=ecdsa.NIST521p, hashfunc=blake2b)
        return vk.verify(bytes.fromhex(signature), text.encode('utf-8'), blake2b)
    except:
        return False

# read private_key
def readFile():
    fileObj = open("signature.txt", "r") #opens the file in read mode
    words = fileObj.read().splitlines() #puts the file into an array
    fileObj.close()
    return words

# cek signpdf
def check(text):
    isSign = False
    
    for sig in readFile():
        if '_' in sig:
            split = sig.split('_')
            priv  = split[0]
            sig   = split[1]

            vk = ecdsa.SigningKey.from_string(bytes.fromhex(priv), curve=ecdsa.NIST521p, hashfunc=blake2b).verifying_key
            vk.precompute()

            try:
                isSign = vk.verify(bytes.fromhex(sig), text.encode('utf-8'), blake2b)
                break
            except ecdsa.BadSignatureError:
                isSign = False
    
    return isSign

if __name__ == '__main__':
    print("--- ENCRYPT DECRYPT PDF ---")
    print("1. Sign PDF")
    print("2. Verify PDF")

    inp = input("masukkan pilihan :  ")
    if inp == '1':
        input_pdf    = input("masukkan nama file PDF:  ")
        input_stream = pdf.PdfFileReader(open("pdf/"+ input_pdf + ".pdf", "rb"))
        text_stream  = input_stream.getPage(0).extractText()

        sk = ecdsa.SigningKey.generate(curve=ecdsa.NIST521p, hashfunc=blake2b)
        private_key = sk.to_string().hex()
        public_key  = sk.verifying_key.to_string().hex()
        signature   = encrypt(private_key, text_stream)

        if check(text_stream):
            print("PDF sudah di tanda tangani")
        else:
            print("private key : ", private_key)
            print("public  key : ", public_key)
            print("signature   : ", signature)

            rl = readFile()
            rl.append(private_key+"_"+signature)

            with open('signature.txt', 'w') as f:
                for line in rl:
                    f.write(line)
                    f.write("\n")
    else:
        input_pdf    = input("masukkan nama file PDF:  ")
        input_stream = pdf.PdfFileReader(open("pdf/"+ input_pdf + ".pdf", "rb"))
        text_stream  = input_stream.getPage(0).extractText()

        input_sig    = input("masukkan signature  :  ")
        signature    = input_sig
        input_pub    = input("masukkan public key :  ")

        print("signature   : ", decrypt(input_pub, signature, text_stream))

