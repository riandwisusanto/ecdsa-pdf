import time
import ecdsa
import PyPDF2 as pdf
from hashlib import blake2b

from reportlab.pdfgen.canvas import Canvas
from pdfrw import PdfReader
from pdfrw.toreportlab import makerl
from pdfrw.buildxobj import pagexobj
from datetime import datetime


# encrypt pdf
def encrypt(private_key, text):
    sk = ecdsa.SigningKey.from_string(bytes.fromhex(private_key), curve=ecdsa.NIST521p, hashfunc=blake2b)
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
    fileObj = open("signature.txt", "r")  # opens the file in read mode
    words = fileObj.read().splitlines()  # puts the file into an array
    fileObj.close()
    return words


# cek signpdf
def check(text):
    isSign = False

    for sig in readFile():
        if '_' in sig:
            split = sig.split('_')
            priv = split[0]
            sig = split[1]

            vk = ecdsa.SigningKey.from_string(bytes.fromhex(priv), curve=ecdsa.NIST521p, hashfunc=blake2b).verifying_key
            vk.precompute()

            try:
                isSign = vk.verify(bytes.fromhex(sig), text.encode('utf-8'), blake2b)
                break
            except ecdsa.BadSignatureError:
                isSign = False

    return isSign


# save sign pdf
def saveSign(input_text):
    input_file = "pdf/" + input_text + ".pdf"
    output_file = "pdf-sign/" + input_text + "_sign.pdf"

    # Get pages
    reader = PdfReader(input_file)
    pages = [pagexobj(p) for p in reader.pages]

    # Compose new pdf
    canvas = Canvas(output_file)

    now = datetime.now()
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")

    for page_num, page in enumerate(pages, start=1):
        # Add page
        canvas.setPageSize((page.BBox[2], page.BBox[3]))
        canvas.doForm(makerl(canvas, page))

        # Draw footer
        footer_text = "Telah ditanda tangani " + dt_string
        x = 160
        canvas.saveState()
        canvas.setFont('Times-Roman', 8)
        canvas.drawString(page.BBox[2] - x, 20, footer_text)
        canvas.restoreState()

        canvas.showPage()

    canvas.save()


if __name__ == '__main__':
    print("--- ENKRIPSI DAN DEKRIPSI DOKUMEN PDF ---")
    print("1. Sign PDF")
    print("2. Verify PDF")

    inp = input("Masukkan Pilihan       : ")
    if inp == '1':
        input_pdf = input("Masukkan nama file PDF : ")
        input_stream = pdf.PdfFileReader(open("pdf/" + input_pdf + ".pdf", "rb"))
        text_stream = input_stream.getPage(0).extractText()

        sk = ecdsa.SigningKey.generate(curve=ecdsa.NIST521p, hashfunc=blake2b)
        private_key = sk.to_string().hex()
        public_key = sk.verifying_key.to_string().hex()
        sign_time = time.time()
        signature = encrypt(private_key, text_stream)

        if check(text_stream):
            print("PDF sudah di tanda tangani")
        else:
            print("Private Key            :", private_key)
            print("Public  Key            :", public_key)
            print("Signature              :", signature)

            rl = readFile()
            rl.append(signature + " -_- " + public_key)
            with open('signature.txt', 'w') as f:
                for line in rl:
                    f.write(line)
                    f.write("\n")

            saveSign(input_pdf)

            print("Waktu proses sign      : %s second" % (time.time() - sign_time))
    else:
        input_pdf = input("Masukkan nama file PDF : ")
        input_stream = pdf.PdfFileReader(open("pdf/" + input_pdf + ".pdf", "rb"))
        text_stream = input_stream.getPage(0).extractText()

        if check(text_stream):
            input_sig = input("Masukkan Signature     : ")
            signature = input_sig
            input_pub = input("Masukkan Public Key    : ")

            verify_time = time.time()
            print("Signature              :", decrypt(input_pub, signature, text_stream))
            print("Waktu proses verify    : %s second" % (time.time() - verify_time))
        else:
            print("PDF belum di tanda tangani")

