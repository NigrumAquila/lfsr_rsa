from sympy import randprime
from math import gcd
from os import urandom
from progress.bar import Bar
from tkinter import filedialog, Tk

# Для работы с проводником
root = Tk()
root.attributes("-topmost", True)
root.withdraw()


# RSA начало

# Нахождение мультипликативной инверсии
def modInverse(n, q):
    return egcd(n, q)[0] % q

def egcd(a, b):
    s0, s1, t0, t1 = 1, 0, 0, 1
    while b > 0:
        q, r = divmod(a, b)
        a, b = b, r
        s0, s1, t0, t1 = s1, s0 - q * s1, t1, t0 - q * t1
    return s0, t0, a

# Проверка 2 чисел на взаимную простоту
def primesrel(a, b):
    if gcd(a,b) == 1:
        return True
    else:
        return False

def RSAgenerateKeys():
    p = randprime(2**128, 2**156)
    q = randprime(2**128, 2**156)
    n = p*q
    fi = (p-1)*(q-1)
    e = randprime(1, fi)
    while(primesrel(e, fi) != True):
        e = randprime(1, fi)
    d = modInverse(e, fi)
    pubKey = {'e': e, 'n': n}
    privKey = {'d': d, 'n': n}
    print('1 простое число:', p, '2 простое число:', q, '\nПроизведение простых чисел:', n, 'Функция Эйлера:', fi, '\nОткрытая экспонента:', e, 'Закрытая экспонента:', d, '\nОткрытый ключ:', pubKey, 'Закрытый ключ:', privKey)
    return pubKey, privKey


def RSAencrypt(pubKey):
    srcFilePath = filedialog.askopenfilename()
    dstFilePath = srcFilePath + '.encrypted'
    srcFile = open(srcFilePath, 'rb')
    dstFile = open(dstFilePath, 'wb')
    
    e = int(pubKey['e'])
    n = int(pubKey['n'])
    
    with Bar('Шифрование', max=len(srcFile.read())) as bar:
        srcFile.seek(0)
        while True:
            b = srcFile.read(1)
            if not b: 
                break
            dstFile.write(pow(int.from_bytes(b, byteorder='big'), e, n).to_bytes(64, byteorder='big'))
            bar.next()


def RSAdecrypt(privKey):
    srcFilePath = filedialog.askopenfilename()
    dstFilePath = srcFilePath[0:-9] + 'decrypted'
    srcFile = open(srcFilePath, 'rb')
    dstFile = open(dstFilePath, 'wb')

    d = int(privKey['d'])
    n = int(privKey['n'])
    
    with Bar('Расшифрование', max=len(srcFile.read())/64) as bar:
        srcFile.seek(0)
        while True:
            byts = srcFile.read(64)
            if not byts: 
                break
            dstFile.write(pow(int.from_bytes(byts, byteorder='big'), d, n).to_bytes(1, byteorder='big'))
            bar.next()

# RSA конец

# LRR начало


nbytes = 16
taps = (8,7,6,1)

def LRRgenerateKey(): 
    return bin(int.from_bytes(urandom(nbytes), byteorder='big'))[2:]
    

def LRRstep(sr):
    xor = 1; nbits = sr.bit_length()
    for tap in taps:
        if (sr & (1<<(tap-1))) != 0:
            xor ^= 1
    sr = (xor << nbits-1) + (sr >> 1)
    return sr


def LRRencrypt(seed):
    srcFilePath = filedialog.askopenfilename()
    dstFilePath = srcFilePath + '.encrypted'
    srcFile = open(srcFilePath, 'rb')
    dstFile = open(dstFilePath, 'wb')
    
    sr = int(seed)

    with Bar('Шифрование', max=len(srcFile.read())) as bar:
        srcFile.seek(0)
        while True:
            b = srcFile.read(1)
            if not b: 
                break
            g = LRRstep(sr)
            sr = g
            dstFile.write((g ^ int.from_bytes(b, byteorder='big')).to_bytes(nbytes*4, byteorder='big'))
            bar.next()


def LRRdecrypt(seed):
    srcFilePath = filedialog.askopenfilename()
    dstFilePath = srcFilePath[0:-9] + 'decrypted'
    srcFile = open(srcFilePath, 'rb')
    dstFile = open(dstFilePath, 'wb')

    sr = int(seed)

    with Bar('Расшифрование', max=len(srcFile.read())/(nbytes*4)) as bar:
        srcFile.seek(0)
        while True:
            byts = srcFile.read(nbytes*4)
            if not byts:
                break
            g = LRRstep(sr)
            sr = g
            dstFile.write((g ^ int.from_bytes(byts, byteorder='big')).to_bytes(1, byteorder='big'))
            bar.next()



if __name__ == "__main__":    
    while True:
        case = input('Выберите алгоритм: 1 - RSA; 2 - LRR; e - Выйти: ')
        if case == '1':

            while True:
                case = input('Выберите действие: 1 - Сгенерировать ключи; 2 - Выбрать открытый ключ; 3 - Выбрать закрытый ключ; 4 - Зашифровать файл; 5 - Расшифровать файл; e - Выйти: ')

                if case == '1':
                    keys = RSAgenerateKeys()
                    filename = input('Введите имя файла для ключа: ')
                    pubkFile = open(filename +'.pubk', 'w')
                    pkFile = open(filename +'.pk', 'w')
                    for value in keys[0].values(): 
                        pubkFile.writelines(str(value) + '\n')
                    for value in keys[1].values(): 
                        pkFile.writelines(str(value) + '\n')
                    pubkFile.close()
                    pkFile.close()

                    print('Ключи сгенерированы.')

                elif case == '2':
                    key = {}
                    fullKey = open(filedialog.askopenfilename(), 'r').readlines()
                    pubKey = {'e': fullKey[0].splitlines()[0], 'n': fullKey[1].splitlines()[0]}
                    
                    print('Открытый ключ выбран успешно.')

                elif case == '3':
                    key = {}
                    fullKey = open(filedialog.askopenfilename(), 'r').readlines()
                    privKey = {'d': fullKey[0].splitlines()[0], 'n': fullKey[1].splitlines()[0]}
                    
                    print('Закрытый ключ выбран успешно.')

                elif case == '4':
                    if not 'pubKey' in locals(): print('Ключ не выбран.'); continue

                    RSAencrypt(pubKey)
                    print('Файл зашифрован.')

                elif case == '5':
                    if not 'privKey' in locals(): print('Ключ не выбран.'); continue

                    RSAdecrypt(privKey)
                    print('Файл расшифрован.')

                elif case == 'e':
                    exit('Работа прекращена.')

                else:
                    print('Некорректный ввод.')

        elif case == '2':

            while True:
                case = input('Выберите действие: 1 - Сгенерировать ключ; 2 - Выбрать ключ; 3 - Зашифровать файл; 4 - Расшифровать файл; e - Выйти: ')

                if case == '1':
                    key = LRRgenerateKey()
                    filename = input('Введите имя файла для ключа: ')
                    open(filename + '.pk', 'w').write(key)
                    
                    print('Ключ сгенерирован.')

                elif case == '2':
                    key = open(filedialog.askopenfilename(), 'r').read()
                    print('Ключ выбран успешно.')
                
                elif case == '3':
                    if not 'key' in locals(): print('Ключ не выбран.'); continue

                    LRRencrypt(key)
                    print('Файл зашифрован.')

                elif case == '4':
                    if not 'key' in locals(): print('Ключ не выбран.'); continue

                    LRRdecrypt(key)
                    print('Файл расшифрован.')

                elif case == 'e':
                    exit('Работа прекращена.')

                else:
                    print('Некорректный ввод.')

        elif case == 'e':
            exit('Работа прекращена.')

        else:
            print('Некорректный ввод.')