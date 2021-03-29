import random
from math import pow
import codecs


def gcd(a, b):  # 欧几里得辗转相除法
    if a < b:
        return gcd(b, a)
    elif a % b == 0:
        return b
    else:
        return gcd(b, a % b)


def fastmod(b, e, m):  # 快速幂算法
    result = 1
    while e != 0:
        if (e & 1) == 1:
            result = (result * b) % m
        e >>= 1
        b = (b * b) % m
    return result


def ext_euclid(a, b):  # 扩展欧几里得辗转相除
    old_s, s = 1, 0
    old_t, t = 0, 1
    old_r, r = a, b
    if b == 0:
        return 1, 0, a
    else:
        while (r != 0):
            q = old_r // r
            old_r, r = r, old_r - q * r
            old_s, s = s, old_s - q * s
            old_t, t = t, old_t - q * t
    return old_s


def miller_rabin(num):  # miller_rabin 素性检测
    if num == 2:
        return True
    elif num % 2 == 0:
        return False
    m = num - 1
    k = 0
    while m % 2 == 0:
        k = k + 1
        m = m // 2
    for i in range(0, 20):
        a = random.randint(2, num - 1)
        x = fastmod(a, m, num)
        for j in range(0, k):
            y = fastmod(x, 2, num)
            if y == 1 and x != 1 and x != num - 1:
                return False
            x = y
        if y != 1:
            return False
    return True

def gen_key():  # 生成私钥函数
    while 1:
        q = random.randint(pow(10, 20), pow(10, 50))
        while miller_rabin(q) == False:
            q = random.randint(pow(10, 20), pow(10, 50))
            p = 2 * q + 1
        if miller_rabin(p) == True:
            break
        else:
            continue
    a = random.randint(pow(10, 20), p - 1)
    while fastmod(a, 2, p) == 1 or fastmod(a, q, p) == 1:
        a = random.randint(pow(10, 20), p - 1)
    return a, p


def strencrypt(msg, g, q, h):  # 字符串 ELGamal 加密函数
    en_msg = []
    y = random.randint(2, q - 2)
    c1 = fastmod(g, y, q)
    s = fastmod(h, y, q)
    for i in range(0, len(msg)):
        en_msg.append(msg[i])
    for i in range(0, len(en_msg)):
        en_msg[i] = (s * ord(msg[i])) % q
    return c1, en_msg


def strdecrypt(en_msg, g, q, x, c1):  # 字符串 ELGamal 解密函数
    dr_msg = []
    s = fastmod(c1, x, q)
    s_rev = ext_euclid(s, q)
    for i in range(0, len(en_msg)):
        dr_msg.append(chr((en_msg[i] * s_rev) % q))
    return dr_msg


def strELGamal(msg):  # 字符串 ELGamal 运行函数
    g, q = gen_key()
    x = random.randint(2, q - 2)
    h = fastmod(g, x, q)
    print("g=", g)
    print("q=", q)
    print("x=", x)
    c1, en_msg = strencrypt(msg, g, q, h)
    print(en_msg)
    dr_msg = strdecrypt(en_msg, g, q, x, c1)
    decry_message = ''.join(dr_msg)
    print("decry_message:", decry_message)


def fileencrypt(readpath, writepath, g, q, h):  # 文件 ELGamal 加密函数
    msg = open(readpath, 'r', encoding='utf-8').read()
    en_msg = []
    y = random.randint(2, q - 2)
    c1 = fastmod(g, y, q)
    s = fastmod(h, y, q)
    for i in range(0, len(msg)):
        en_msg.append(msg[i])
    for i in range(0, len(en_msg)):
        en_msg[i] = (s * ord(msg[i]) % q)
    file = open(writepath, 'w')
    for i in range(0, len(en_msg)):
        file.write(str(en_msg[i]))
        file.write(' ')
    file.close()
    return c1


def filedecrypt(readpath, writepath, g, q, x, c1):  # 文件 ELGamal 解密函数
    en_msg = open(readpath, 'r', encoding='utf-8').read()
    en_msg = en_msg.split()
    for i in range(0, len(en_msg)):
        en_msg[i] = (int)(en_msg[i])
    print(en_msg)
    dr_msg = []
    s = fastmod(c1, x, q)
    s_rev = ext_euclid(s, q)
    for i in range(0, len(en_msg)):
        dr_msg.append(chr((en_msg[i] * s_rev) % q))
    file = open(writepath, 'w')
    for i in range(0, len(dr_msg)):
        file.write(dr_msg[i])
    file.close()


def fileELGamal(readpath, enpath, depath):  # 文件 ELGamal 运行函数
    g, q = gen_key()
    x = random.randint(2, q - 2)
    h = fastmod(g, x, q)
    print("g=", g)
    print("q=", q)
    print("x=", x)
    return g, q, x, h


def sigELGamal(signature):  # 数字签名函数
    g, q = gen_key()
    d = random.randint(2, q - 2)
    b = fastmod(g, d, q)
    publickey = [q, g, b]
    kpr = random.randint(2, q - 2)
    while gcd(kpr, q - 1) != 1:
        kpr = random.randint(2, q - 2)
    r = fastmod(g, kpr, q)
    k_rev = ext_euclid(kpr, q - 1)
    s = k_rev * (signature - d * r) % (q - 1)
    sig = [r, s]
    return publickey, sig


def verifysig(publickey, sig, signature):  # 检验数字签名函数
    if(fastmod(publickey[2], sig[0], publickey[0]) * fastmod(sig[0], sig[1], publickey[0]) %publickey[0] - fastmod(publickey[1], signature, publickey[0])) % publickey[0] == 0:
        return True
    else:
        return False
    if __name__ == '__main__':  # main 函数
        strELGamal('this is message:flag{ctf}')
        g, q, x, h = fileELGamal('data.txt', 'endata.txt', 'dedata.txt')
        c1 = fileencrypt('data.txt', 'endata.txt', g, q, h)
        filedecrypt('endata.txt', 'dedata.txt', g, q, x, c1)
        publickey, sig = sigELGamal(10000)
        print(verifysig(publickey, sig, 10000))
