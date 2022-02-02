import base64
from Crypto import Random
from Crypto.Cipher import AES


class AES128Crypto:

    def __init__(self, encrypt_key):
        self.BS = AES.block_size
        ##암호화 키중 16자리만 잘라서 쓴다.
        self.encrypt_key = encrypt_key[:16].encode(encoding='utf-8', errors='strict')
        self.pad = lambda s: bytes(s + (self.BS - len(s) % self.BS) * chr(self.BS - len(s) % self.BS), 'utf-8')
        self.unpad = lambda s: s[0:-ord(s[-1:])]

    def encrypt(self, raw):
        raw = self.pad(raw)
        # initialization vector 를 매번 랜덤으로 생성 한다.
        iv = Random.new().read(self.BS)
        cipher = AES.new(self.encrypt_key, AES.MODE_CBC, iv)

        # 암호화시 앞에 iv와 암화화 값을 붙여 인코딩 한다.
        # 디코딩시 앞에서 BS(block_size) 만금 잘라서 iv를 구하고, 이를통해 복호화 한다.
        return base64.b64encode(iv + cipher.encrypt(raw)).decode("utf-8")

    def decrypt(self, enc):
        enc = base64.b64decode(enc)

        # encrypt 에서 작업한 것처럼 첫 16바이트(block_size=BS) 를 잘라 iv를 만들고, 그 뒤를 복호화 하고자 하는 메세지로 잘라 만든다.
        iv = enc[:self.BS]
        encrypted_msg = enc[self.BS:]
        cipher = AES.new(self.encrypt_key, AES.MODE_CBC, iv)
        return self.unpad(cipher.decrypt(encrypted_msg)).decode('utf-8')


key = [0x10, 0x01, 0x15, 0x1B, 0xA1, 0x11, 0x57, 0x72, 0x6C, 0x21, 0x56, 0x57, 0x62, 0x16, 0x05, 0x3D,
       0xFF, 0xFE, 0x11, 0x1B, 0x21, 0x31, 0x57, 0x72, 0x6B, 0x21, 0xA6, 0xA7, 0x6E, 0xE6, 0xE5, 0x3F]
data = "1111"

encrypted_data = AES128Crypto(str(key)).encrypt(data)
print(encrypted_data)

decrypted_data = AES128Crypto(str(key)).decrypt(encrypted_data)
print(decrypted_data)