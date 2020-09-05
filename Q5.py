# You can import all modules you need from Crypto here
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256


def compute_hash(msg):
    # TODO starts #
    hash_val = SHA256.new(msg).hexdigest()
    # TODO ends  #
    return hash_val


def get_parameters():
    key_length = 2048
    # TODO starts #
    iv = Random.new().read(AES.block_size)
    # Generate RSA key pair
    RSA_key = RSA.generate(key_length)
    RSA_pub = RSA_key.publickey().exportKey()
    RSA_prv = RSA_key.exportKey()
    AES_key = b'3120740500000000'  # Please use your student ID plus zero padding to make a 16 byte key
    # TODO ends #
    return iv, AES_key, RSA_pub, RSA_prv  # return initialization vector and RSA keys


def AES_enc(msg, iv, key, mode='CFB'):
    # TODO starts #
    while len(msg) % 16 != 0:  # whitespace passing if msg length is not multiple of 16
        msg = msg + b' '

    cipher = AES.new(key)
    cipher.IV = iv

    ciphertext = cipher.encrypt(msg)
    # TODO ends   #
    return ciphertext


def AES_dec(ciphertext, iv, key):
    # TODO starts #
    plaintext = ''
    try:
        cipher = AES.new(key)
        cipher.IV = iv
        plaintext = cipher.decrypt(ciphertext)
        plaintext = plaintext.strip()  # remove trailing space
    except KeyError:
        print("Incorrect Decryption due to Key Error")
    except ValueError:
        print("Incorrect Decryption due to Value Error")

    # TODO ends   #
    return plaintext


def RSA_enc(message, key_pub):
    # TODO starts #
    FLAG = "|"  # self-config flag to separate message and signature

    message_hash = compute_hash(message)

    cipher_rsa = RSA.importKey(key_pub)
    encrypted = cipher_rsa.encrypt(message_hash.encode("utf-8"), 0)[0]  # return a tuple, first item is the ciphertext

    enc_text = message.decode("utf-8") + FLAG + encrypted.hex()
    return enc_text
    # TODO ends   #


def RSA_dec(ciphertext, key_prv):
    # TODO starts #
    FLAG = "|"  # self-config flag to separate message and signature

    msg = ciphertext[:ciphertext.index(FLAG)]
    encrypted_hash = ciphertext[ciphertext.index(FLAG) + 1:]

    encrypted_hash_bytes = bytes.fromhex(encrypted_hash)  # convert hex string to bytes

    cipher_rsa = RSA.importKey(key_prv)
    decrypted_hash = cipher_rsa.decrypt(encrypted_hash_bytes).decode("utf-8")  # decrypt and decode using UTF-8

    message_hash = compute_hash(msg.encode())

    return message_hash == decrypted_hash  # signature verified if and only if message_hash is exactly the same as decrypted_hash

    # TODO ends   #


def main():
    message = b"I love Monash University"
    # Step 1  Generate Initialization Vector and RSA key pair
    iv, AES_key, RSA_pub, RSA_prv = get_parameters()

    # Step 2  Compute Hash value #
    hash_val = compute_hash(message)
    print("----------------------------------------------------------")
    print("The hash value for given input is:\n {}".format(hash_val))

    # Step 4  AES  #
    ciphertext = AES_enc(message, iv, AES_key)
    plaintext = AES_dec(ciphertext, iv, AES_key)
    print("----------------------------------------------------------")
    print("The ciphertext after AES algorithm\n {}".format(ciphertext))
    print("The text recovered is:\n {}".format(plaintext))

    # Step 5  RSA Signature  #
    # TODO starts #
    rsa_signed = RSA_enc(message, RSA_pub)
    rsa_verified = RSA_dec(rsa_signed, RSA_prv)
    print("----------------------------------------------------------")
    print("The message after RSA signature\n {}".format(rsa_signed))
    print("The signature verification:\n {}".format(rsa_verified))  # True if signature is verified successfully
    # TODO ends #
    return 0


if __name__ == "__main__":
    main()