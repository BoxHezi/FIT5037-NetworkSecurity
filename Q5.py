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
    while len(msg) % 16 != 0:
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
        plaintext = plaintext.strip()
    except KeyError:
        print("Incorrect Decryption due to Key Error")
    except ValueError:
        print("Incorrect Decryption due to Value Error")

    # TODO ends   #
    return plaintext


def RSA_enc(message, key_pub):
    # TODO starts #

    message_hash = compute_hash(message)
    temp_rsa = RSA.importKey(key_pub)

    encrypted = temp_rsa.encrypt(message_hash.encode(), 0)[0]

    enc_text = encrypted
    return enc_text
    # TODO ends   #


def RSA_dec(ciphertext, key_prv):
    # TODO starts #
    temp_rsa = RSA.importKey(key_prv)
    decrypted = temp_rsa.decrypt(ciphertext)

    plaintext = decrypted.decode("utf-8")
    return plaintext
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
    print("The signature after RSA signature\n {}".format(rsa_signed))
    print("The verification of signed RSA signature is:\n {}".format(rsa_verified))
    # TODO ends #
    return 0


if __name__ == '__main__':
    main()
