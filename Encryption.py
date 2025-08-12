import secrets
import random, string
import hashlib
import time


# create a program that encrypts and decrypts a message using RSA
# 1. convert the message to ascii digits and back to
# 2. encrypts the converted ascii using rsa public key
# 3. decrypt the encrypted message and convert it back to the main message

# 1

# create a function that converts letters, numbers and symbols to their ascii numerics
def convert_to_ascii(message: str)-> list:
    """Convert Alphabets, digits or symbols to their ascii code
    Paramerer
        message: str
            plaintext
    Return: list
        Converted message from plaintext to ascii
    """
    converted = [ord(i) for i in message]
    return converted

# Create a function that reverts ascii numbers back ti plaintext
def revert_ascii(message: list)-> str:
    """Converts ASCII code to plaintext
    Parameter
        messagge: list
            ascii digits
    Return: str
        Converted ascii code to plaintext
    """
    # converted_message ="".join([chr(i) for i in message]) # takes ascii numerics and converts back to their character representation
    converted_message_2 = ""
    for i in message:
        if i <= 127:
            converted_message_2 += chr(i)
        else:
            converted_message_2 += chr(10)
    return converted_message_2

# 2
def encrypt(m: str, e: int, n: int)-> str:
    """Performs an RSA encryption
    Parameters
        m: str
            message in plaintext to be encrypted

        e, n: int
            public key to encrypt the messagge

    Return: str
        an encrypted version of the message

    """
    # rsa encryption formula = m^e mod n
    converted = convert_to_ascii((m + "\u000A")) # convert all the information in the message to ascii
    # perform RSA encryption conversion
    cipher_text = [str(pow(i, e, n)) for i in converted]

    return " ".join(cipher_text)

# 3
def decrypt(cipher_text: str, d: int, n: int)-> str:
    """Cnverts an RSA encryption back to plaintext
    Parameter
        cipher_text: str
            Encrypted text
        d, n: int
             Private keys
    Return: str
        Converted plaintext
    """
    #  to decipher cipher_text ^ d mod n
    # convert each message in the cipher_text back to the original ascii numerics
    decipher_text = [pow(int(i), d, n) for i in cipher_text.split()]
    # convert decipher_text ascii back to original message
    original_message = revert_ascii(decipher_text)
    return original_message


def extended_euclidean(a, b):
    if b == 0:
        return a, 1, 0  # Base case: gcd, x, y
    gcd, x1, y1 = extended_euclidean(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    return gcd, x, y

def find_d(e, phi_n):
    gcd, x, y = extended_euclidean(e, phi_n)
    if gcd != 1:
        raise ValueError(f"No modular inverse exists because gcd({e}, {phi_n}) ≠ 1")
    return x % phi_n  # Ensure the result is positive

def random_prime_number(n_bit):
    """Generates a random prime number of n_bit length"""
    # generate a number of 64 bits using the secrets module
    num = secrets.randbits(n_bit)
    # check if the number is even or ends with 5
    while num % 2 == 0 or str(num)[-1] == 5:
        num = secrets.randbits(64)
    # check if the number is prime
    from sympy import isprime
    while not isprime(num):
        num = secrets.randbits(64)
    return num

def hash_message(message: str, salt: str)-> str:
    """
    hash a message using sha256
    Parameters:
        message: str-> message to be hashed
        salt: str-> string to make the hash more difficult to guess
    Return:
        hashed_message: str-> hashed version of message
    """
    hashed_message = hashlib.sha256((salt + str(message)).encode()).hexdigest()

    return hashed_message
def generate_keys():
    """
    Create RSA encryption keys
    Return:
        Public Keys (e,n) and Private key (d)
    """
    bits = [i for i in range(32, 62)]
    n_bits = random.choice(bits)
    p = random_prime_number(n_bits)
    q = random_prime_number(n_bits)
    n = p * q
    phi_n = (p-1)*(q-1)
    e = 65537
    d = find_d(e, phi_n)
    public_key = (e, n)
    chars = string.ascii_letters + string.digits
    salt = "".join(random.choice(chars) for char in range(6))
    hashed_key = hash_message(d, salt)
    print(f"Public Key: {public_key}")
    print("Private key is {}\nStore in a safe place \nNote that private key cannot be retrieved".format(d))
    return f"{e}, {n}, {salt}, {hashed_key}"

def get_keys():
    """
    Gets public keys from public_keys.txt
    Return:
        e, n
    """
    file_name = "public_keys.txt"
    # Get content from Public Key file
    with open(file_name, 'r+', encoding='utf-8') as file:
        content = file.read().strip(" ").split(",")
        print("Validating\n...")
        time.sleep(1)
        # create public keys if none exists
        if content != [""]:
            print("Validation complete\n...")
            public_key = content[0], content[1].strip(" ")
            salt = content[2].strip(" ")
            hashed_key = content[3].strip(" ")
        else:
            print("No keys found")
            print("Do you want to generate keys. yes/no")
            option = input("Enter an option: ")
            if option.upper() == "YES":
                generated_keys = generate_keys()
                file.write(generated_keys)
                content = generated_keys.strip(" ").split(",")
                public_key = content[0], content[1].strip(" ")
                salt = content[2].strip(" ")
                hashed_key = content[3].strip(" ")
    return [public_key, salt, hashed_key]


def validate_private_key(key: int, salt: str, hashed_key) -> bool:
    rehashed_key = hashlib.sha256((salt + str(key)).encode()).hexdigest()
    if hashed_key == rehashed_key:
        return True
    else:
        return False


def main(d: int, n: int):
    print("Welcome to simple RSA encryption")
    while True:
        print("1. Encrypt a file\n2. Decrypt a file\n3. Generate RSA key\n4. Quit")
        choice = input("Enter your choice: ")
        # select_e = [3,5,17,65537]
        e = 65537

        if choice == "1":
            print("1. Encrypt from file path\n2. Encrypt via text input")
            option = input("Enter an option: ")
            if option == "1":
                file_path = input("Enter file path: ")
                with open(fr"{file_path}", "r", encoding="utf-8") as file:
                    encrypted_message = encrypt(file.read(), e, n)
                    print(encrypted_message)
                with open(fr"{file_path}", "w+", encoding="utf-8") as file:
                    encrypted_message_str = "".join(map(str, encrypted_message))
                    file.write(encrypted_message_str)
                return 0

            elif option == '2':
                word_to_encrypt = input("Enter text to encrypt: ")
                encrypted_message = encrypt(word_to_encrypt, e, n)
                return encrypted_message

        if choice == "2":
            print("1. Decrypt from file path\n2. Decrypt via text input")
            option = input("Enter an option: ")
            if option == "1":
                file_path = input("Enter file path: ")

                with open(fr"{file_path}", "r", encoding="utf-8") as file:
                    decoded_message = decrypt(file.read(), d, n)
                    print(decoded_message)
                # with open(fr"{file_path}", "w+", encoding="utf-8") as file:
                #     file.write(decoded_message)
            elif option == '2':
                encrypted_message = input('Enter encrypted message: ')
                decrypted_message = decrypt(encrypted_message, d, n)
                return decrypted_message

        elif choice == '3':
            generate_keys()

        elif choice == '4':
            exit()

if __name__ == "__main__":
    while True:
        print("Do You already have existing keys")
        key_option = input("Answer Yes or No: ")
        if key_option.upper() == "YES":
            public_key, private_key = input("Enter public key: "), input("Enter private key: ")
            if public_key.isdigit() and private_key.isdigit():
                print(main(int(private_key), int(public_key)))
            else:
                print("Public key and private keys should be digits\n")
                continue

        elif key_option.upper() == 'NO':
            print("Proceeding to generate keys to initiate program... ")
            option = input("Type YES to proceed and NO to exit: ")
            if option.upper() == "YES":
                e_n_salt_hash = generate_keys().strip(" ").split(",")
                n = int(e_n_salt_hash[1].strip(" ")) # Extract public key from e_n_salt_hash
                print(f"N: {n}")
                d = int(input("Paste private key: ")) # Request private key
                print(main(d,n))


            elif key_option.upper() == "NO":
                continue

            else:
                print("Invalid input")

        else:
            print("Invalid input")


# TODO: Debug if user is tryingg to decript a file or input that is in plaintext. it should warn user, instead of traceback
# TODO: Allow user to generate keys public and private key at will