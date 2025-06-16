import secrets

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
    converted_message ="".join([chr(i) for i in message]) # takes ascii numerics and converts back to their character representation
    return converted_message

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
    converted = convert_to_ascii(m) # convert all the information in the message to ascii
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

def find_d(a, n):
    gcd, x, y = extended_euclidean(a, n)
    if gcd != 1:
        raise ValueError(f"No modular inverse exists because gcd({a}, {n}) ≠ 1")
    return x % n  # Ensure the result is positive

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

def main(p, q):
    print("Welcome to simple RSA encryption")
    while True:
        print("1. Encrypt a file\n2. Decrypt a file\n3. Generate private key\n4. Quit")
        choice = input("Enter your choice: ")
        n = p * q
        phi_n = (p - 1) * (q - 1)
        # select_e = [3,5,17,65537]
        e = 17  # random.choice(select_e)
        d = find_d(e, phi_n)
        print(d)
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
                with open(fr"{file_path}", "w+", encoding="utf-8") as file:
                    file.write(decoded_message)
            elif option == '2':
                encrypted_message = input('Enter encrypted message: ')
                decrypted_message = decrypt(encrypted_message, d, n)
                return decrypted_message

        elif choice == '3':
            n_bit = int(input('How many bits should the private key be: '))
            p =input("Enter p: ") # 7283167306650267509 # random_prime_number(n_bit)
            q =input("Enter q: ") # 4571792070546891821 #random_prime_number(n_bit)
            phi_n = (p-1) * (q-1)
            print(phi_n, "phi")
            d = find_d(e, phi_n)

            print(f'Your private key is: {d}')
            return d

        elif choice == '4':
            exit()

# print(main(7283167306650267509, 4571792070546891821))

print(main(int(input("Enter p: ")), int(input("Enter q: "))))


# TODO: if user is tryingg to decript a file or input that is in plaintext. it should warn user, instead of traceback