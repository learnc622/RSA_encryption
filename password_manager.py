import random, string
import sqlite3

import Encryption
from Encryption import encrypt, decrypt

conn = sqlite3.connect("")

def get_password(n:int = 12) -> str:
    """
    Generate a random password
    :param n: int
        intended password length
    :return: str
        random generated password of length n
    """
    chars = string.ascii_letters + string.digits + string.punctuation # alphabets + numbers + symbols
    password = "".join(random.choice(chars) for _ in range(n)) # gets a random char from chars n times and join it together
    return password

def store_password(password: str):
    """encrypts password and saves it to a file"""
    password_purpose = input("What is the password for: ")
    user_id = input("Enter email or username: ")
    password = password
    # Encrypt information before saving
    message = "".join(f"{password_purpose} Password, User Id: {user_id}, Password: {password}")
    # Get public keys
    content = Encryption.get_keys()
    e = int(content[0][0])
    n = int(content[0][1])
    salt = content[1]
    hashed_message = Encryption.hash_message(message, salt)
    hash_file = "message_hash.txt"
    with open(hash_file, 'a') as file:
        file.write(f"{hashed_message}\n")
    encrypted_message = encrypt(message, e, n)
    file_name = "store.txt"

    with open(file_name.format(file_name), "a") as file:
        file.write(f"{encrypted_message}\n")
        print("Password stored Successfully")

def retrieve_password():
    """
    Get stored encrypted password
    No Parameter
    Returns: str
        prints password in plaintext
    """
    content = Encryption.get_keys()
    n = int(content[0][1])
    salt = content[1]
    hashed_key = content[2]
    private_key = int(input("Enter Private key: "))
    if Encryption.validate_private_key(private_key, salt, hashed_key):
        file_path = "store.txt"
        with open("message_hash.txt", 'r') as hash_file:
            hashed_message = hash_file.read().split("\n")


        with open(file_path, "r", encoding="utf-8") as file:
            message = file.read()
            decrypted_message = decrypt(message, private_key, n)
            iter = 0
            for i in (decrypted_message.split("\n")[:(len(decrypted_message.split("\n")) - 1)]):
                if hashed_message[iter] == Encryption.hash_message(i, salt):
                    print(i)
                    iter += 1

    else:
        print("Private key dont match")


def main():

    try:
        while True:
            print("Do you want to\n1. Generate random password\n2. Get stored password\n3. Store a password")
            option = input("Enter an option: ")
            if option == "1":
                # password_length = int(input("Enter password length. minimum = 10: ")) # request password length
                #
                # while password_length < 10: # Force user to enter password length greater than 10
                #     print("For good security, length of password should be 10 and above")
                #     password_length = int(input("Enter password length. minimum = 10: "))
                password = get_password()
                print("Password: {}".format(password))
                while True:
                    save_option = input("Do yow want to save password. Yes/ No: ")
                    if save_option.upper() == "YES":
                        store_password(password)
                        break
                    elif save_option.upper() == "NO":
                        break
                    else:
                        print("Invalid imput")
                        continue

            elif option == "2":
                # Get public keys and
                retrieve_password()

            elif option == "3":
                # store password to txt file.
                password = input("Enter password to store: ")
                store_password(password)

            else:
                print("Invalid input")

    except ValueError:
        pass

if __name__ == "__main__":
    main()

# TODO: hash message befure encrypting and then confirm if it is the same with hash of message after encryption.
