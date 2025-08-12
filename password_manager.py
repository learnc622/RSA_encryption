import random, string
import time

import Encryption
from Encryption import encrypt, decrypt


def generate_pasword(n:int = 12) -> str:
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
    """encrypts password and saves it to a file
    Parameters:
        password: password that would be encryppted and stored"""
    password_purpose = input("What is the password for: ")
    user_id = input("Enter email or username: ")
    # Encrypt information before saving
    message = "".join(f"{password_purpose} Password, User Id: {user_id}, Password: {password}")
    # Get public keys, salt and private-key hash
    content = Encryption.get_keys()
    e = int(content[0][0])
    n = int(content[0][1])
    salt = content[1]
    hashed_message = Encryption.hash_message(message, salt) # Hash password for futute validation
    # store hashed message in text file
    hash_file = "message_hash.txt"
    with open(hash_file, 'a') as file:
        file.write(f"{hashed_message}\n")
    encrypted_message = encrypt(message, e, n) # encrypts user passwords using rsa logic
    # store encrypted password in text file
    file_name = "store.txt"
    with open(file_name.format(file_name), "a") as file:
        file.write(f"{encrypted_message}\n")
        print("...\nPassword stored Successfully\n...")

def retrieve_password():
    """
    Get stored encrypted password
    No Parameter
    Returns: str
        prints password in plaintext
    """
    
    content = Encryption.get_keys() # get stored public keys , salt and private-key hash
    n = int(content[0][1]) 
    salt = content[1]
    hashed_key = content[2]
    private_key = int(input("....\nEnter Private key: "))
    if Encryption.validate_private_key(private_key, salt, hashed_key): # validated that private-key matches with hashed-key
        file_path = "store.txt"
        with open("message_hash.txt", 'r') as hash_file:
            hashed_message = hash_file.read().split("\n")
        with open(file_path, "r", encoding="utf-8") as file:
            message = file.read()
            decrypted_message = decrypt(message, private_key, n)
            iter = 0
            for i in (decrypted_message.split("\n")[:(len(decrypted_message.split("\n")) - 1)]):
                if hashed_message[iter] == Encryption.hash_message(i, salt): # validated that hashed message matches with hashed mesage
                    print(i)
                    iter += 1
                else:
                    print("....\nWarning...\n An error has occoured.\n....")
    else:
        print("Authentication error")
        print("Private key dont match")


def main():

    try:
        while True:
            print("Do you want to\n1. Generate random password\n2. Get stored password\n3. Store a password\n4. Reset  keys\n5. Quit")
            option = input("...\nEnter an option: ")
            if option == "1":
                # password_length = int(input("Enter password length. minimum = 10: ")) # request password length
                #
                # while password_length < 10: # Force user to enter password length greater than 10
                #     print("For good security, length of password should be 10 and above")
                #     password_length = int(input("Enter password length. minimum = 10: "))
                default_length_opt = input("....\nUse default password length. Yes\\no: ")
                
                password = generate_pasword()
                print("Password: {}".format(password))
                while True:
                    save_option = input("...\nDo yow want to save password. Yes/ No: ")
                    if save_option.upper() == "YES":
                        store_password(password)
                        break
                    elif save_option.upper() == "NO":
                        print("....\nReturning to main menu\n....")
                        break
                    else:
                        print("...\nInvalid imput\n...")
                        continue

            elif option == "2":
                # Get public keys and
                retrieve_password()

            elif option == "3":
                # store password to txt file.
                password = input("...\nEnter password to store: ")
                store_password(password)

            elif option == "4":
                print("....\nAre you sure you want to reset keys\n1. Yes\n2. No")
                reset_option =  input("...\nEnter an option: ")
                print("....")
                if reset_option == "1" or reset_option.upper() == "YES":
                    print("This action will delete previous keys and stored message permanently ")
                    print("....\nThis action cannot be undone\n1. Proceed\n2. Cancel\n....")
                    reset_option = input("Enter an option: ")
                    if reset_option == "1" or reset_option.upper() == "PROCEED":
                        keys_file = "public_keys.txt" # Keys file
                        message_file = "store.txt" #message store file
                        hash_file = "message_hash.txt" # message hash file
                        with open(keys_file, "w") as k_file, open(message_file, "w") as m_file, open(hash_file, "w") as h_file:
                            keys = Encryption.generate_keys() #Generate new keys
                            k_file.write(keys) # Write new keys to file
                            m_file.write("") # clear previously stored message
                            h_file.write("") # clear previously stored message hash

                    elif reset_option == "2" or reset_option.upper() == "CANCEL":
                        print("Returning to menu\n...")
                        time.sleep(1.2)
                    else:
                        print("Invalid option")
                elif reset_option == "2" or reset_option.upper() == "NO":
                    print("Returning to menu\n...")
                    time.sleep(1.2)
            elif option == "5":
                exit()
            else:
                print("\nInvalid input\n")

    except Exception as error:
        print(error)

if __name__ == "__main__":
    main()

# TODO: nudge user to choose password they want to decrypt instead of decrypting it all and exposing other passwords