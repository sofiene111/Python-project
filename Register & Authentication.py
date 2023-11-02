import re
import hashlib
import bcrypt
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random
##################################Regular expression check#####################################
# Function to validate email using Regular Expression
def is_valid_email(email):
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    if re.match(pattern, email):
        return True, "Email is valid."
    else:
        return False, "Email format is incorrect. Please enter a valid email."


# Function to validate password (at least 1 uppercase, 1 lowercase, 1 digit, 1 special char, length 8)
def is_valid_password(password):
    # Regular expression pattern for a valid password
    password_pattern = r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
    if re.match(password_pattern, password):
        return True, "Password is valid."
    else:
        return False, "Password format is incorrect. Please use at least 8 characters, including at least one uppercase letter, one lowercase letter, one digit, and one special character."
###############################################################################################
###############################################################################################


# Function to register email and login into Enregistrement.txt file
def register(email, password):
    email_valid, email_message = is_valid_email(email)
    password_valid, password_message = is_valid_password(password)
    
    if email_valid and password_valid:
        with open('Enregistrement.txt', 'a') as file:
            file.write(f'{email}:{password}\n')
        print("Registration successful.")
    else:
        if not email_valid:
            print(email_message)
        if not password_valid:
            print(password_message)

# Function to authenticate a user 
def authenticate(email, password):
    found = False
    with open('Enregistrement.txt', 'r') as file:
        lines = file.readlines()
    for line in lines:
        stored_email, stored_password = line.strip().split(':')
        if email == stored_email and password == stored_password:
            found = True
            print("Authentication successful.")
            menu()
            break

    if not found:
        print("Authentication failed. Please check your email and password.")



# Function to display the main menu options
def menu():
    while True:
        print("Main Menu:")
        print("1- Hashing")
        print("2- RSA Encryption")
        print("3- RSA Certificate")
        print("4- Quit")
        choice = input("Enter your choice: ")

        if choice == "1":
            hashing_menu()
        elif choice == "2":
            rsa_encryption_menu()
        elif choice == "3":
            rsa_certificate_menu()
        elif choice == "4":
            break
        else:
            print("Invalid choice. Please try again.")


#################################################################################################
#################################################################################################
                           #####ALL MENUS#####
#################################################################################################
#################################################################################################

# Function to display the hashing menu options
def hashing_menu():
    while True:
        print("Hashing Menu:")
        print("a- Hash a word with sha256")
        print("b- Hash a word with bcrypt and generate a salt")
        print("c- Dictionary Attack")
        print("d- Return to Main Menu")
        choice = input("Enter your choice: ")

        if choice == "a":
            word = input("Enter the word to hash: ")
            hash_sha256(word)
        elif choice == "b":
            word = input("Enter the word to hash: ")
            hash_bcrypt(word)
        elif choice == "c":
            word = input("Enter the word: ")
            dictionary_file = input("Enter the dictionary file path: ")
            dictionary_attack(word.encode(), dictionary_file)
        elif choice == "d":
            break
        else:
            print("Invalid choice")

# Function to display RSA encryption menu options
def rsa_encryption_menu():
    while True:
        print("RSA Encryption Menu:")
        print("a- Generate RSA key pair and save to a file")
        print("b- Encrypt a message using RSA")
        print("c- Decrypt an RSA-encrypted message")
        print("d- Sign a message using RSA")
        print("e- Verify the signature of a message using RSA")
        print("f- Return to Main Menu")
        choice = input("Enter your choice: ")

        if choice == "a":
            generate_rsa_key_pair()
        elif choice == "b":
            message = input("Enter the message to encrypt: ")
            encrypt_rsa_message(message)
        elif choice == "c":
            encrypted_message = input("Enter the encrypted message: ")
            decrypt_rsa_message(encrypted_message)
        elif choice == "d":
            message = input("Enter the message to sign: ")
            sign_rsa_message(message)
        elif choice == "e":
            message = input("Enter the message to verify: ")
            signature = input("Enter the signature to verify: ")
            verify_rsa_signature(message, signature)
        elif choice == "f":
            break
        else:
            print("Invalid choice. Please try again.")


# Function to display the RSA certificate menu options
def rsa_certificate_menu():
    while True:
        print("RSA Certificate Menu:")
        print("a- Generate RSA key pair and save to a file")
        print("b- Generate a self-signed RSA certificate")
        print("c- Encrypt a message using the certificate")
        print("d- Return to Main Menu")
        choice = input("Enter your choice: ")

        if choice == "a":
            generate_rsa_key_pair()
        elif choice == "b":
            generate_self_signed_certificate()
        elif choice == "c":
            message = input("Enter the message to encrypt: ")
            encrypt_with_certificate(message)
        elif choice == "d":
            break
        else:
            print("Invalid choice. Please try again.")

#################################################################################################
#################################################################################################



#################################################################################################
#################################################################################################
                                ###HASHING FUNCTIONS####
#################################################################################################
#################################################################################################
# Function to hash a word with sha256
def hash_sha256(word):
    hashed = hashlib.sha256(word.encode()).hexdigest()
    print(f"SHA256 Hash: {hashed}")

# Function to hash a word with bcrypt and generate a salt
def hash_bcrypt(word):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(word.encode('utf-8'), salt)
    print(f"Bcrypt Hash: {hashed}")

# Function for dictionary attack
def dictionary_attack(target_word, dictionary_file):
    try:
        with open(dictionary_file, 'r') as file:
            dictionary = [line.strip() for line in file]
            print(dictionary)
        check_word = False
        for word in dictionary:
            print(f"Wordlists: {word}")
            if  target_word.decode() == word:
                check_word = True
                found_word = word
                break

        if check_word:
            print(f"Word found in the dictionary: {found_word}")
        else:
            print("Word not found in the dictionary.")
    except FileNotFoundError:
        print(f"Dictionary file '{dictionary_file}' not found.")
#################################################################################################
#################################################################################################




#################################################################################################
#################################################################################################
                                    ###RSA ENCRYPTION FUNCTIONS##
#################################################################################################
#################################################################################################
# Function to generate RSA key pair and save to a file
def generate_rsa_key_pair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    with open('private_key.pem', 'wb') as private_file, open('public_key.pem', 'wb') as public_file:
        private_file.write(private_key)
        public_file.write(public_key)
    print("RSA key pair generated and saved.")

# Function to encrypt a message using RSA
def encrypt_rsa_message(message):
    with open('public_key.pem', 'rb') as file:
        public_key = RSA.import_key(file.read())
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_message = cipher.encrypt(message.encode('utf-8'))
    print(f"Encrypted Message: {encrypted_message.hex()}")

# Function to decrypt an RSA-encrypted message
def decrypt_rsa_message(encrypted_message):
    with open('private_key.pem', 'rb') as file:
        private_key = RSA.import_key(file.read())
    cipher = PKCS1_OAEP.new(private_key)
    decrypted_message = cipher.decrypt(bytes.fromhex(encrypted_message)).decode('utf-8')
    print(f"Decrypted Message: {decrypted_message}")

# Function to sign a message using RSA
def sign_rsa_message(message):
    with open('private_key.pem', 'rb') as file:
        private_key = RSA.import_key(file.read())
    signature = pkcs1_15.new(private_key).sign(message.encode('utf-8'))
    print(f"Signature: {signature.hex()}")

# Function to verify the signature of a message using RSA
def verify_rsa_signature(message, signature):
    with open('public_key.pem', 'rb') as file:
        public_key = RSA.import_key(file.read())
    try:
        pkcs1_15.new(public_key).verify(message.encode('utf-8'), bytes.fromhex(signature))
        print("Signature is valid.")
    except (ValueError, TypeError):
        print("Signature is invalid.")

#################################################################################################
#################################################################################################





#################################################################################################
#################################################################################################
                                    ###RSA CERTIFICATE FUNCTIONS##
#################################################################################################
#################################################################################################

# Function to generate a self-signed RSA certificate
def generate_self_signed_certificate():
    key = RSA.generate(2048)
    with open('private_key.pem', 'wb') as private_file:
        private_file.write(key.export_key())
    cert = x509.CertificateBuilder()
    cert = cert.issuer_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Org"),
        x509.NameAttribute(NameOID.COMMON_NAME, "example.com"),
    ]))
    cert = cert.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Org"),
        x509.NameAttribute(NameOID.COMMON_NAME, "example.com"),
    ]))
    cert = cert.public_key(key.publickey())
    cert = cert.serial_number(x509.random_serial_number())
    cert = cert.not_valid_before(datetime.datetime.utcnow())
    cert = cert.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
    cert = cert.sign(key, hashes.SHA256(), default_backend())
    with open('certificate.pem', 'wb') as certificate_file:
        certificate_file.write(cert.public_bytes(serialization.Encoding.PEM))

# Function to encrypt a message using the certificate
def encrypt_with_certificate(message):
    with open('certificate.pem', 'rb') as certificate_file:
        certificate = x509.load_pem_x509_certificate(certificate_file.read(), default_backend())
        public_key = certificate.public_key()
        encrypted = public_key.encrypt(
            message.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print(f"Encrypted Message: {encrypted.hex()}")

#################################################################################################
#################################################################################################


# Main program
while True:
    print("Main Menu:")
    print("1- Registration")
    print("2- Authentication")
    print("3- Quit")

    choice = input("Enter your choice: ")
    if choice == "1":
        email = input("Enter your email: ")
        password = input("Enter your password: ")
        register(email, password)
    elif choice == "2":
        email = input("Enter your email: ")
        password = input("Enter your password: ")
        authenticate(email, password)
    elif choice == "3":
        break
    else:
        print("Invalid choice. Please try again.")
