import base64
import hashlib
from random import randbytes


def hash_validation(password, hash_value, version=3, ):
    try:
        if password is None or hash_value is None:
            return False
        if type(version) is not int or (version != 2 and version != 3):
            raise TypeError("version is an integers and should be 2 or 3")
        password = password.encode()
        hash_in_bytes = base64.b64decode(hash_value)
        if version == 2:
            # version = hash_in_bytes[0:1]
            salt = hash_in_bytes[1:17]
            password_hash_database = hash_in_bytes[17:49]
            calculated_password_hash = hashlib.pbkdf2_hmac("sha1", password, salt, 1000, 32)
        elif version == 3:
            # version = hash_in_bytes[0:1]
            # prf = hash_in_bytes[1:5]
            iteration_bytes = hash_in_bytes[5:9]
            iteration_int = int.from_bytes(iteration_bytes, byteorder="big")
            salt_size_bytes = hash_in_bytes[9:13]
            salt_size_int = int.from_bytes(salt_size_bytes, byteorder="big")
            salt = hash_in_bytes[13:(13 + salt_size_int)]
            password_hash_database = hash_in_bytes[(13 + salt_size_int):len(hash_in_bytes)]
            calculated_password_hash = hashlib.pbkdf2_hmac("SHA256", password, salt, iteration_int, 32)
    except(Exception,):
        return False
    if calculated_password_hash.hex() == password_hash_database.hex():
        return True
    else:
        return False


def create_hash(password, version=3, iterations=10000, ):
    try:
        if type(password) is not str:
            raise Exception("Only Strings passwords are allowed")
        if type(version) is not int or (version != 2 and version != 3):
            raise Exception("version is an integers and should be 2 or 3")
        if type(iterations) is not int:
            raise Exception("Only integers are allowed")
        password = password.encode()
        if version == 2:
            version_byte = (0).to_bytes(1, byteorder='big')
            salt = randbytes(16)
            calculated_password_hash = hashlib.pbkdf2_hmac("sha1", password, salt, 1000, 32)
            hash_generator = (version_byte + salt + calculated_password_hash)
            return base64.b64encode(hash_generator)
        elif version == 3:
            version_byte = (1).to_bytes(1, byteorder='big')
            hash_type_byte = (1).to_bytes(4, byteorder='big')
            iterations_byte = iterations.to_bytes(4, byteorder='big')
            salt_size_byte = (16).to_bytes(4, byteorder='big')
            salt = randbytes(16)
            calculated_password_hash = hashlib.pbkdf2_hmac("SHA256", password, salt, iterations, 32)
            hash_generator = (version_byte + hash_type_byte + iterations_byte + salt_size_byte + salt +
                              calculated_password_hash)
            return base64.b64encode(hash_generator)
    except Exception as e:
        print("Oops!", e.__class__, "occurred.")
  
