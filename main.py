import base64
import hashlib


def hash_validation(password, hash_value):

    if password is None or hash_value is None:
        return False
    try:
        hash_in_bytes = base64.b64decode(hash_value)
        prf = hash_in_bytes[1:5]
        iteration_bytes = hash_in_bytes[5:9]
        iteration_int = int.from_bytes(iteration_bytes, byteorder="big")
        salt_size_bytes = hash_in_bytes[9:13]
        salt_size_int = int.from_bytes(salt_size_bytes, byteorder="big")
        salt = hash_in_bytes[13:(13 + salt_size_int)]

        password_hash_database = hash_in_bytes[(13 + salt_size_int):len(hash_in_bytes)]
        password = password.encode()
        calculated_password_hash = hashlib.pbkdf2_hmac("SHA256", password, salt, iteration_int, 32)
    except(Exception,):
        return False
    if calculated_password_hash.hex() == password_hash_database.hex():
        return True
    else:
        return False




print(hash_validation('!AOMfps2020', 'AQAAAAEAACcQAAAAEHfxouMZ9BU2tg2pNOhmexTPPeCAGIsVTGI9USPvZJWZPbRobJzFYzWO9WMnnEPS9g=='))
"""
Version3:
PBKDF2
with HMAC - SHA256, 128 - bit salt, 256-bit subkey, 10000 iterations.
Format: {0x01, prf(UInt32), iter count(UInt32), salt length(UInt32), salt, subkey}
(All UInt32s are stored big-endian.)

# print(any_bytes.hex()) # u can use it to print the result
# to get int from bytearray int.from_bytes() ... If byteorder is "big", the most significant byte is at the beginning of the byte array
"""