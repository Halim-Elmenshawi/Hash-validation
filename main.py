import base64
import hashlib
def hash_validation(password,passHash):
# print(prfAsArray.hex()) # u can use it to print the result
# print(int.from_bytes(prfAsArray, byteorder="big"))
    """
        Version3:
        PBKDF2
        with HMAC - SHA256, 128 - bit salt, 256-bit subkey, 10000 iterations.
        Format: {0x01, prf(UInt32), iter count(UInt32), salt length(UInt32), salt, subkey}
        (All UInt32s are stored big-endian.)
    """
    if(password==None or passHash==None):
        print("jds")
        return False
    try:
        bytes = base64.b64decode(passHash)

        prfAsArray=bytearray(4) #this Fun to store byte array
        prfAsArray=bytes[1:5] # based on ASP.net Format

        iterationCountAsArray=bytearray(4)
        iterationCountAsArray=bytes[5:9]
        iteration=int.from_bytes(iterationCountAsArray, byteorder="big") # to get int from bytearray

        saltSizeAsArray=bytearray(4)
        saltSizeAsArray=bytes[9:13]
        saltSize=int.from_bytes(saltSizeAsArray, byteorder="big")

        salt=bytearray(saltSize)
        salt=bytes[13:(13+saltSize)]

        savedHashedPassword=bytearray(len(bytes)-1-4-4-4-saltSize)
        savedHashedPassword=bytes[(13+saltSize):len(bytes)]

        password=password.encode()
        password_hash = hashlib.pbkdf2_hmac("SHA256", password,salt,iteration,32)
    except:
        return False
    if(password_hash.hex()==savedHashedPassword.hex()):
        return True
    else:
        return False
