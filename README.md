# Compare and create hash passwords in ASP.NET format using python and integrate them in Django

Sometimes you work with a database that already exists. In this tutorial, I will show how to integrate your Django project with the database that has a login system created with the ASP.Net framework without using an API from the ASP.NET project.

In case you will work with the database has a user table that was created from ASP.NET framework. the problem here is if you need to work with Django and connect with the same database the users they already created can not log in to your project they need to register again via your project.

we can solve this problem with two methods, first solution you can use an API from ASP.NET project in case you need to check the password and username. The username and password will be sent by HTTP post and get the result in the response. and the same thing when creating a new user. but I don’t recommend this solution cuz you need a third party here.

The second solution depends on how the ASP.NET hashing the password and after that, we can hash the password in Python with the same format and compare the calculated hash with the hash that is saved in the database before.

In this context, I prefer to read the article Anatomy of an ASP.NET Identity PasswordHash (https://www.blinkingcaret.com/2017/11/29/asp-net-identity-passwordhash/) he mentioned that the PasswordHash consists of 49 bytes in case version 2 and 61 bytes in version 3.

1st byte: The value 0 indicates a password hash from Identity Version 2 or the value 1 indicates Version 3

## version 2:

From 2nd to 17th is 16 bytes for the random salt is stored.

From 18th to 49th is 32 bytes where the password hash is stored.

## version 3:

From 2nd to 5th is Hash type

From 6th to 9th byte is the number of iterations

From 10th to 13th is the salt size (it’s always 16)

From 14th to 29th is 16 bytes where the random salt is stored

From 30th to 61th is 32 bytes that contain the hashed password

An example for ASP.Net PasswordHash version 3 is “AQAAAAEAACcQAAAAEJSPbbFM1aeXB8fGRV7RRamLpjzktAF7FjwDWtFx35eol4AxN6vm4zWR9EApc7WPsQ==”

## Create a function to check the password validation in python.

    
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


let’s explain this function, this function needs two inputs the password and the passwordHash which is saved in the database.

you have to convert the passwordHash in bytes array using base64.b64decode() function after that you divide this array as mentioned in the previous part.

with using hashlib.pbkdf2_hmac() function you can hash the password and you will use the same salt to get the same hash value as the passwordHash which is saved in the database.


## Create a function to create a passwordHash as ASP.NET framework



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


this function needs three inputs the password, version type, and the number of iterations. in version 2 the number of iterations is always 1000.

## How do integrate those functions in Django?

you have to Substituting a custom User model(https://docs.djangoproject.com/en/4.0/topics/auth/customizing/) by adding this line in the settings.py

    AUTH_USER_MODEL = 'myapp.MyUser'


in your model, you should edit it to be a AbstractUser

    from django.contrib.auth.models import AbstractUser

    class User(AbstractUser):
    


To avoid some errors, you have to add some attributes, which are needed, in your user Table as isSuperuser, isStaff, and isActive.

  
    from django.contrib.auth.models import AbstractUser

    class User(AbstractUser):

      def check_password(self, password):

        if hash_validation(password=password, passHash=self.password):
            return True
        else:
            def setter(password):
                self.set_password(password)
                # Password hash upgrades shouldn't be considered password changes.
                self._password = None
                self.save(update_fields=["password"])

            return check_password(password, self.password, setter)
            
   



in your user model, you will add the check_password(self, password) which is the Overrides method in AbstractBaseUser with adding hash_validation function. Now you can check the password that was created by the ASP.NET framework without using an API.

you can make the same thing with OverridingCreate_user() function in the user model and add create_hash(password) in Create_user() function to hash the password in the ASP.NET format.




