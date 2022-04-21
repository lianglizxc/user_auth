# user_auth

user_auth.py contains all required api. 
The class Expire_data implements a custom data structure with the functionality of expired keys, 
which was used to store all auth_tokens. I used unittest library to run all test suits in test_api.py.
To test expired key, I set ttl = 5s, then wait for 10s to see the token become invalidate.
You can simply run the test script in pycharm or in terminal with cmd, python3 test_api.py
