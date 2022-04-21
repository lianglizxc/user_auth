import time
from datetime import datetime, timedelta
from custom_exception import User_exception, Role_exception, Token_exception
import uuid


class Expire_data():

    def __init__(self, ttl=7200):
        self.auth = {}
        self.ttl = ttl

    def __setitem__(self, key, value):
        self.auth[key] = (value, datetime.now())

    def __getitem__(self, key):
        if key not in self.auth:
            raise KeyError(f'token {key} is invalid')

        value, val_time = self.auth[key]
        if (datetime.now() - val_time) > timedelta(seconds=self.ttl):
            del self.auth[key]
            return None
        else:
            return value

    def __len__(self):
        return len(self.auth)

    def __delitem__(self, key):
        del self.auth[key]

    def __contains__(self, item):
        if item not in self.auth:
            return False
        if self[item]:
            return True
        else:
            return False

    def check_validate_token(self, token):
        return token in self.auth

class User_roles():

    def __init__(self, ttl = 7200):
        self.users = {}
        self.auths_data = Expire_data(ttl)
        self.roles = set()

    def create_user(self, user_name, pwd):
        if user_name in self.users:
            raise User_exception(f'user {user_name} already exists')
        self.users[user_name] = (pwd, [])

    def delete_user(self, user_name):
        if user_name not in self.users:
            raise User_exception(f"user {user_name} doesn't exist")
        del self.users[user_name]


    def create_role(self, role_name):
        if role_name in self.roles:
            raise Role_exception(f"role {role_name} already exists")
        self.roles.add(role_name)

    def delete_role(self, role_name):
        if role_name not in self.roles:
            raise Role_exception(f"role {role_name} doesn't exist")
        self.roles.remove(role_name)
        for user_name in self.users:
            _, user_role = self.users[user_name]
            if role_name in user_role:
                user_role.remove(role_name)

    def add_role_user(self, user_name, role_name):
        if user_name not in self.users:
            raise User_exception(f"user {user_name} doesn't exist")
        if role_name not in self.roles:
            raise Role_exception(f"role {role_name} doesn't exist")

        _, user_roles = self.users[user_name]
        if role_name not in user_roles:
            user_roles.append(role_name)

    def authenticate(self,user_name, pwd):
        if user_name not in self.users:
            raise User_exception(f"user {user_name} doesn't exist")

        if pwd != self.users[user_name][0]:
            raise KeyError(f"password is wrong")

        token = uuid.uuid4().hex
        self.auths_data[token] = user_name
        return token

    def invalidate(self,token):
        if self.auths_data.check_validate_token(token):
            del self.auths_data[token]

    def check_role(self, token, role_name):
        if token not in self.auths_data:
            raise Token_exception('token is invalidate')

        user_name = self.auths_data[token]
        _, user_roles = self.users[user_name]
        return role_name in user_roles

    def all_roles(self, token):
        if token not in self.auths_data:
            raise Token_exception('token is invalidate')

        user_name = self.auths_data[token]
        _, user_roles = self.users[user_name]
        return user_roles


if __name__ == '__main__':
    pass
