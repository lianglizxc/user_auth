import time
import unittest
import user_auth as ua
from custom_exception import User_exception, Token_exception, Role_exception

class Test_user_auth(unittest.TestCase):

    def test_add_remove_user(self):
        ur = ua.User_roles()
        ur.create_user('tony','12345')
        ur.delete_user('tony')
        with self.assertRaises(User_exception):
            ur.delete_user('tony')

    def test_add_remove_role(self):
        ur = ua.User_roles()
        ur.create_role('job1')
        ur.delete_role('job1')
        with self.assertRaises(Role_exception):
            ur.delete_role('job1')

    def test_add_role_user(self):
        ur = ua.User_roles()
        with self.assertRaises(User_exception):
            ur.add_role_user('tony', 'job1')

        ur.create_user('tony', '12345')
        with self.assertRaises(Role_exception):
            ur.add_role_user('tony', 'job1')

        ur.create_role('job1')
        ur.add_role_user('tony', 'job1')
        with self.assertRaises(KeyError):
            ur.authenticate('tony','4321')

        token = ur.authenticate('tony','12345')
        ur.create_role('job2')
        ur.add_role_user('tony', 'job2')
        self.assertEqual(ur.all_roles(token), ['job1','job2'])

        ur.delete_role('job1')
        self.assertFalse(ur.check_role(token, 'job1'))
        self.assertTrue(ur.check_role(token, 'job2'))

        ur.delete_user('tony')

    def test_authenticate(self):
        ur = ua.User_roles()
        with self.assertRaises(User_exception):
            ur.authenticate('liangli','212131')

        ur.create_user('tony', '12345')
        token = ur.authenticate('tony', '12345')
        self.assertEqual(ur.all_roles(token), [])

        ur.create_role('job1')
        ur.add_role_user('tony', 'job1')

    def test_invalidate(self):
        ur = ua.User_roles()
        ur.create_user('tony', '12345')
        token = ur.authenticate('tony', '12345')

        ur.invalidate('some random token')
        ur.invalidate(token)
        with self.assertRaises(Token_exception):
            ur.check_role(token, 'job1')

    def test_expire_token(self):
        ur = ua.User_roles(ttl=5)
        ur.create_user('tony', '12345')
        ur.create_role('job1')
        ur.add_role_user('tony','job1')
        token = ur.authenticate('tony', '12345')
        self.assertTrue(ur.check_role(token, 'job1'))
        self.assertFalse(ur.check_role(token, 'job2'))

        time.sleep(10)
        with self.assertRaises(Token_exception):
            ur.check_role(token, 'job1')

if __name__ == '__main__':
    unittest.main()