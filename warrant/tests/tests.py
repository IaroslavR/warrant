import unittest
from mock import patch

from warrant import Cognito, UserObj, TokenVerificationException
from warrant.secrets import COGNITO_USER_POOL_ID, COGNITO_APP_ID, COGNITO_TEST_USERNAME, COGNITO_TEST_PASSWORD, \
    COGNITO_TEST_EMAIL, COGNITO_TEST_ADMIN_USERNAME, COGNITO_TEST_ADMIN_PASSWORD, COGNITO_TEST_ADMIN_EMAIL
from warrant.aws_srp import AWSSRP


class UserObjTestCase(unittest.TestCase):

    def setUp(self):
        self.cognito_user_pool_id = COGNITO_USER_POOL_ID
        self.app_id = COGNITO_APP_ID
        self.username = COGNITO_TEST_USERNAME
        self.user = Cognito(
            self.cognito_user_pool_id, 
            self.app_id,
            self.username
        )
        self.user_metadata = {
            'user_status': 'CONFIRMED',
            'username': 'bjones',
        }
        self.user_info = [
            {'Name': 'name', 'Value': 'Brian Jones'},
            {'Name': 'given_name', 'Value': 'Brian'},
            {'Name': 'birthdate', 'Value': '12/7/1980'}
        ]

    def test_init(self):
        u = UserObj('bjones', self.user_info, self.user, self.user_metadata)
        self.assertEquals(u.pk, self.user_metadata.get('username'))
        self.assertEquals(u.name, self.user_info[0].get('Value'))
        self.assertEquals(u.user_status, self.user_metadata.get('user_status'))


class CognitoAuthTestCase(unittest.TestCase):

    def setUp(self):
        self.cognito_user_pool_id = COGNITO_USER_POOL_ID
        self.app_id = COGNITO_APP_ID
        self.username = COGNITO_TEST_USERNAME
        self.password = COGNITO_TEST_PASSWORD
        self.user = Cognito(
            self.cognito_user_pool_id,
            self.app_id,
            username=self.username
        )
        self.admin_username = COGNITO_TEST_ADMIN_USERNAME
        self.admin_password = COGNITO_TEST_ADMIN_PASSWORD
        self.admin_user = Cognito(
            self.cognito_user_pool_id,
            self.app_id,
            username=self.admin_username
        )

    def test_authenticate(self):
        self.user.authenticate(self.password)
        self.assertNotEqual(self.user.access_token, None)
        self.assertNotEqual(self.user.id_token, None)
        self.assertNotEqual(self.user.refresh_token, None)

    def test_verify_token(self):
        self.user.authenticate(self.password)
        bad_access_token = '{}wrong'.format(self.user.access_token)

        with self.assertRaises(TokenVerificationException) as vm:
            self.user.verify_token(bad_access_token, 'access_token', 'access')

    def test_logout(self):
        self.user.authenticate(self.password)
        self.user.logout()
        self.assertEquals(self.user.id_token, None)
        self.assertEquals(self.user.refresh_token, None)
        self.assertEquals(self.user.access_token, None)

    @patch('warrant.Cognito', autospec=True)
    def test_register(self, cognito_user):
        user = cognito_user(
            self.cognito_user_pool_id, 
            self.app_id,
            username=self.username
        )
        response = user.register(
            username='sampleuser',
            password='sample4#Password',
            given_name='Brian',
            family_name='Jones',
            name='Brian Jones',
            email='test@foodog.io',
            phone_number='+19194894555',
            gender='Male',
            preferred_username='billyocean'
        )
        print('test_register -> response', response)
        # TODO: Write assumptions

    def test_renew_access_tokens(self):
        self.user.authenticate(self.password)
        self.user.renew_access_token()

    @patch('warrant.Cognito', autospec=True)
    def test_update_profile(self, cognito_user):
        user = cognito_user(
            self.cognito_user_pool_id,
            self.app_id,
            username=self.username
        )
        user.authenticate(self.password)
        user.update_profile({'given_name': 'Jenkins'})

    def test_admin_get_user(self):
        user = self.user.admin_get_user()
        self.assertEquals(user.pk, self.username)
    
    def test_check_token(self):
        self.user.authenticate(self.password)
        self.assertFalse(self.user.check_token())

    @patch('warrant.Cognito', autospec=True)
    def test_validate_verification(self, cognito_user):
        user = cognito_user(
            self.cognito_user_pool_id,
            self.app_id,
            username=self.username
        )
        user.validate_verification('4321')

    @patch('warrant.Cognito', autospec=True)
    def test_confirm_forgot_password(self, cognito_user):
        user = cognito_user(
            self.cognito_user_pool_id,
            self.app_id,
            username=self.username
        )
        user.confirm_forgot_password('4553', 'samplepassword')
        with self.assertRaises(TypeError) as vm:
            user.confirm_forgot_password(self.password)

    @patch('warrant.Cognito', autospec=True)
    def test_change_password(self, cognito_user):
        user = cognito_user(
            self.cognito_user_pool_id,
            self.app_id,
            username=self.username
        )
        user.authenticate(self.password)
        user.change_password(self.password, 'crazypassword$45DOG')

        with self.assertRaises(TypeError) as vm:
            self.user.change_password(self.password)

    def test_set_attributes(self):
        user = Cognito(self.cognito_user_pool_id, self.app_id)
        user._set_attributes(
            {
                'ResponseMetadata': {
                    'HTTPStatusCode': 200
                }
            },
            {
                'somerandom': 'attribute'
            }
        )
        self.assertEquals(user.somerandom, 'attribute')

    # def test_admin_authenticate(self):
    #     self.admin_user.admin_authenticate(self.admin_password)
    #     self.assertNotEqual(self.user.access_token, None)
    #     self.assertNotEqual(self.user.id_token, None)
    #     self.assertNotEqual(self.user.refresh_token, None)


class AWSSRPTestCase(unittest.TestCase):

    def setUp(self):
        """
        Create instance of AWS Secure Remote Password.
        :return: None
        """
        self.cognito_user_pool_id = COGNITO_USER_POOL_ID
        self.app_id = COGNITO_APP_ID
        self.username = COGNITO_TEST_USERNAME
        self.password = COGNITO_TEST_PASSWORD
        self.email = COGNITO_TEST_EMAIL

        # Create a user if one doesn't already exist.
        user = Cognito(
            self.cognito_user_pool_id,
            self.app_id,
            username=self.username
        )
        try:
            response = user.register(
                username=self.username,
                password=self.password,
                email=self.email,
            )
        except Exception:         # The user already exists which is great.
            pass

        self.awssrp = AWSSRP(
            username=self.username,
            password=self.password,
            pool_id=self.cognito_user_pool_id,
            client_id=self.app_id
        )

    def tearDown(self):
        self.awssrp.close_ssl_socket()
        del self.awssrp

    def test_authenticate_user(self):
        tokens = self.awssrp.authenticate_user()
        self.assertTrue('IdToken' in tokens['AuthenticationResult'])
        self.assertTrue('AccessToken' in tokens['AuthenticationResult'])
        self.assertTrue('RefreshToken' in tokens['AuthenticationResult'])


if __name__ == '__main__':
    unittest.main()
