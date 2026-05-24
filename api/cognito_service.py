import os
import boto3
from botocore.exceptions import ClientError
from django.contrib.auth import get_user_model
from .models import UserProfile

User = get_user_model()

class CognitoService:
    def __init__(self):
        self.region = os.getenv('AWS_REGION', 'us-east-1')
        self.user_pool_id = os.getenv('COGNITO_USER_POOL_ID')
        self.client_id = os.getenv('COGNITO_APP_CLIENT_ID') or os.getenv('COGNITO_USER_POOL_CLIENT_ID')
        self.endpoint_url = os.getenv('AWS_ENDPOINT_URL')  # LocalStack endpoint

        # Initialize Cognito IDP client
        if self.endpoint_url:
            # LocalStack setup
            self.client = boto3.client(
                'cognito-idp',
                region_name=self.region,
                endpoint_url=self.endpoint_url,
                aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID', 'test'),
                aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY', 'test'),
            )
        else:
            # Production AWS setup
            self.client = boto3.client('cognito-idp', region_name=self.region)

    def sign_up(self, email, password, first_name, last_name, role='patient'):
        """Register a new user in Cognito and local database"""
        try:
            # Try to sign up first (in case user doesn't exist)
            try:
                response = self.client.sign_up(
                    ClientId=self.client_id,
                    Username=email,
                    Password=password,
                    UserAttributes=[
                        {'Name': 'email', 'Value': email},
                        {'Name': 'given_name', 'Value': first_name},
                        {'Name': 'family_name', 'Value': last_name},
                        {'Name': 'custom:role', 'Value': role},
                    ],
                )
                cognito_sub = response['UserSub']
            except ClientError as e:
                if e.response['Error']['Code'] == 'UsernameExistsException':
                    # User already exists, get their sub
                    user_info = self.client.admin_get_user(
                        UserPoolId=self.user_pool_id,
                        Username=email
                    )
                    cognito_sub = None
                    for attr in user_info['UserAttributes']:
                        if attr['Name'] == 'sub':
                            cognito_sub = attr['Value']
                            break
                else:
                    raise

            # Create user in local database if not exists
            user, created = User.objects.get_or_create(
                email=email,
                defaults={
                    'username': email,
                    'first_name': first_name,
                    'last_name': last_name,
                    'role': role,
                    'cognito_sub': cognito_sub,
                }
            )

            if created:
                UserProfile.objects.create(user=user)
            else:
                if cognito_sub:
                    user.cognito_sub = cognito_sub
                user.save()

            return {
                'success': True,
                'user_sub': cognito_sub,
                'user': user,
                'message': 'User registered successfully'
            }

        except ClientError as e:
            error_code = e.response['Error']['Code']
            return {
                'success': False,
                'error': str(e),
                'error_code': error_code
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Registration failed: {str(e)}',
                'error_code': 'UnknownError'
            }

    def sign_in(self, email, password):
        """Authenticate user with Cognito and return tokens"""
        try:
            response = self.client.initiate_auth(
                ClientId=self.client_id,
                AuthFlow='USER_PASSWORD_AUTH',
                AuthParameters={
                    'USERNAME': email,
                    'PASSWORD': password,
                }
            )

            # Get tokens from response
            tokens = response.get('AuthenticationResult', {})
            access_token = tokens.get('AccessToken')
            id_token = tokens.get('IdToken')
            refresh_token = tokens.get('RefreshToken')

            # Fetch user attributes from Cognito
            user_attrs = {}
            try:
                user_info = self.client.admin_get_user(
                    UserPoolId=self.user_pool_id,
                    Username=email
                )
                for attr in user_info.get('UserAttributes', []):
                    user_attrs[attr['Name']] = attr['Value']
            except:
                pass

            # Get or create local user with Cognito attributes
            defaults = {'username': email}
            if 'given_name' in user_attrs:
                defaults['first_name'] = user_attrs['given_name']
            if 'family_name' in user_attrs:
                defaults['last_name'] = user_attrs['family_name']
            if 'custom:role' in user_attrs:
                defaults['role'] = user_attrs['custom:role']

            user, created = User.objects.get_or_create(
                email=email,
                defaults=defaults
            )

            if created:
                UserProfile.objects.create(user=user)
            else:
                # Update existing user with fresh data from Cognito
                if 'given_name' in user_attrs and user_attrs['given_name'] != user.first_name:
                    user.first_name = user_attrs['given_name']
                if 'family_name' in user_attrs and user_attrs['family_name'] != user.last_name:
                    user.last_name = user_attrs['family_name']
                if 'custom:role' in user_attrs and user_attrs['custom:role'] != user.role:
                    user.role = user_attrs['custom:role']
                user.save()

            return {
                'success': True,
                'user': user,
                'tokens': {
                    'access_token': access_token,
                    'id_token': id_token,
                    'refresh_token': refresh_token,
                },
                'message': 'Authentication successful'
            }

        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'NotAuthorizedException':
                return {
                    'success': False,
                    'error': 'Invalid credentials',
                    'error_code': error_code
                }
            elif error_code == 'UserNotFoundException':
                return {
                    'success': False,
                    'error': 'User not found',
                    'error_code': error_code
                }
            elif error_code == 'UserNotConfirmedException':
                return {
                    'success': False,
                    'error': 'User account not confirmed',
                    'error_code': error_code
                }
            return {
                'success': False,
                'error': str(e),
                'error_code': error_code
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Authentication failed: {str(e)}',
                'error_code': 'UnknownError'
            }

    def confirm_sign_up(self, email, confirmation_code):
        """Confirm user email in Cognito"""
        try:
            self.client.confirm_sign_up(
                ClientId=self.client_id,
                Username=email,
                ConfirmationCode=confirmation_code,
            )
            return {
                'success': True,
                'message': 'Email confirmed successfully'
            }
        except ClientError as e:
            return {
                'success': False,
                'error': str(e),
                'error_code': e.response['Error']['Code']
            }

    def resend_confirmation_code(self, email):
        """Resend confirmation code to user email"""
        try:
            self.client.resend_confirmation_code(
                ClientId=self.client_id,
                Username=email,
            )
            return {
                'success': True,
                'message': 'Confirmation code resent'
            }
        except ClientError as e:
            return {
                'success': False,
                'error': str(e),
                'error_code': e.response['Error']['Code']
            }

    def change_password(self, email, old_password, new_password):
        """Change user password"""
        try:
            # First authenticate to get access token
            auth_response = self.client.initiate_auth(
                ClientId=self.client_id,
                AuthFlow='USER_PASSWORD_AUTH',
                AuthParameters={
                    'USERNAME': email,
                    'PASSWORD': old_password,
                }
            )

            access_token = auth_response['AuthenticationResult']['AccessToken']

            # Change password
            self.client.change_password(
                PreviousPassword=old_password,
                ProposedPassword=new_password,
                AccessToken=access_token,
            )

            return {
                'success': True,
                'message': 'Password changed successfully'
            }
        except ClientError as e:
            return {
                'success': False,
                'error': str(e),
                'error_code': e.response['Error']['Code']
            }

    def admin_set_user_password(self, email, password, permanent=True):
        """Admin endpoint to set user password (for testing/setup)"""
        try:
            self.client.admin_set_user_password(
                UserPoolId=self.user_pool_id,
                Username=email,
                Password=password,
                Permanent=permanent,
            )
            return {
                'success': True,
                'message': 'Password set successfully'
            }
        except ClientError as e:
            return {
                'success': False,
                'error': str(e),
                'error_code': e.response['Error']['Code']
            }

    def admin_confirm_sign_up(self, email):
        """Admin endpoint to confirm user without email verification"""
        try:
            self.client.admin_confirm_sign_up(
                UserPoolId=self.user_pool_id,
                Username=email,
            )
            return {
                'success': True,
                'message': 'User confirmed successfully'
            }
        except ClientError as e:
            return {
                'success': False,
                'error': str(e),
                'error_code': e.response['Error']['Code']
            }
