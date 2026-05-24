from rest_framework.authentication import TokenAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth import get_user_model
import jwt
import json
import base64

User = get_user_model()


class CognitoTokenAuthentication(TokenAuthentication):
    """
    Custom authentication class that validates Cognito JWT tokens.
    Tokens are verified by extracting the user info from the JWT payload
    and looking up the user in the database.
    """
    keyword = 'Bearer'

    def authenticate(self, request):
        auth_header = request.META.get('HTTP_AUTHORIZATION', '').split()

        if not auth_header or auth_header[0].lower() != self.keyword.lower():
            return None

        if len(auth_header) != 2:
            raise AuthenticationFailed('Invalid token header.')

        try:
            token = auth_header[1]
            # Decode JWT without verification (for Cognito tokens from LocalStack)
            # In production, you should verify the signature using Cognito's public key
            parts = token.split('.')
            if len(parts) != 3:
                raise AuthenticationFailed('Invalid token format.')

            # Decode payload (part 1)
            payload = parts[1]
            padding = 4 - (len(payload) % 4)
            if padding != 4:
                payload += '=' * padding

            decoded = json.loads(base64.urlsafe_b64decode(payload))

            # Look up user by email (try multiple fields)
            email = (decoded.get('email') or
                    decoded.get('cognito:username') or
                    decoded.get('username'))
            if not email:
                raise AuthenticationFailed('Token does not contain email or username.')

            user = User.objects.get(email=email)
            return (user, token)

        except User.DoesNotExist:
            raise AuthenticationFailed('User not found.')
        except Exception as e:
            raise AuthenticationFailed(f'Invalid token: {str(e)}')
