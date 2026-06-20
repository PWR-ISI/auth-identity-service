import json
import logging
import os
import uuid

import boto3
from rest_framework import viewsets, status
from rest_framework.decorators import action, api_view, permission_classes, parser_classes
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User, UserProfile, AuditLog
from .serializers import (
    UserSerializer, UserDetailSerializer, CreateUserSerializer,
    LoginSerializer, TokenSerializer, AuditLogSerializer, UserProfileSerializer
)
from .cognito_service import CognitoService
from .permissions import IsAdmin, IsAdminOrStaff
from drf_spectacular.utils import extend_schema, OpenApiResponse
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

logger = logging.getLogger(__name__)


def _client_ip(request):
    xff = request.META.get('HTTP_X_FORWARDED_FOR')
    return xff.split(',')[0] if xff else request.META.get('REMOTE_ADDR')


def _upload_avatar(photo, user):
    """Upload a profile photo to S3 and store its URL on the user's profile.
    Best-effort: a failed upload must not block account creation."""
    try:
        bucket = os.getenv('USER_AVATARS_BUCKET', 'user-avatars')
        endpoint = os.getenv('AWS_ENDPOINT_URL') or None
        region = os.getenv('AWS_REGION', 'us-east-1')
        s3 = boto3.client(
            's3', endpoint_url=endpoint, region_name=region,
            aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID', 'test'),
            aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY', 'test'),
        )
        try:
            s3.create_bucket(Bucket=bucket)
        except Exception:
            pass
        try:
            s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
                    "Resource": f"arn:aws:s3:::{bucket}/*",
                }],
            }))
        except Exception:
            pass
        key = f"{user.cognito_sub or user.id}/{uuid.uuid4().hex}_{photo.name}"
        s3.put_object(Bucket=bucket, Key=key, Body=photo.read(),
                      ContentType=getattr(photo, 'content_type', None) or 'application/octet-stream')
        # Must be browser-reachable: never the internal docker hostname ('localstack').
        public = (os.getenv('S3_PUBLIC_URL') or 'http://localhost:4566').replace('localstack', 'localhost')
        url = f"{public}/{bucket}/{key}"
        profile, _ = UserProfile.objects.get_or_create(user=user)
        profile.avatar = url
        profile.save(update_fields=['avatar'])
        return url
    except Exception as exc:  # noqa: BLE001 - avatar is optional
        logger.warning("Avatar upload for %s failed: %s", getattr(user, 'email', '?'), exc)
        return ''


@api_view(['GET', 'OPTIONS'])
@permission_classes([AllowAny])
def health_check(request):
    if request.method == 'OPTIONS':
        return Response(status=status.HTTP_200_OK)
    return Response({'status': 'healthy'}, status=status.HTTP_200_OK)


@api_view(['OPTIONS'])
@permission_classes([AllowAny])
def options_handler(request):
    """Handle CORS preflight requests"""
    return Response(status=status.HTTP_200_OK)


class AuthViewSet(viewsets.ViewSet):
    permission_classes = [AllowAny]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cognito_service = CognitoService()

    @action(detail=False, methods=['post', 'options'])
    def login(self, request):
        if request.method == 'OPTIONS':
            return Response(status=status.HTTP_200_OK)

        email = request.data.get('email')
        password = request.data.get('password')

        if not email or not password:
            return Response(
                {'error': 'Email and password are required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Authenticate with Cognito
        result = self.cognito_service.sign_in(email, password)

        if not result['success']:
            return Response(
                {'error': result['error']},
                status=status.HTTP_401_UNAUTHORIZED
            )

        user = result['user']

        # Log the login
        AuditLog.objects.create(
            user=user,
            action='login',
            ip_address=self._get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )

        return Response({
            'access_token': result['tokens']['access_token'],
            'id_token': result['tokens']['id_token'],
            'refresh_token': result['tokens']['refresh_token'],
            'user': UserSerializer(user).data
        }, status=status.HTTP_200_OK)

    @action(detail=False, methods=['post', 'options'])
    def register(self, request):
        if request.method == 'OPTIONS':
            return Response(status=status.HTTP_200_OK)

        email = request.data.get('email')
        password = request.data.get('password')
        password_confirm = request.data.get('password_confirm')
        first_name = request.data.get('first_name')
        last_name = request.data.get('last_name')
        role = request.data.get('role', 'patient')

        # Validate input
        if not all([email, password, password_confirm, first_name, last_name]):
            return Response(
                {'error': 'All fields are required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        if password != password_confirm:
            return Response(
                {'error': 'Passwords do not match'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Try to sign up with Cognito
        result = self.cognito_service.sign_up(
            email=email,
            password=password,
            first_name=first_name,
            last_name=last_name,
            role=role
        )

        if not result['success']:
            return Response(
                {'error': result['error']},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Set permanent password for user (bypasses unconfirmed status)
        password_result = self.cognito_service.admin_set_user_password(
            email, password, permanent=True
        )
        if not password_result['success']:
            return Response(
                {'error': f'Could not set password: {password_result["error"]}'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Now sign in the user
        signin_result = self.cognito_service.sign_in(email, password)
        if not signin_result['success']:
            return Response(
                {'error': f'Authentication failed: {signin_result["error"]}'},
                status=status.HTTP_401_UNAUTHORIZED
            )

        user = signin_result['user']

        return Response({
            'access_token': signin_result['tokens']['access_token'],
            'id_token': signin_result['tokens']['id_token'],
            'refresh_token': signin_result['tokens']['refresh_token'],
            'user': UserSerializer(user).data
        }, status=status.HTTP_201_CREATED)

    @action(detail=False, methods=['post'], permission_classes=[IsAuthenticated])
    def logout(self, request):
        AuditLog.objects.create(
            user=request.user,
            action='logout',
            ip_address=self._get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
        return Response({'message': 'Logged out successfully'}, status=status.HTTP_200_OK)

    @action(detail=False, methods=['get'], permission_classes=[IsAuthenticated])
    def me(self, request):
        serializer = UserDetailSerializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=False, methods=['post'], permission_classes=[IsAuthenticated])
    def refresh_token(self, request):
        refresh = request.data.get('refresh')
        if not refresh:
            return Response({'error': 'Refresh token required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            refresh_token = RefreshToken(refresh)
            return Response({
                'token': str(refresh_token.access_token)
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def _get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    permission_classes = [IsAuthenticated]

    def get_serializer_class(self):
        if self.action == 'create':
            return CreateUserSerializer
        elif self.action == 'retrieve':
            return UserDetailSerializer
        return UserSerializer

    def get_permissions(self):
        if self.action == 'create':
            return [AllowAny()]
        return [IsAuthenticated()]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()

            if request.user.is_authenticated:
                AuditLog.objects.create(
                    user=request.user,
                    action='create_user',
                    ip_address=self._get_client_ip(request),
                    details={'created_user_id': user.id}
                )

            return Response(UserSerializer(user).data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, *args, **kwargs):
        user = self.get_object()
        AuditLog.objects.create(
            user=request.user,
            action='delete_user',
            ip_address=self._get_client_ip(request),
            details={'deleted_user_id': user.id}
        )
        return super().destroy(request, *args, **kwargs)

    @action(detail=True, methods=['get', 'put'])
    def profile(self, request, pk=None):
        user = self.get_object()
        if request.method == 'GET':
            profile, created = UserProfile.objects.get_or_create(user=user)
            serializer = UserProfileSerializer(profile)
            return Response(serializer.data)
        elif request.method == 'PUT':
            profile, created = UserProfile.objects.get_or_create(user=user)
            serializer = UserProfileSerializer(profile, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def _get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class AuditLogViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = AuditLog.objects.all()
    serializer_class = AuditLogSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        if self.request.user.role == 'admin':
            return AuditLog.objects.all()
        return AuditLog.objects.filter(user=self.request.user)


@extend_schema(
    summary='Create a staff account (admin only)',
    description='Administrator creates a Cognito + DB account for staff (e.g. a doctor) and assigns a role. '
                'Returns the new account id (cognito_sub) used as doctor_id across services.',
    responses={201: OpenApiResponse(description='Created: {user_id, id, email, first_name, last_name, role}')},
)
@api_view(['POST'])
@permission_classes([IsAdminOrStaff])
@parser_classes([MultiPartParser, FormParser, JSONParser])
def create_staff(request):
    """Admin or front-desk clerk provisions a staff/doctor/patient account in Cognito + DB.
    Accepts an optional multipart `photo` (e.g. a receptionist's avatar)."""
    data = request.data
    email = data.get('email')
    password = data.get('password')
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    role = data.get('role', 'doctor')

    missing = [f for f in ('email', 'password', 'first_name', 'last_name') if not data.get(f)]
    if missing:
        return Response({'error': f'Missing required fields: {", ".join(missing)}'},
                        status=status.HTTP_400_BAD_REQUEST)
    if role not in dict(User.ROLE_CHOICES):
        return Response({'error': f'Invalid role: {role}'}, status=status.HTTP_400_BAD_REQUEST)

    cognito = CognitoService()
    result = cognito.sign_up(email=email, password=password,
                             first_name=first_name, last_name=last_name, role=role)
    if not result['success']:
        return Response({'error': result['error']}, status=status.HTTP_400_BAD_REQUEST)

    pw = cognito.admin_set_user_password(email, password, permanent=True)
    if not pw['success']:
        return Response({'error': f'Could not set password: {pw["error"]}'},
                        status=status.HTTP_400_BAD_REQUEST)

    user = result['user']
    avatar_url = ''
    photo = request.FILES.get('photo')
    if photo:
        avatar_url = _upload_avatar(photo, user)
    AuditLog.objects.create(
        user=request.user,
        action='create_user',
        ip_address=_client_ip(request),
        user_agent=request.META.get('HTTP_USER_AGENT', ''),
        details={'created_user_id': user.id, 'email': email, 'role': role},
    )
    return Response({
        'user_id': user.cognito_sub or str(user.id),
        'id': user.id,
        'email': user.email,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'role': user.role,
        'avatar': avatar_url,
    }, status=status.HTTP_201_CREATED)
