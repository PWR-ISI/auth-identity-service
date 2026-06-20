from rest_framework import serializers
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User, UserProfile, AuditLog


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        # cognito_sub is the patient/user UUID used as patient_id across services
        # (needed e.g. so a receptionist can book a visit on behalf of a patient).
        fields = ('id', 'cognito_sub', 'email', 'first_name', 'last_name', 'role', 'phone', 'is_active', 'date_joined')
        read_only_fields = ('id', 'cognito_sub', 'date_joined')


class UserDetailSerializer(serializers.ModelSerializer):
    profile = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ('id', 'email', 'first_name', 'last_name', 'role', 'phone', 'is_active', 'date_joined', 'profile')
        read_only_fields = ('id', 'date_joined')

    def get_profile(self, obj):
        if hasattr(obj, 'profile'):
            return UserProfileSerializer(obj.profile).data
        return None


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = ('id', 'bio', 'avatar', 'specialization', 'license_number', 'facility', 'created_at', 'updated_at')
        read_only_fields = ('id', 'created_at', 'updated_at')


class CreateUserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8)
    password_confirm = serializers.CharField(write_only=True, min_length=8)

    class Meta:
        model = User
        fields = ('email', 'first_name', 'last_name', 'role', 'phone', 'password', 'password_confirm')

    def validate(self, data):
        if data.get('password') != data.get('password_confirm'):
            raise serializers.ValidationError({'password': 'Passwords do not match'})
        return data

    def create(self, validated_data):
        validated_data.pop('password_confirm')
        password = validated_data.pop('password')
        email = validated_data.get('email')
        user = User.objects.create_user(username=email, **validated_data)
        user.set_password(password)
        user.save()
        UserProfile.objects.create(user=user)
        return user


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        user = authenticate(username=data['email'], password=data['password'])
        if not user:
            raise serializers.ValidationError('Invalid credentials')
        data['user'] = user
        return data


class TokenSerializer(serializers.Serializer):
    refresh = serializers.CharField()
    access = serializers.CharField()
    user = UserSerializer(read_only=True)


class AuditLogSerializer(serializers.ModelSerializer):
    user_email = serializers.CharField(source='user.email', read_only=True)

    class Meta:
        model = AuditLog
        fields = ('id', 'user_email', 'action', 'ip_address', 'details', 'timestamp')
        read_only_fields = ('id', 'timestamp')
