
from rest_framework import serializers
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        write_only=True,
        min_length=8,
        error_messages={'min_length': 'Password must be at least 8 characters long.'}
    )

    def validate_password(self, value):
        """
        Validate that the password meets certain criteria.
        """
        if len(value) < 8:
            raise serializers.ValidationError('Password must be at least 8 characters long.')
        elif not any(char.isdigit() for char in value):
            raise serializers.ValidationError('Password must contain at least one digit.')
        elif not any(char.isupper() for char in value):
            raise serializers.ValidationError('Password must contain at least one uppercase letter.')
        return value

    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'password', 'department', 'age', 'city', 'profile_photo')
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        return user

class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)

class TokenObtainPairSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    access = serializers.CharField(read_only=True)
    refresh = serializers.CharField(read_only=True)

    def validate(self, data):
        email = data.get('email', None)
        password = data.get('password', None)

        user = User.objects.filter(email=email).first()

        if user is None or not user.check_password(password):
            raise serializers.ValidationError('Incorrect email or password.')

        refresh = RefreshToken.for_user(user)
        refresh.access_token.set_exp(lifetime=24 * 60 * 60)
        data['access'] = str(refresh.access_token)
        data['refresh'] = str(refresh)
        return data