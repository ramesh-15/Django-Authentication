
from rest_framework import generics, permissions,status
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.response import Response
from .models import CustomUser
from .serializers import UserSerializer, TokenObtainPairSerializer,ChangePasswordSerializer
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .models import CustomUser
from .serializers import UserSerializer
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenObtainPairView
from .models import CustomUser
from .serializers import UserSerializer, TokenObtainPairSerializer



class UserRegistrationView(generics.CreateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = UserSerializer
    permission_classes = [AllowAny]

    def create(self, request, *args, **kwargs):
        response = super().create(request, *args, **kwargs)
        
        # Get the user data from the created instance
        user_data = UserSerializer(instance=response.data).data

        # Add the user details to the response
        response.data = {
            'message': 'Registration successful',
            
        }
        
        response.status_code = status.HTTP_201_CREATED
        return response

class UserLoginView(TokenObtainPairView):
    
    serializer_class = TokenObtainPairSerializer



class UserProfileUpdateView(generics.RetrieveUpdateAPIView):
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        return self.request.user

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        # Create a new serializer instance for the updated user data
        updated_user_data = UserSerializer(instance).data

        # Add the success message and user details to the response
        response_data = {
            'message': 'Profile updated successfully',
            'user': updated_user_data
        }

        return Response(response_data)

    def get_response(self, data):
        response = super().get_response(data)
        return response
    
class UserListView(generics.ListAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated] 



class ChangePasswordView(generics.UpdateAPIView):
    serializer_class = ChangePasswordSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user

    def update(self, request, *args, **kwargs):
        user = self.get_object()
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            # Check if the old password is correct
            if not user.check_password(serializer.validated_data['old_password']):
                return Response({'detail': 'Invalid old password.'}, status=status.HTTP_400_BAD_REQUEST)

            # Set the new password
            user.set_password(serializer.validated_data['new_password'])
            user.save()
            
            return Response({'detail': 'Password updated successfully.'}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)