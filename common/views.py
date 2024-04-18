from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from common.forms import UserForm
from common.models import Profile
import pytz

from django.urls import reverse
from rest_framework_jwt.settings import api_settings
from django.contrib.auth.forms import AuthenticationForm

from django.contrib.auth.models import User
from .models import UserProfile, UserPin
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from django.http import JsonResponse
from rest_framework_simplejwt.authentication import JWTAuthentication

from rest_framework_simplejwt.tokens import UntypedToken
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.state import token_backend

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated


jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER

def signup(request):
    if request.method == "POST":
        form = UserForm(request.POST)
        if form.is_valid():
            user = form.save()  # Save the User object and get the instance
            username = form.cleaned_data.get("username")
            raw_password = form.cleaned_data.get("password1")
            user = authenticate(username=username, password=raw_password)
            login(request, user)

            # Now, create or update the Profile
            profile, created = Profile.objects.get_or_create(user=user)
            profile.height = form.cleaned_data.get('height')
            profile.weight = form.cleaned_data.get('weight')
            # Add additional fields as necessary
            profile.save()

            return redirect("synopex:index")
    else:
        form = UserForm()
    return render(request, "common/signup.html", {"form": form})


def custom_login(request):
    if request.method == "POST":
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
                jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
                payload = jwt_payload_handler(user)
                token = jwt_encode_handler(payload)
                return redirect(f'/synopex?jwt={token}')
            else:
                # If authentication fails, you can add an error message to the form
                form.add_error(None, 'Username or password is incorrect')
    else:
        form = AuthenticationForm()
    return render(request, "common/login.html", {'form': form})


@api_view(['POST'])
def register_user(request):
    username = request.data.get('username')
    email = request.data.get('email')
    password = request.data.get('password')
    birthdate = request.data.get('birthdate')
    gender = request.data.get('gender')
    height = request.data.get('height')
    weight = request.data.get('weight')
    body_type = request.data.get('body_type')

    if User.objects.filter(username=username).exists():
        return Response({'error': '이미 존재하는 유저입니다.'}, status=status.HTTP_400_BAD_REQUEST)
    if User.objects.filter(email=email).exists():
        return Response({'error': '이미 존재하는 이메일입니다.'}, status=status.HTTP_400_BAD_REQUEST)

    user = User.objects.create_user(username=username, email=email, password=password)
    UserProfile.objects.create(user=user, birthdate=birthdate, gender=gender, height=height, weight=weight, body_type=body_type)

    refresh = RefreshToken.for_user(user)
    return Response({'jwt_token': str(refresh.access_token)}, status=status.HTTP_201_CREATED)


def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(username=username, password=password)

        if user is not None:
            # User authenticated, generate token
            refresh = RefreshToken.for_user(user)
            return JsonResponse({
                'token': str(refresh.access_token),
            })
        else:
            # Attempt to find a user matching the username or email to provide a more specific error message
            from django.contrib.auth.models import User
            if User.objects.filter(username=username).exists() or User.objects.filter(email=username).exists():
                return JsonResponse({'message': '비밀번호가 일치하지 않습니다.'}, status=400)
            else:
                return JsonResponse({'message': '사용자가 존재하지 않습니다.'}, status=404)

    return JsonResponse({'message': '잘못된 요청입니다.'}, status=400)

@api_view(['POST'])
def set_pin(request):
    token = request.data.get('token')
    if not token:
        return Response({'error': 'Token is required.'}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        # Decode the token to get the user
        decoded_data = token_backend.decode(token, verify=True)
        user_id = decoded_data['user_id']
        user = User.objects.get(id=user_id)
    except (TokenError, User.DoesNotExist):
        return Response({'error': 'Invalid or expired token.'}, status=status.HTTP_401_UNAUTHORIZED)

    pin = request.data.get('pin')
    if not pin:
        return Response({'error': 'PIN is required.'}, status=status.HTTP_400_BAD_REQUEST)

    # Set or update the PIN
    UserPin.objects.update_or_create(user=user, defaults={'pin': pin})
    return Response({'message': 'PIN set successfully.'}, status=status.HTTP_200_OK)

@api_view(['POST'])
def verify_pin(request):
    token = request.data.get('token')
    if not token:
        return Response({'error': 'Token is required.'}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        # Decode the token to get the user
        decoded_data = token_backend.decode(token, verify=True)
        user_id = decoded_data['user_id']
        user = User.objects.get(id=user_id)
    except (TokenError, User.DoesNotExist):
        return Response({'error': 'Invalid or expired token.'}, status=status.HTTP_401_UNAUTHORIZED)

    pin = request.data.get('pin')
    if not pin:
        return Response({'error': 'PIN is required.'}, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        user_pin = UserPin.objects.get(user=user)
        if user_pin.pin == pin:
            return Response({'message': 'PIN verified successfully.'}, status=status.HTTP_200_OK)
        else:
            return Response({'message': 'PIN does not match.'}, status=status.HTTP_400_BAD_REQUEST)
    
    except UserPin.DoesNotExist:
        return Response({'message': 'PIN not set for user.'}, status=status.HTTP_404_NOT_FOUND)
