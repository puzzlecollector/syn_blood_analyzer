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
import json
import datetime

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
    print("!!!!========================= register_user   request   ", request.data)
    username = request.data.get('username')
    email = request.data.get('email')
    password = request.data.get('password')
    birthdate = request.data.get('birthdate')
    gender = request.data.get('gender')
    height = request.data.get('height')
    weight = request.data.get('weight')
    body_type = request.data.get('body_type')
    name = request.data.get('name')

    if User.objects.filter(username=username).exists():
        return Response({'error': '이미 존재하는 유저입니다.'}, status=status.HTTP_400_BAD_REQUEST)
    if User.objects.filter(email=email).exists():
        return Response({'error': '이미 존재하는 이메일입니다.'}, status=status.HTTP_400_BAD_REQUEST)

    user = User.objects.create_user(username=username, email=email, password=password, name=name)
    UserProfile.objects.create(user=user, birthdate=birthdate, gender=gender, height=height, weight=weight, body_type=body_type)

    refresh = RefreshToken.for_user(user)
    return Response({'jwt_token': str(refresh.access_token)}, status=status.HTTP_201_CREATED)

@api_view(['POST'])
def login_view(request):
    username = request.data.get('username')
    password = request.data.get('password')
    user = authenticate(username=username, password=password)
    user2 = authenticate(email=username, password=password)

    if user or user2:
        # User authenticated, generate token
        refresh = ''
        if user:
            refresh = RefreshToken.for_user(user)
        else: 
            refresh = RefreshToken.for_user(user2)
        return JsonResponse({
            'token': str(refresh.access_token),
        }, status=200)
    else:
        # If authentication fails, return a generic error message
        return JsonResponse({
            'message': '로그인 정보를 확인 해주세요.'
        }, status=400)

    # This line is now redundant and should not be reached
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

@api_view(['POST'])
def get_profile(request):
    token = request.data.get('token')
    if not token:
        return JsonResponse({'error': 'Token is required.'}, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        # Decode the token to get the user
        decoded_data = token_backend.decode(token, verify=True)
        user_id = decoded_data['user_id']
        user = User.objects.get(id=user_id)
    except (TokenError, User.DoesNotExist):
        return JsonResponse({'error': 'Invalid or expired token.'}, status=status.HTTP_401_UNAUTHORIZED)

    # Assuming UserProfile contains birthdate and related profile info
    try:
        profile = UserProfile.objects.get(user=user)
        # Calculate age
        today = datetime.date.today()
        age = today.year - profile.birthdate.year - ((today.month, today.day) < (profile.birthdate.month, profile.birthdate.day))

        profile_data = {
            'name': user.name,
            'nickname': user.username,
            'birthdate': profile.birthdate.strftime('%Y-%m-%d'),
            'age': age,
            'height': profile.height,
            'weight': profile.weight,
            'gender': profile.gender,
        }
        return JsonResponse(profile_data, safe=False, status=status.HTTP_200_OK)
    except UserProfile.DoesNotExist:
        return JsonResponse({'error': 'UserProfile does not exist.'}, status=status.HTTP_404_NOT_FOUND)
    
def radar_chart(request):
    # Extract query parameters
    wbc = request.GET.get('WBC', 0)
    rbc = request.GET.get('RBC', 0)
    plt = request.GET.get('PLT', 0)
    hb = request.GET.get('Hb', 0)
    hct = request.GET.get('Hct', 0)

    # Data for the radar chart
    data = {
        'WBC': wbc,
        'RBC': rbc,
        'PLT': plt,
        'Hb': hb,
        'Hct': hct,
    }

    # Render the response, passing data to the template
    return render(request, 'common/radar_chart.html', {'data': json.dumps(data)})