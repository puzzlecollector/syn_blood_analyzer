from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from common.forms import UserForm
from common.models import Profile
import pytz

from django.urls import reverse
from rest_framework_jwt.settings import api_settings
from django.contrib.auth.forms import AuthenticationForm

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

