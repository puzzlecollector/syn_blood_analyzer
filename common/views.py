from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from common.forms import UserForm
from common.models import Profile
import pytz

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
