from django.shortcuts import render, redirect
from django.http import HttpResponse
from common.models import Profile
from django.contrib.auth.decorators import login_required
from django.utils import timezone
import datetime
import pytz

def index(request):
    data = {
        'labels': ["WBC", "Hct", "Hb", "RBC", "PLT"],
        'data': [5.0, 4.3, 180, 14.0, 42.0],  # Example values
    }
    # Initialize profile as None
    profile = None
    # Check if user is authenticated
    if request.user.is_authenticated:
        profile = Profile.objects.filter(user=request.user).first()

    # Ensure the use of 'Asia/Seoul' timezone
    seoul_timezone = pytz.timezone('Asia/Seoul')
    now = timezone.now().astimezone(seoul_timezone)

    # Format the date and time in Korean
    formatted_now = now.strftime('%Y년 %m월 %d일 %H시 %M분')

    # Pass both chart data and profile to the template
    context = {
        'chart_data': data,
        'profile': profile,
        'current_datetime': formatted_now,
    }

    return render(request, "my_template.html", context)


def chart_example(request):
    return render(request, "custom_radar_chart.html", {})