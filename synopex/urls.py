from django.urls import path

from . import views

app_name = "synopex"

urlpatterns = [
    path('', views.index, name="index"),
    path('radar_chart_test/', views.chart_example, name="radar_chart_example"),
]