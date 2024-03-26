from django.urls import path

from . import views

app_name = "synopex"

urlpatterns = [
    path('', views.chart_example, name="index"),
    path('radar_chart_test/', views.chart_example, name="radar_chart_example"),
    path('blood_test_detailed/', views.blood_analysis_detail, name="blood_test_result"),
    path("blood_test_list/", views.blood_test_list, name="blood_test_list"),
]