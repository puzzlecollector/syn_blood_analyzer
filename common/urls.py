from django.urls import path
from django.contrib.auth import views as auth_views
from . import views

app_name = 'common'

urlpatterns = [
    # path('login/', auth_views.LoginView.as_view(template_name="common/login.html"), name='login'),
    path('logout', auth_views.LogoutView.as_view(), name='logout'),
    path('signup', views.signup, name='signup'),
    path('login', views.custom_login, name='login'),
    path('api/register', views.register_user, name='register_user'),
    path('api/login', views.login_view, name='api-login'),
    path('api/setpin', views.set_pin, name='set-pin'),
    path('api/verifypin', views.verify_pin, name='verify-pin'),
    path('api/getprofile', views.get_profile, name='get_profile'),
    path('radarchart', views.radar_chart, name='radarchart'),
    path('walkingchart', views.walking_chart, name='walkingchart'),
    path('boxchart', views.boxchart, name='boxchart'),
    path('bpchart', views.bp_chart, name='bpchart'),
    path('bschart', views.bs_chart, name='bschart'),
    path('api/recordhealthdata', views.record_health_data, name='record_health_data'),
    path('api/fetchhealthdatahistory', views.fetch_health_data_history, name='fetch_health_data_history'),
]