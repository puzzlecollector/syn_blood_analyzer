from django.urls import path
from django.contrib.auth import views as auth_views
from . import views

app_name = 'common'

urlpatterns = [
    # path('login/', auth_views.LoginView.as_view(template_name="common/login.html"), name='login'),
    path('logout/', auth_views.LogoutView.as_view(), name='logout'),
    path('signup/', views.signup, name='signup'),
    path('login/', views.custom_login, name='login'),
    path('api/register', views.register_user, name='register_user'),
    path('api/login/', views.login_view, name='api-login'),
    path('api/set_pin/', views.set_pin, name='set-pin'),
    path('api/verify_pin/', views.verify_pin, name='verify-pin'),

]