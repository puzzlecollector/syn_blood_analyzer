from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    profile_picture = models.ImageField(upload_to="profile_pics/", blank=True, null=True)
    weight = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)
    height = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)

    @property
    def bmi(self):
        # Check if weight or height is None
        if self.weight is None or self.height is None:
            return None  # Or return a default value or message
        # BMI = weight(kg) / (height(m))^2
        height_in_meters = self.height / 100
        return self.weight / (height_in_meters ** 2)
    
class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    birthdate = models.DateField()
    gender = models.CharField(max_length=1, choices=(('M', 'Male'), ('F', 'Female')))
    height = models.IntegerField()
    weight = models.IntegerField()
    body_type = models.CharField(max_length=20, choices=(('Muscular', '근육형'), ('Normal', '일반형'), ('Abdominal obesity', '복부 비만형'), ('Overweight', '과체중형'), ('Obese', '비만형')))
    
    def __str__(self):
        return self.user.username
    
class UserPin(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    pin = models.CharField(max_length=6)

    def __str__(self):
        return f"PIN for {self.user.username}"
    
class BloodPressure(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    systolic = models.IntegerField()
    diastolic = models.IntegerField()
    datetime = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"{self.user.username} BP: {self.systolic}/{self.diastolic} at {self.datetime.strftime('%Y-%m-%d %H:%M')}"

class Walking(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    target = models.IntegerField()
    actual = models.IntegerField()
    datetime = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"{self.user.username} Target: {self.target}, Actual: {self.actual} on {self.datetime.strftime('%Y-%m-%d')}"

class BloodSugar(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    blood_sugar = models.IntegerField()
    datetime = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"{self.user.username} Blood Sugar: {self.blood_sugar} at {self.datetime.strftime('%Y-%m-%d %H:%M')}"