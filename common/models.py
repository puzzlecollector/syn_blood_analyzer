from django.db import models
from django.contrib.auth.models import User

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