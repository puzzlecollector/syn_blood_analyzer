from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User

class UserForm(UserCreationForm):
    email = forms.EmailField(label="이메일")
    birth_date = forms.DateField(label="생년월일",
                                 widget=forms.DateInput(attrs={'type': 'text', 'class': 'datepicker'}), required=True)
    gender = forms.ChoiceField(label="성별", choices=[('M', '남성'), ('F', '여성')])
    height = forms.IntegerField(label="신장 (cm)")
    weight = forms.IntegerField(label="체중 (kg)")
    body_type = forms.ChoiceField(
        label="당신의 현재 체형은 아래 중 어떤 체형에 가장 가깝습니까?",
        choices=[
            ('muscular', '근육형'),
            ('normal', '일반형'),
            ('abdominal_obesity', '복부 비만형'),
            ('overweight', '과체중형'),
            ('obese', '비만형')
        ],
        widget=forms.RadioSelect
    )

    class Meta:
        model = User
        fields = ("username", "email", "birth_date", "gender", "height", "weight", "body_type")
