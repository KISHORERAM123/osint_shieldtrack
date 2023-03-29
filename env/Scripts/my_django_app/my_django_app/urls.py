
from django .contrib import admin
from django.urls import path
from osint import views
urlpatterns = [
    path('', views.generate_report, name='generate_report'),
]

