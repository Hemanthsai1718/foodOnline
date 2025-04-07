from django.shortcuts import render
from django.http import HttpResponse

def home(request):
    vendors = Vendor.objects
    return render(request, 'home.html')