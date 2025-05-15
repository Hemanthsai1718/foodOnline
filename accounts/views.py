#from datetime import datetime
#from django.contrib.auth.tokens import default_token_generator
#from django.core.mail import message
from django.http.response import HttpResponse
from django.shortcuts import redirect, render
#from django.utils.http import urlsafe_base64_decode

#from vendor.forms import VendorForm
from .forms import UserForm
from .models import User#, UserProfile
from django.contrib import messages, auth
from .utils import detectUser#, send_verification_email
from django.contrib.auth.decorators import login_required, user_passes_test

#from django.core.exceptions import PermissionDenied
#from vendor.models import Vendor
#from django.template.defaultfilters import slugify
#from orders.models import Order
#import datetime

# Create your views here.
def registerUser(request):
    if request.user.is_authenticated:
        messages.warning(request, 'You are already logged in!')
        return redirect('dashboard')
    elif request.method == 'POST':
        form = UserForm(request.POST)
        if form.is_valid():
            # Create the user using the form
            # password = form.cleaned_data['password']
            # user = form.save(commit=False)
            # user.set_password(password)
            # user.role = User.CUSTOMER
            # user.save()

            # Create the user using create_user method
            first_name = form.cleaned_data['first_name']
            last_name = form.cleaned_data['last_name']
            username = form.cleaned_data['username']
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            user = User.objects.create_user(first_name=first_name, last_name=last_name, username=username, email=email, password=password)
            user.role = User.CUSTOMER
            user.save()

            # Send verification email
            #mail_subject = 'Please activate your account'
            #email_template = 'accounts/emails/account_verification_email.html'
            #send_verification_email(request, user, mail_subject, email_template)
            #messages.success(request, 'Your account has been registered sucessfully!')
            #return redirect('registerUser')
        else:
            print('invalid form')
            print(form.errors)
    else:
        form = UserForm()
    context = {
        'form': form,
    }
    return render(request, 'accounts/registerUser.html', context) 

def registerVendor(request):
        return render(request, 'accounts/registerUser.html')


def login(request):
    if request.user.is_authenticated:
        messages.warning(request, 'You are already logged in!')
        return redirect('myAccount')
    elif request.method == 'POST':
        email = request.POST['email']
        password = request.POST['password']

        user = auth.authenticate(email=email, password=password)

        if user is not None:
            auth.login(request, user)
            messages.success(request, 'You are now logged in.')
            return redirect('myAccount')
        else:
            messages.error(request, 'Invalid login credentials')
            return redirect('login')
    return render(request, 'accounts/login.html')

def logout(request):
    auth.logout(request)
    messages.info(request, 'You are logged out.')
    return redirect('login')


@login_required(login_url='login')
def myAccount(request):
    user = request.user
    redirectUrl = detectUser(user)
    return redirect(redirectUrl)

def custDashboard(request):
    return render(request, 'accounts/custDashboard.html')

def vendorDashboard(request):
    return render(request, 'accounts/vendorDashboard.html')

