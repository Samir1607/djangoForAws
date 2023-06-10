from django.db import IntegrityError
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout


class RegisterUser(APIView):
    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")

        if not username or not password:
            return Response(
                {"error": "Please check username and password again if not filled"},
                status=400,
            )

        try:
            user = User.objects.create_user(username=username, password=password)
        except IntegrityError:
            return Response({"error": "Username already exists."}, status=400)
        return Response({"message": "User Created Successfully....!!!"}, status=201)


class LoginUser(APIView):
    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")

        user = authenticate(username=username, password=password)

        if user is None:
            return Response({"error": "Invalid credentials."}, status=401)
        login(request, user)
        return Response({"message": "User logged in successfully...!"}, status=200)


class LogoutUser(APIView):
    def post(self, request):
        logout(request)
        return Response({"message": "User logged out successfully...!"}, status=200)
