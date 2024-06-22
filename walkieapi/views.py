from django.shortcuts import render
from .models import *
from .serializers import *
from rest_framework.viewsets import ModelViewSet
from rest_framework.views import APIView
from rest_framework.response import Response
import base64
from django.conf import settings
import jwt
from datetime import datetime, timedelta
import random
import string
from django.contrib.auth import authenticate
from django.contrib.auth.hashers import make_password
from .authentication import Authentication
from rest_framework.permissions import IsAuthenticated
from django.db.models import Q


def get_rand(length):
    return "".join(random.choices(string.ascii_uppercase + string.digits, k=length))


def get_access_token(payload):
    return jwt.encode(
        {"exp": datetime.now() + timedelta(minutes=10000), **payload},
        settings.SECRET_KEY,
        algorithm="HS256",
    )


def get_refresh_token():
    return jwt.encode(
        {"exp": datetime.now() + timedelta(days=365), "data": get_rand(10)},
        settings.SECRET_KEY,
        algorithm="HS256",
    )

class UserViewset(ModelViewSet):
    """ authentication_classes = [ApiKeyAuthentication] """

    queryset = UserModel.objects.all()
    serializer_class = UserSerializer

    def get_authenticators(self):
        if self.request.method == 'PUT':
            return [Authentication()]
        return []

    def get_permissions(self):
        if self.request.method == 'PUT':
            return [IsAuthenticated()]
        return []

    def create(self, request, *args, **kwargs):
        data = request.data

        if User.objects.filter(username=data["username"]).exists():
            return Response({"message": "Username already exist"}, status=400)
        if User.objects.filter(email=data["email"]).exists():
            return Response({"message": "Email already exist"}, status=400)
        try:
            user = User.objects.create(
                username=data["username"],
                email=data["email"],
                password=make_password(data["password"])
            )
            UserModel.objects.create(username=data['username'], email=data['email'], user=user)
            user.save()
            Jwt.objects.filter(user_id=user.pk).delete()

            access = get_access_token({"user_id": user.id})
            refresh = get_refresh_token()

            Jwt.objects.create(user_id=user.id, access=access, refresh=refresh)

            userdata = UserModel.objects.get(user=user.id)
            serialized_user = UserSerializer(userdata)

            context = {
                "user": serialized_user.data,
            }

            context['user']["user_id"] = user.id,

            return Response(
                {   
                    "tokens": {
                        "accessToken": access,
                        "refreshToken": refresh
                    },
                    "username": user.username,
                    "message": "Your account have been successfully created!",
                    "userData": context
                }, status=200
            )
        except Exception as e:
            print(e)
            return Response({"message": "An error occurred"}, status=400)
        
    def update(self, request, *args, **kwargs):
        user = request.user
        data = request.data

        try:
            user_data = UserModel.objects.get(user=user.id)
            user_data.user.email = data["email"]
            user_data.user.username = data["username"]

            user_data.fullname = data["fullname"]
            user_data.username = data["username"]
            user_data.email = data["email"]
            user_data.phone = data["phone"]
            user_data.gender = data["gender"]
            user_data.address = data["address"]

            user_data.user.save()
            user_data.save()

            user_contact_list = PairModel.objects.filter(Q(sender=user_data) | Q(receiver=user_data))

            serialized_user = UserSerializer(user_data)
            serialized_contact = PairSerializer(user_contact_list, many=True)

            context = {
                "user": serialized_user.data,
                "contact_list": serialized_contact.data
            }

            context['user']["user_id"] = user.id,

            jwt_user = Jwt.objects.get(user=user.id)
            access = jwt_user.access
            refresh = jwt_user.refresh

            return Response(
                {   
                    "tokens": {
                        "accessToken": access,
                        "refreshToken": refresh
                    },
                    "username": user.username,
                    "message": "Profile sucessfully updated!",
                    "userData": context
                }, status=200
            )
        except Exception as e:
            return Response({"message": "An error occured"}, status=400)



class UserLoginView(APIView):
    """ authentication_classes = [ApiKeyAuthentication] """

    serializer_class = UserLoginSerializer

    def post(self, request):
        data = request.data
        serializer = self.serializer_class(data=data)
        try:
            serializer.is_valid(raise_exception=True)
        except Exception as e:
            return Response({"message": "invalid email address"}, status=400)
        user = authenticate(
            username=serializer.validated_data["username"],
            password=serializer.validated_data["password"],
        )

        if not user:
            try:
                get_username = User.objects.get(email=data["username"]).username
                user = authenticate(
                    username=get_username,
                    password=serializer.validated_data["password"],
                )
                if not user:
                    return Response({"message": "invalid email or password"}, status=400)
            except Exception as e:
                return Response({"message": "invalid email or password"}, status=400)

        check_user = User.objects.filter(id=user.id).exists()

        if not check_user:
            return Response({"message": "invalid emall or password"}, status=400)

        Jwt.objects.filter(user_id=user.pk).delete()

        access = get_access_token({"user_id": user.id})
        refresh = get_refresh_token()

        Jwt.objects.create(user_id=user.id, access=access, refresh=refresh)

        userdata = UserModel.objects.get(user=user.id)
        user_contact_list = PairModel.objects.filter(Q(sender=userdata) | Q(receiver=userdata))

        serialized_user = UserSerializer(userdata)
        serialized_contact = PairSerializer(user_contact_list, many=True)

        context = {
            "user": serialized_user.data,
            "contact_list": serialized_contact.data
        }

        context['user']["user_id"] = user.id,

        return Response(
            {   
                "tokens": {
                    "accessToken": access,
                    "refreshToken": refresh
                },
                "username": user.username,
                "message": "Login successful!",
                "userData": context
            }, status=200
        )
    
class ContactView(APIView):
    authentication_classes = [Authentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        keyword = request.GET["search"]
        try:
            search_user = UserModel.objects.get(username=keyword)
            search_user = UserSerializer(search_user)
            return Response({"search_user": search_user.data}, status=200)
        except UserModel.DoesNotExist:
            return Response({"message": "User with the above username does not exist"}, status=400)

    """ def post(self, request):
        user = request.user
        keyword = request.GET["add_user"]
        user_data = UserModel.objects.get(user=user.id)
        contact = user_data.contact_list
        list_obj = ast.literal_eval(contact)
        for obj in list_obj:
            if keyword == obj["username"]:
                return Response({"message": "Contact already added"}, status=404)
            else:
                continue
        contact_user = UserModel.objects.get(username=keyword)
        list_obj.append(UserSerializer(contact_user).data)
        user_data.contact_list = str(list_obj)
        user_data.save()
        return Response({"contacts": ""}, status=200) """
    

class PairViewset(ModelViewSet):
    authentication_classes = [Authentication]
    permission_classes = [IsAuthenticated]

    queryset = UserModel.objects.all()
    serializer_class = UserSerializer

    def create(self, request, *args, **kwargs):
        user = request.user
        user_data = UserModel.objects.get(user=user.id)
        keyword = request.GET["add_user"]
        contact_user = UserModel.objects.get(username=keyword)
        sender_user = UserModel.objects.get(user=user)

        check_pair = PairModel.objects.filter(sender=sender_user, receiver=contact_user).exists()
        
        if not check_pair:
            PairModel.objects.create(sender=sender_user, receiver=contact_user)
            return Response({"message": "done"}, status=200)
        return Response({"message": "Pair already added"}, status=400)
        

