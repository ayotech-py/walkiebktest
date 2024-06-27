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
import pusher
import json
from cloudinary.uploader import upload
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator


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

pusher_client = pusher.Pusher(
  app_id="1823396",
  key="c28e46f783880b24243a",
  secret="68165cd6b3265ca8b0c1",
  cluster="sa1",
  ssl=True
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
    def get(self, request):
        #user = request.user
        keyword = request.GET["search"]
        try:
            search_user = UserModel.objects.get(username=keyword)
            search_user = UserSerializer(search_user)
            return Response({"search_user": search_user.data}, status=200)
        except UserModel.DoesNotExist:
            return Response({"message": "User with the above username does not exist"}, status=400)
        
class ProfileImageView(APIView):
    authentication_classes = [Authentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        data = request.data
        userdata = UserModel.objects.get(user=user.id)
        userdata.profile_image = data['file']
        userdata.save()

        user_contact_list = PairModel.objects.filter(Q(sender=userdata) | Q(receiver=userdata))
        
        serialized_user = UserSerializer(userdata)
        serialized_contact = PairSerializer(user_contact_list, many=True)

        context = {
            "user": serialized_user.data,
            "contact_list": serialized_contact.data
        }

        context['user']["user_id"] = user.id,

        return Response({"userData": context}, status=200)

def get_user_data(id):
    receiver_user = UserModel.objects.get(id=id)
    receiver_contact_list = PairModel.objects.filter(Q(sender=receiver_user) | Q(receiver=receiver_user))
    serialized_receiver_user = UserSerializer(receiver_user)
    serialized_receiver_contact_list = PairSerializer(receiver_contact_list, many=True)

    receiver_context = {
        "user": serialized_receiver_user.data,
        "contact_list": serialized_receiver_contact_list.data
    }

    return(receiver_context)

def get_online_users(channel_name):
    response = pusher_client.channels_info([channel_name], info=['user_count', 'subscription_count'])
    users = pusher_client.channel_users(channel_name)
    return {
        'status': 'success',
        'users': users['users'],
        'user_count': response['channels'][channel_name]['user_count'],
        'subscription_count': response['channels'][channel_name]['subscription_count']
    }

class PairViewset(ModelViewSet):
    authentication_classes = [Authentication]
    permission_classes = [IsAuthenticated]

    queryset = PairModel.objects.all()
    serializer_class = PairSerializer

    def create(self, request, *args, **kwargs):
        user = request.user
        user_data = UserModel.objects.get(user=user.id)
        keyword = request.GET["add_user"]
        contact_user = UserModel.objects.get(username=keyword)
        sender_user = UserModel.objects.get(user=user)

        check_pair = PairModel.objects.filter(sender=sender_user, receiver=contact_user).exists()
        
        if not check_pair:
            PairModel.objects.create(sender=sender_user, receiver=contact_user).save()
            user_contact_list = PairModel.objects.filter(Q(sender=user_data) | Q(receiver=user_data))
            serialized_user = UserSerializer(user_data)
            serialized_contact = PairSerializer(user_contact_list, many=True)
            receiver_user_data = get_user_data(contact_user.id)

            pusher_client.trigger(f'private-user_{contact_user.id}', 'friend-request', {
                'from': sender_user.username,
                'message': 'You have a new friend request!',
                "userData": receiver_user_data
            })

            context = {
                "user": serialized_user.data,
                "contact_list": serialized_contact.data
            }

            context['user']["user_id"] = user.id,

            return Response({"userData": context}, status=200)
        return Response({"message": "Pair already added"}, status=400)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        if getattr(instance, '_prefetched_objects_cache', None):
            instance._prefetched_objects_cache = {}

        # Trigger Pusher event
        pair_id = kwargs.get('pk')

        sender_id = PairModel.objects.get(id=pair_id).sender.id

        print(PairModel.objects.get(id=pair_id).sender.id, PairModel.objects.get(id=pair_id).sender)

        pusher_client.trigger(f'private-user_{sender_id}', 'accept-request', {
            'message': 'Friend request accepted',
            'data': serializer.data
        })

        return Response(serializer.data)

    
class PusherAuthView(APIView):
    authentication_classes = [Authentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):        
        pusher_client = pusher.Pusher(
            app_id="1823396",
            key="c28e46f783880b24243a",
            secret='68165cd6b3265ca8b0c1',
            cluster="sa1",
            ssl=True
        )

        socket_id = request.data.get('socket_id')
        channel_name = request.data.get('channel_name')
        presence_data = {
            'user_id': request.user.id,
            'user_info': {
                'name': request.user.username,
            }
        }
        auth = pusher_client.authenticate(
            channel=channel_name,
            socket_id=socket_id,
            custom_data=presence_data
        )

        return Response(auth)

def str_to_bool(value):
    return value.lower() in ['true', '1', 't', 'y', 'yes']

@method_decorator(csrf_exempt, name='dispatch')
class RecordViewset(ModelViewSet):
    authentication_classes = [Authentication]
    permission_classes = [IsAuthenticated]

    queryset = RecordModel.objects.all()
    serializer_class = RecordSerializer

    def create(self, request, *args, **kwargs):
        user = request.user
        file_obj = request.data['file']
        pair_id = request.data.get('pair_id')
        delivered = request.data.get('delivered')
        user_data = UserModel.objects.get(user=user.id)

        pair = PairModel.objects.get(id=pair_id)

        upload_result = upload(
            file_obj,
            resource_type="auto"
        )
        file_url = upload_result['url']

        record = RecordModel.objects.create(pair=pair, sender=user_data, audio_file=file_url, delivered=str_to_bool(delivered))
        record.save()

        pusher_client.trigger(f'presence-chat_{pair_id}', 'presence-chat-audio', {
                'id': pair_id,
                'channel_name': f"presence-chat_{pair_id}",
                'content': file_url,
                'sender': UserSerializer(user_data).data,
                'created_at': RecordSerializer(record).data['created_at']
            })
        
        return Response({"file_url": file_url}, status=200)


class checkDelivered(APIView):
    authentication_classes = [Authentication]
    permission_classes = [IsAuthenticated]

    serializer_class = RecordSerializer

    def get(self, request):
        user = request.user
        undelivered = RecordModel.objects.filter(delivered=False)
        falseStatuses = PairModel.objects.filter(status=False)
        falseAccepted = PairModel.objects.filter(Q(status=True) & Q(accepted=False))
        for obj in undelivered:
            if (obj.pair.receiver.user == user and obj.sender.email != user.email) or (obj.pair.sender.user == user and obj.sender.email != user.email):
                obj_d = RecordSerializer(obj)
                obj_d = obj_d.data
                pusher_client.trigger(f"presence-chat_{obj_d['pair']}", 'presence-chat-audio', {
                    'id': obj_d['pair'],
                    'channel_name': f"presence-chat_{obj_d['pair']}",
                    'content': obj_d['audio_file'],
                    'sender': obj_d['sender'],
                    'created_at': obj_d['created_at']
                })
                obj.delivered = True
                obj.save()

        for obj in falseStatuses:
            if obj.receiver.user.email == user.email:
                receiver_user_data = get_user_data(obj.receiver.id)
                pusher_client.trigger(f'private-user_{obj.receiver.id}', 'friend-request', {
                    'from': obj.sender.username,
                    'message': 'You have a new friend request!',
                    "userData": receiver_user_data
                })

        for obj in falseAccepted:
            if obj.sender.user.email == user.email:
                pair = PairModel.objects.get(id=obj.id)
                sender_id = pair.sender.id
                
                pair.accepted = True
                pair.save()
                
                pusher_client.trigger(f'private-user_{sender_id}', 'accept-request', {
                    'message': 'PairModel updated',
                    'data': PairSerializer(pair).data
                })

        return Response({"message": "All Messsages delivered"}, status=200)