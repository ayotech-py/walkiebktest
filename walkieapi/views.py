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
from google.oauth2 import service_account
from google.cloud import speech_v2
from google.cloud.speech_v2.types import cloud_speech
from rest_framework.parsers import MultiPartParser, FormParser
import subprocess
import os
from gtts import gTTS
from google.cloud import texttospeech
import html
import requests
import random
from django.core.mail import send_mail
from django.conf import settings
from google.cloud import speech


def generate_4_digit_code():
    return f"{random.randint(1000, 9999)}"

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
  app_id='1828071',
  key='431004fa41f035822549',
  secret='812e5e84405a5246d31d',
  cluster='eu',
  ssl=True
)

def send_notification(token, msg, body, username):
    print("receipient", username)
    url = "https://exp.host/--/api/v2/push/send"
    headers = {"Content-Type": "application/json"}
    data = {"to": token, "title": msg, "body": body, "data": {"username": username}}
    requests.post(url, headers=headers, data=json.dumps(data))

encoded_credentials = os.getenv('GOOGLE_APPLICATION_CREDENTIALS_JSON')
decoded_credentials = base64.b64decode(encoded_credentials)
service_account_info = json.loads(decoded_credentials)

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
        userdata.notification_token = serializer.validated_data['notificationToken']
        userdata.save()
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
        keyword = request.GET["search"]
        try:
            search_user = UserModel.objects.get(username=keyword)
            search_user = UserSerializer(search_user)
            return Response({"search_user": search_user.data}, status=200)
        except UserModel.DoesNotExist:
            return Response({"message": "User with the above username does not exist"}, status=400)
        
class resetTokenView(APIView):
    def get(self, request):
        keyword = request.GET["email"]
        try:
            check_user = UserModel.objects.filter(email=keyword).exists()
            if not check_user:
                return Response({"message": "Email address does not exist"}, status=400)

            user = UserModel.objects.get(email=keyword)
            code = generate_4_digit_code()
            user.password_reset_token = code
            user.save()

            send_mail(
                'Password Reset Code Request',
                f'Please use this code {code} to complete your password reset',
                settings.EMAIL_HOST_USER,
                [user.email],
                fail_silently=False,
            )

            return Response({"message": "A four digits code have been sent to your mail"}, status=200)
        except Exception:
            return Response({"message": "An error occured, please try again later!"}, status=400)
        
class resetVerificationView(APIView):
    def get(self, request):
        email = request.GET["email"]
        token = request.GET["token"]
        try:
            user = UserModel.objects.get(email=email)
            print(user.password_reset_token, token)
            if user.password_reset_token == token:
                return Response({"message": "correct token"}, status=200)
            return Response({"message": "Invalid token"}, status=400)
        except Exception as e:
            return Response({"message": "An error occured, please try again later!"}, status=400)

class resetTokenPasswordView(APIView):
    def post(self, request):
        data = request.data
        email = data['email']
        password = data['password']
        try:
            user = User.objects.get(email=email)
            user.password = make_password(password=password)
            user.save()
            return Response({"message", "Password reset successful"}, status=200) 
        except Exception as e:
            return Response({"message": "An error occured, please try again later!"}, status=400)
        
class emailNotificationView(APIView):
    authentication_classes = [Authentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        data = request.data
        emailState = data['emailNotification']
        try:
            user = UserModel.objects.get(user=user)
            user.email_notification = emailState
            user.save()
            return Response({"message", "Email state successfuly updated"}, status=200) 
        except Exception as e:
            print(e)
            return Response({"message": "An error occured, please try again later!"}, status=400)
        
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

class PasswordReset(APIView):
    authentication_classes = [Authentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        user = request.user
        data = request.data
        password = data['password']
        user.password = make_password(password=password)
        user.save()
        return Response({"message", "Password reset successful"}, status=200) 

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
            send_notification(token=contact_user.notification_token, msg="Friend Request", body=f"{user_data.username} sent a request to talk and see status", username=user_data.username)
            
            if contact_user.email_notification:
                send_mail(
                'Friend Request',
                f"{user_data.username} sent a request to talk and see status",
                settings.EMAIL_HOST_USER,
                [contact_user.email],
                fail_silently=False,
            )
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

        pair = PairModel.objects.get(id=pair_id)

        user_data = UserModel.objects.get(id=pair.sender.id)
        user_contact_list = PairModel.objects.filter(Q(sender=user_data) | Q(receiver=user_data))

        serialized_user = UserSerializer(user_data)
        serialized_contact = PairSerializer(user_contact_list, many=True)


        context = {
            "user": serialized_user.data,
            "contact_list": serialized_contact.data
        }        

        pusher_client.trigger(f'private-user_{pair.sender.id}', 'accept-request', {
            'message': 'Friend request accepted',
            'userData': context
        })

        send_notification(token=pair.sender.notification_token, msg="Friend Request Accepted", body=f"{pair.receiver.username} accepted your request to talk and see status", username=pair.receiver.username)

        if pair.sender.email_notification:
            send_mail(
                'Friend Request Accepted',
                f"{pair.receiver.username} accepted your request to talk and see status",
                settings.EMAIL_HOST_USER,
                [pair.sender.email],
                fail_silently=False,
            )
                
        return Response(serializer.data)

    
class PusherAuthView(APIView):
    authentication_classes = [Authentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):        

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


def check_id_exists(users, id_to_check):
    for user in users:
        if user.get('id') == id_to_check:
            return True
    return False

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
        receiver_id = request.data.get('receiver_id')
        receiver = request.data.get('receiver')
        language = request.data.get('lang')
        user_data = UserModel.objects.get(user=user.id)

        pair = PairModel.objects.get(id=pair_id)

        upload_result = upload(
            file_obj,
            resource_type="video",
            format="wav"
        )
        file_url = upload_result['url']

        members = pusher_client.users_info('presence-chat_walkie')
        delivered = False

        if receiver_id:
            delivered = check_id_exists(users=members['users'], id_to_check=receiver_id)

        record = RecordModel.objects.create(pair=pair, sender=user_data, audio_file=file_url, delivered=delivered, language=language)
        record.save()

        receiver_user = UserModel.objects.get(username=receiver)

        pusher_client.trigger(f'presence-chat_walkie', 'presence-chat-audio', {
                'id': pair_id,
                'channel_name': f"presence-chat_walkie",
                'content': file_url,
                'sender': UserSerializer(user_data).data,
                'created_at': RecordSerializer(record).data['created_at'],
                "language": language,
                "record_id": record.id
            })
        
        send_notification(token=receiver_user.notification_token, msg="New Message", body=f"You have a new message from {user_data.username}", username=user_data.username)
        if receiver_user.email_notification:
            send_mail(
                'New Message',
                f"You have a new message from {user_data.username}",
                settings.EMAIL_HOST_USER,
                [receiver_user.email],
                fail_silently=False,
            )

        return Response({"file_url": file_url}, status=200)


class checkDelivered(APIView):
    authentication_classes = [Authentication]
    permission_classes = [IsAuthenticated]

    serializer_class = RecordSerializer

    def get(self, request):
        user = request.user

        # Fetch all relevant undelivered records in one query
        undelivered = RecordModel.objects.filter(
            delivered=False
        ).filter(
            Q(pair__receiver__user=user) | Q(pair__sender__user=user)
        ).exclude(
            sender__email=user.email
        )

        # Process and deliver undelivered records
        undelivered_ids = []
        for obj in undelivered:
            obj_d = RecordSerializer(obj).data
            pusher_client.trigger(f"presence-chat_walkie", 'presence-chat-audio', {
                'id': obj_d['pair'],
                'channel_name': f"presence-chat_walkie",
                'content': obj_d['audio_file'],
                'sender': obj_d['sender'],
                'created_at': obj_d['created_at'],
                "language": obj_d['language'],
                "record_id": obj_d['id'],
            })
            undelivered_ids.append(obj.id)

        # Bulk update delivered status
        RecordModel.objects.filter(id__in=undelivered_ids).update(delivered=True)

        # Fetch all relevant PairModel objects in one query
        falseStatuses = PairModel.objects.filter(status=False, receiver__user__email=user.email)
        falseAccepted = PairModel.objects.filter(status=True, accepted=False, sender__user__email=user.email)

        # Process false statuses
        for obj in falseStatuses:
            receiver_user_data = get_user_data(obj.receiver.id)
            pusher_client.trigger(f'private-user_{obj.receiver.id}', 'friend-request', {
                'from': obj.sender.username,
                'message': 'You have a new friend request!',
                "userData": receiver_user_data
            })

        # Process false accepted
        for obj in falseAccepted:
            pair = PairModel.objects.get(id=obj.id)
            sender_id = pair.sender.id
            pair.accepted = True
            pair.save()

            receiver_user_data = get_user_data(sender_id)

            pusher_client.trigger(f'private-user_{sender_id}', 'accept-request', {
                'message': 'PairModel updated',
                "userData": receiver_user_data
            })

        return Response({"message": "All Messages delivered"}, status=200)
    

def transcribe_model_selection_v2(language: str, audio_path: str) -> cloud_speech.RecognizeResponse:
    credentials = service_account.Credentials.from_service_account_info(service_account_info)
    client = speech.SpeechClient(credentials=credentials)

    with open(audio_path, "rb") as f:
        content = f.read()

    audio = speech.RecognitionAudio(content=content)

    config = speech.RecognitionConfig(
        encoding=speech.RecognitionConfig.AudioEncoding.LINEAR16,
        sample_rate_hertz=8000,
        language_code=language,
        model="default",
        audio_channel_count=1,
        enable_word_time_offsets=True,
        enable_automatic_punctuation=True,
        use_enhanced=True,
        profanity_filter=True, 
        alternative_language_codes=["yo", "en", 'ig', 'ha'],
    )

    operation = client.long_running_recognize(config=config, audio=audio)

    print("Waiting for operation to complete...")
    response = operation.result(timeout=90)
    
    return response

class TranslateView(APIView):
    parser_classes = (MultiPartParser, FormParser)

    def post(self, request):
        file_obj = request.data['file']
        language = request.data['lang']
        target = request.data['target']
        gender = request.data['gender']
        record_id = request.data['record_id']

        print(f"initial langage: {language} target language: {target}")

        file_name = '/tmp/uploaded_audio.mp3'

        with open(file_name, 'wb+') as destination:
            for chunk in file_obj.chunks():
                destination.write(chunk)

        output_file = '/tmp/output.mp3'


        try:
            response = transcribe_model_selection_v2(language=language, audio_path=file_name)
            
            transcription = ''
            for result in response.results:
                transcription += result.alternatives[0].transcript

            trans_text = translate_text(target=target, text=transcription, source=language.replace('-NG', ''))
            translated_text = html.unescape(trans_text['translatedText'])

            if gender == 'FEMALE':
                ssml_gender = texttospeech.SsmlVoiceGender.FEMALE
            else:
                ssml_gender = texttospeech.SsmlVoiceGender.MALE

            text_to_speech(text=translated_text, gender=ssml_gender)
            

            upload_result = upload(
                output_file,
                resource_type="auto"
            )
            file_url = upload_result['url']

            record = RecordModel.objects.get(id=record_id)
            record.trans_language = file_url
            record.save()

            context = {
                "file_url": file_url,
                "text_translate": trans_text,
            }
            os.remove(file_name)
            os.remove(output_file)
            return Response(context, status=200)
        except Exception as e:
            os.remove(file_name)
            os.remove(output_file)
            return Response("An error occured", status=400)
            
from google.cloud import translate_v2 as translate

def translate_text(target: str, text: str, source: str) -> dict:
    credentials = service_account.Credentials.from_service_account_info(service_account_info)
    translate_client = translate.Client(credentials=credentials)

    if isinstance(text, bytes):
        text = text.decode("utf-8")

    result = translate_client.translate(text, target_language=target, source_language=source)

    print("Text: {}".format(result["input"]))
    print("Translation: {}".format(result["translatedText"]))
    print("Detected source language: {}".format(source))

    return result

def text_to_speech(text, lang='en', gender=texttospeech.SsmlVoiceGender.MALE, output_file='/tmp/output.mp3'):
    credentials = service_account.Credentials.from_service_account_info(service_account_info)
    client = texttospeech.TextToSpeechClient(credentials=credentials)

    input_text = texttospeech.SynthesisInput(text=text)

    voice = texttospeech.VoiceSelectionParams(
        language_code=lang,
        ssml_gender=gender
    )

    audio_config = texttospeech.AudioConfig(
        audio_encoding=texttospeech.AudioEncoding.MP3
    )

    response = client.synthesize_speech(
        input=input_text,
        voice=voice,
        audio_config=audio_config
    )

    with open(output_file, 'wb') as out:
        out.write(response.audio_content)
        print(f'Audio content written to {output_file}')
