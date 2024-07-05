from rest_framework import serializers
from .models import *

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserModel
        fields = "__all__"

class UserLoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()
    notificationToken = serializers.CharField()

class PairSerializer(serializers.ModelSerializer):
    sender = UserSerializer()
    receiver = UserSerializer()
    
    class Meta: 
        model = PairModel
        fields = "__all__"

class RecordSerializer(serializers.ModelSerializer):
    sender = UserSerializer()

    class Meta:
        model = RecordModel
        fields = "__all__"

""" class ExpoTokenSerializer(serializers.ModelSerializer):
    class Meta:
        model = ExpoTokenModel
        fields = "__all__" """