from rest_framework import serializers
from .models import *

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserModel
        fields = "__all__"

class UserLoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()

class PairSerializer(serializers.ModelSerializer):
    sender = UserSerializer()
    receiver = UserSerializer()
    
    class Meta: 
        model = PairModel
        fields = "__all__"