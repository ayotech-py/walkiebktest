from django.contrib import admin
from .models import *

admin.site.register(UserModel)
admin.site.register(PairModel)
admin.site.register(RecordModel)