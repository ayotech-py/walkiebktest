from rest_framework.routers import DefaultRouter
from django.urls import path, include
from .views import *
from .models import *

router = DefaultRouter()
router.register("user_view", UserViewset, basename=UserModel)
router.register("pair_view", PairViewset, basename=PairModel)

urlpatterns = [
    path("", include(router.urls)),
    path("auth-login/", UserLoginView.as_view()),
    path("contact-api/", ContactView.as_view())
]
