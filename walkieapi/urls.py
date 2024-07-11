from rest_framework.routers import DefaultRouter
from django.urls import path, include
from .views import *
from .models import *

router = DefaultRouter()
router.register("user_view", UserViewset, basename=UserModel)
router.register("pair_view", PairViewset, basename=PairModel)
router.register("record_view", RecordViewset, basename=RecordModel)

urlpatterns = [
    path("", include(router.urls)),
    path("auth-login/", UserLoginView.as_view()),
    path("contact-api/", ContactView.as_view()),
    path("photo-api/", ProfileImageView.as_view()),
    path("pusher-auth/", PusherAuthView.as_view()),
    path("check-undelivered/", checkDelivered.as_view()),
    path("translate-audio/", TranslateView.as_view()),
    path("password-reset/", PasswordReset.as_view()),
    path("password-reset-token/", resetTokenView.as_view()),
    path("password-verification-token/", resetVerificationView.as_view()),
    path("password-token-reset/", resetTokenPasswordView.as_view()),
    path("email-notification/", emailNotificationView.as_view()),
    path("push-notification/", pushNotificationView.as_view()),
    path("translate-self/", TranslateSelfView.as_view())
]
