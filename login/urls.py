from django.urls import path
from . import views

# Import profile views from the profiles app
from profiles import views as profile_views

urlpatterns = [
    # ========== AUTHENTICATION ==========
    path("register/", views.RegisterView.as_view(), name="register"),
    path("login/", views.LoginView.as_view(), name="login"),
    path("google-login/", views.GoogleLoginView.as_view(), name="google-login"),
    path("google-callback/", views.GoogleCallbackView.as_view(), name="google-callback"),

    # # Profile endpoints
    # path("profile/", views.ProfileView.as_view(), name="profile"),
    # path("profile/<path:email>/", views.ProfileDetailView.as_view(), name="profile-detail"),

    # Photo upload (media + URL stored in Firestore)
    path("photos/upload/", views.PhotoUploadView.as_view(), name="photo-upload"),

    # Auth status (existing vs new user)
    path("auth/status/", views.AuthStatusView.as_view(), name="auth-status"),
    
    # OTP login
    path("login/send-otp/", views.SendLoginOTPView.as_view(), name="send-login-otp"),
    path("login/verify-otp/", views.VerifyLoginOTPView.as_view(), name="verify-login-otp"),
    
    # ========== PROFILE (Using profiles app) ==========
    # path("profile/", profile_views.get_profile, name="profile"),
    # path("profile/save/", profile_views.create_or_update_profile, name="save-profile"),
    # path("profile/status/", profile_views.profile_status, name="profile-status"),
    # path("profile/upload-photo/", profile_views.upload_photo, name="upload-photo"),
    
    # ========== MATCHING ==========
    path("matches/", views.MatchRecommendationsView.as_view(), name="matches"),

    path("like/", views.LikeProfileView.as_view()),
    # path("matches/accept/", views.AcceptMatchView.as_view(), name="accept_match"),

    path("chats/matched/", views.MatchedChatsView.as_view(), name="matched-chats"),

    path("chats/<str:chat_id>/messages/", views.ChatMessagesView.as_view()),
    path("chats/<str:chat_id>/send/", views.SendChatMessageView.as_view()),
    path("chats/<str:chat_id>/read/", views.MarkChatReadView.as_view()),

    path("users/block/", views.BlockUserView.as_view()),
    path("users/unblock/", views.UnblockUserView.as_view()),

    path('reports/', views.CreateUserReportView.as_view(), name='create-report'),

    path("create-order/", views.CreateOrderView.as_view()),
    path("verify-payment/", views.VerifyPaymentView.as_view()),

    path("password/forgot/", views.ForgotPasswordView.as_view(), name="forgot-password"),
    path("password/verify-otp/", views.VerifyResetOTPView.as_view(), name="verify-reset-otp"),
    path("password/reset/", views.ResetPasswordView.as_view(), name="reset-password"),

    # ========== NOTIFICATIONS ==========
    path("notifications/",views.NotificationListView.as_view(),name="notification-list",),
    path("notifications/read/",views.MarkNotificationReadView.as_view(),name="notification-read",),
    path("notifications/read-all/",views.MarkAllNotificationsReadView.as_view(),name="notification-read-all",),
    path("notifications/unread-count/",views.UnreadNotificationCountView.as_view(),name="notification-unread-count", ),
]