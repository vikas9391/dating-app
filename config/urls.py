"""
Main URL Configuration
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static


# Admin panel public endpoints
from admin_panel.views import (
    public_premium_plans,
    public_premium_features,
    public_expert_tips,
    public_footer_data,
    ValidatePromoCodeView,
    RedeemPromoCodeView,
    ApprovedReviewsView,
    SubmitReviewView,
    # ✅ FIX: Import payment views from admin_panel, not login
    CreateOrderView,
    VerifyPaymentView,
)

urlpatterns = [
    # Django Admin
    path("admin/", admin.site.urls),

    # ==========================================
    # PUBLIC ENDPOINTS
    # ==========================================

    # Promo Codes
    path('api/promo/validate/', ValidatePromoCodeView.as_view(), name='validate-promo'),
    path('api/promo/redeem/', RedeemPromoCodeView.as_view(), name='redeem-promo'),

    # Reviews
    path('api/reviews/approved/', ApprovedReviewsView.as_view(), name='approved-reviews'),
    path('api/reviews/submit/', SubmitReviewView.as_view(), name='submit-review'),

    # Premium Plans & Features
    path('api/premium/plans/', public_premium_plans, name='public-premium-plans'),
    path('api/premium/features/', public_premium_features, name='public-premium-features'),

    # Expert Tips
    path('api/expert-tips/', public_expert_tips, name='public-expert-tips'),

    # Footer
    path('api/footer/', public_footer_data, name='public-footer-data'),

    # ==========================================
    # PAYMENT ENDPOINTS
    # ==========================================
    path('api/create-order/', CreateOrderView.as_view(), name='create-order'),
    path('api/verify/', VerifyPaymentView.as_view(), name='verify-payment'),

    # ==========================================
    # APP ROUTES
    # ==========================================
    path("api/", include("login.urls")),          # login/auth APIs
    path("api/profile/", include("profiles.urls")),
    path("api/admin/", include("admin_panel.urls")),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)