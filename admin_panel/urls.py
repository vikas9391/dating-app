from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    AdminDashboardViewSet,
    UserManagementViewSet,
    ReportManagementViewSet,
    AdminActionViewSet,
    AdminLoginView,  
    PremiumManagementViewSet, 
    PremiumFeatureViewSet,
    ExpertTipViewSet,
    AdminRoleViewSet, 
    # Admin review management views only
    AdminReviewsListView,
    AdminReviewDetailView,
    ApproveReviewView,
    RejectReviewView,
    BulkApproveReviewsView,
    BulkRejectReviewsView,
    # footer 
    FooterSectionViewSet,
    FooterLinkViewSet,
    FooterSettingsViewSet,
    # promo-code
    PromoCodeViewSet,
    ValidatePromoCodeView, 
    RedeemPromoCodeView,
    # ✅ Payment endpoints
    CreateOrderView,
    VerifyPaymentView,
)

# Create router for ViewSets
router = DefaultRouter()
router.register(r'dashboard', AdminDashboardViewSet, basename='admin-dashboard')
router.register(r'users', UserManagementViewSet, basename='admin-users')
router.register(r'reports', ReportManagementViewSet, basename='admin-reports')
router.register(r'actions', AdminActionViewSet, basename='admin-actions')
router.register(r'premium/plans', PremiumManagementViewSet, basename='premium-plans')
router.register(r'premium/features', PremiumFeatureViewSet, basename='premium-features')
router.register(r'expert-tips', ExpertTipViewSet, basename='expert-tips')
router.register(r'admin-roles', AdminRoleViewSet, basename='admin-roles') 
router.register(r'footer/sections', FooterSectionViewSet, basename='footer-sections')
router.register(r'footer/links', FooterLinkViewSet, basename='footer-links')
router.register(r'footer/settings', FooterSettingsViewSet, basename='footer-settings')
router.register(r'promo-codes', PromoCodeViewSet, basename='promo-codes')


urlpatterns = [
    # Admin login endpoint
    path('login/', AdminLoginView.as_view(), name='admin-login'),
    
    # ==========================================
    # ADMIN-ONLY REVIEW MANAGEMENT ENDPOINTS
    # ==========================================
    # Note: Public endpoints (approved reviews & submit) are in config/urls.py
    path('reviews/', AdminReviewsListView.as_view(), name='admin-reviews-list'),
    path('reviews/<int:pk>/', AdminReviewDetailView.as_view(), name='admin-review-detail'),
    path('reviews/<int:pk>/approve/', ApproveReviewView.as_view(), name='approve-review'),
    path('reviews/<int:pk>/reject/', RejectReviewView.as_view(), name='reject-review'),
    path('reviews/bulk_approve/', BulkApproveReviewsView.as_view(), name='bulk-approve-reviews'),
    path('reviews/bulk_reject/', BulkRejectReviewsView.as_view(), name='bulk-reject-reviews'),
    
    # Include all router URLs
    path('', include(router.urls)),
]