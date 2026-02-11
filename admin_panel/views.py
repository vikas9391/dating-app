import logging
import secrets
import string
from datetime import timedelta

from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.db import transaction
from django.db.models import Count, Q, Sum, QuerySet
from django.utils import timezone

from rest_framework import viewsets, status, generics
from rest_framework.authentication import TokenAuthentication, SessionAuthentication
from rest_framework.authtoken.models import Token
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.pagination import PageNumberPagination
from rest_framework.permissions import AllowAny, IsAuthenticated, IsAdminUser
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication

# Razorpay imports
import razorpay
from django.conf import settings
from dateutil.relativedelta import relativedelta

# Local imports
from profiles.models import UserProfile
from .models import (
    UserReport, AdminAction, PremiumPlan, PremiumFeature,
    ExpertTip, Review, AdminRole,
    FooterSection, FooterLink, FooterSettings,
    PromoCode, PromoCodeUsage,
)
from .serializers import (
    UserProfileSerializer, UserReportSerializer,
    AdminActionSerializer, UserActionSerializer,
    PremiumPlanSerializer, PremiumFeatureSerializer,
    ExpertTipSerializer, ReviewSerializer, ApprovedReviewSerializer,
    AdminRoleSerializer, AdminRoleCreateSerializer,
    FooterSectionSerializer, FooterLinkSerializer, FooterSettingsSerializer,
    PromoCodeSerializer, PromoCodeUsageSerializer,
)

# Try importing custom permissions, fallback to standard IsAdminUser if missing
try:
    from .permissions import IsSuperAdmin, HasSectionPermission
except ImportError:
    # Fallback to IsAdminUser if custom permissions file is incomplete
    IsSuperAdmin = IsAdminUser
    HasSectionPermission = IsAdminUser

logger = logging.getLogger(__name__)

# Initialize Razorpay Client
client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))


# ─────────────────────────────────────────────────────────────────────────────
# PAGINATION
# ─────────────────────────────────────────────────────────────────────────────

class StandardResultsSetPagination(PageNumberPagination):
    page_size = 20
    page_size_query_param = 'page_size'
    max_page_size = 100


# ─────────────────────────────────────────────────────────────────────────────
# PREMIUM MANAGEMENT (FIXED FOR PUBLIC ACCESS)
# ─────────────────────────────────────────────────────────────────────────────

class PremiumManagementViewSet(viewsets.ModelViewSet):
    """ViewSet for managing premium plans"""
    serializer_class = PremiumPlanSerializer
    queryset = PremiumPlan.objects.all()
    lookup_field = 'plan_id'
    # Default permission is Admin, but overridden in get_permissions
    permission_classes = [IsAdminUser]

    def get_permissions(self):
        """
        CRITICAL FIX: Allow public access to list/retrieve plans.
        """
        if self.action in ['list', 'retrieve', 'public_plans']:
            return [AllowAny()]
        return [IsAdminUser()]

    def get_queryset(self):
        """Get queryset with optional filtering"""
        request = self.request
        queryset = PremiumPlan.objects.all()

        # SECURITY: If user is NOT admin, only show active plans
        if not request.user.is_staff:
            queryset = queryset.filter(active=True)

        # Filters for Admin
        active = request.query_params.get('active', None)
        if active is not None and request.user.is_staff:
            queryset = queryset.filter(active=active.lower() == 'true')

        popular = request.query_params.get('popular', None)
        if popular is not None:
            queryset = queryset.filter(popular=popular.lower() == 'true')

        return queryset.order_by('display_order', 'price')

    @action(detail=False, methods=['get'])
    def public_plans(self, request):
        """Get active plans for public display (Explicit endpoint)"""
        plans = PremiumPlan.objects.filter(active=True).order_by('display_order', 'price')
        serializer = self.get_serializer(plans, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def toggle_active(self, request, plan_id=None):
        """Toggle plan active status"""
        try:
            plan = self.get_object()
            plan.active = not plan.active
            plan.save()

            return Response({
                'message': f'Plan {"activated" if plan.active else "deactivated"} successfully',
                'plan': PremiumPlanSerializer(plan).data
            })
        except PremiumPlan.DoesNotExist:
            return Response(
                {'error': 'Plan not found'},
                status=status.HTTP_404_NOT_FOUND
            )

    @action(detail=True, methods=['post'])
    def toggle_popular(self, request, plan_id=None):
        """Toggle plan popular status"""
        try:
            plan = self.get_object()

            # If setting as popular, remove popular from all other plans
            if not plan.popular:
                PremiumPlan.objects.all().update(popular=False)

            plan.popular = not plan.popular
            plan.save()

            return Response({
                'message': f'Plan marked as {"popular" if plan.popular else "regular"}',
                'plan': PremiumPlanSerializer(plan).data
            })
        except PremiumPlan.DoesNotExist:
            return Response(
                {'error': 'Plan not found'},
                status=status.HTTP_404_NOT_FOUND
            )

    @action(detail=False, methods=['post'])
    def reorder(self, request):
        """Reorder plans"""
        try:
            orders = request.data.get('orders', [])
            for item in orders:
                plan_id = item.get('plan_id')
                order = item.get('order')

                if plan_id and order is not None:
                    PremiumPlan.objects.filter(plan_id=plan_id).update(display_order=order)

            return Response({'message': 'Plans reordered successfully'})
        except Exception as e:
            return Response(
                {'error': f'Reorder failed: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class PremiumFeatureViewSet(viewsets.ModelViewSet):
    """ViewSet for managing premium features"""
    serializer_class = PremiumFeatureSerializer
    queryset = PremiumFeature.objects.all()
    permission_classes = [IsAdminUser]

    def get_permissions(self):
        """
        CRITICAL FIX: Allow public access to list features.
        """
        if self.action in ['list', 'retrieve', 'public_features']:
            return [AllowAny()]
        return [IsAdminUser()]

    def get_queryset(self):
        """Get queryset with optional filtering"""
        request = self.request
        queryset = PremiumFeature.objects.all()

        # SECURITY: If user is NOT admin, only show active features
        if not request.user.is_staff:
            queryset = queryset.filter(active=True)

        # Filter by active status (Admin only)
        active = request.query_params.get('active', None)
        if active is not None and request.user.is_staff:
            queryset = queryset.filter(active=active.lower() == 'true')

        return queryset.order_by('display_order')

    @action(detail=False, methods=['get'])
    def public_features(self, request):
        """Get active features for public display (no auth required)"""
        features = PremiumFeature.objects.filter(active=True).order_by('display_order')
        serializer = self.get_serializer(features, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def toggle_active(self, request, pk=None):
        """Toggle feature active status"""
        try:
            feature = self.get_object()
            feature.active = not feature.active
            feature.save()

            return Response({
                'message': f'Feature {"activated" if feature.active else "deactivated"} successfully',
                'feature': PremiumFeatureSerializer(feature).data
            })
        except PremiumFeature.DoesNotExist:
            return Response(
                {'error': 'Feature not found'},
                status=status.HTTP_404_NOT_FOUND
            )

    @action(detail=False, methods=['post'])
    def reorder(self, request):
        """Reorder features"""
        try:
            orders = request.data.get('orders', [])
            for item in orders:
                feature_id = item.get('id')
                order = item.get('order')

                if feature_id and order is not None:
                    PremiumFeature.objects.filter(id=feature_id).update(display_order=order)

            return Response({'message': 'Features reordered successfully'})
        except Exception as e:
            return Response(
                {'error': f'Reorder failed: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


# ─────────────────────────────────────────────────────────────────────────────
# ADMIN LOGIN
# ─────────────────────────────────────────────────────────────────────────────

class AdminLoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request: Request) -> Response:
        try:
            identifier = request.data.get('username')
            password = request.data.get('password')

            if not identifier or not password:
                return Response(
                    {'error': 'Username/email and password are required'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            user = authenticate(username=identifier, password=password)

            # Fall back to email lookup
            if user is None and '@' in identifier:
                try:
                    for potential_user in User.objects.filter(email=identifier):
                        user = authenticate(username=potential_user.username, password=password)
                        if user is not None:
                            break
                except Exception:
                    pass

            if user is None:
                return Response(
                    {'error': 'Invalid credentials'},
                    status=status.HTTP_401_UNAUTHORIZED
                )

            if not user.is_staff:
                return Response(
                    {'error': 'Access denied. Admin privileges required.'},
                    status=status.HTTP_403_FORBIDDEN
                )

            # Check AdminRole is active (superusers bypass)
            if not user.is_superuser:
                try:
                    role = user.admin_role
                    if not role.is_active:
                        return Response(
                            {'error': 'This admin account has been deactivated.'},
                            status=status.HTTP_403_FORBIDDEN
                        )
                except AdminRole.DoesNotExist:
                    return Response(
                        {'error': 'No admin role configured for this account.'},
                        status=status.HTTP_403_FORBIDDEN
                    )

            # Update last_login on AdminRole
            try:
                if hasattr(user, 'admin_role'):
                    admin_role = user.admin_role
                    admin_role.last_login = timezone.now()
                    admin_role.save()
            except Exception:
                pass

            Token.objects.filter(user=user).delete()
            token = Token.objects.create(user=user)

            return Response({
                'token': token.key,
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'is_staff': user.is_staff,
                    'is_superuser': user.is_superuser,
                }
            }, status=status.HTTP_200_OK)

        except Exception as e:
            import traceback
            print("Admin login error:", traceback.format_exc())
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ─────────────────────────────────────────────────────────────────────────────
# REVIEWS
# ─────────────────────────────────────────────────────────────────────────────

class SubmitReviewView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            text = request.data.get('text', '').strip()
            rating = request.data.get('rating', 5)

            if not text:
                return Response({'error': 'Review text is required'}, status=status.HTTP_400_BAD_REQUEST)
            if len(text) < 50:
                return Response({'error': 'Review must be at least 50 characters'}, status=status.HTTP_400_BAD_REQUEST)
            if not (1 <= rating <= 5):
                return Response({'error': 'Rating must be between 1 and 5'}, status=status.HTTP_400_BAD_REQUEST)

            review = Review.objects.create(user=request.user, text=text, rating=rating, status='pending')

            return Response({
                'message': 'Review submitted successfully! It will be visible after admin approval.',
                'review': ReviewSerializer(review).data
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            import traceback
            print("Review submission error:", traceback.format_exc())
            return Response({'error': f'Failed to submit review: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ApprovedReviewsView(generics.ListAPIView):
    permission_classes = [AllowAny]
    serializer_class = ApprovedReviewSerializer

    def get_queryset(self):
        return Review.objects.filter(status='approved').order_by('-created_at')


class AdminReviewsListView(generics.ListAPIView):
    permission_classes = [HasSectionPermission]
    serializer_class = ReviewSerializer
    section_id = 'reviews'
    required_level = 'view'

    def get_queryset(self):
        queryset = Review.objects.all()
        status_filter = self.request.query_params.get('status')
        if status_filter and status_filter != 'all':
            queryset = queryset.filter(status=status_filter)
        rating_filter = self.request.query_params.get('rating')
        if rating_filter and rating_filter != 'all':
            queryset = queryset.filter(rating=int(rating_filter))
        search = self.request.query_params.get('search')
        if search:
            queryset = queryset.filter(text__icontains=search)
        return queryset


class AdminReviewDetailView(generics.RetrieveDestroyAPIView):
    permission_classes = [HasSectionPermission]
    serializer_class = ReviewSerializer
    queryset = Review.objects.all()
    section_id = 'reviews'
    required_level = 'edit'


class ApproveReviewView(APIView):
    permission_classes = [HasSectionPermission]
    section_id = 'reviews'
    required_level = 'edit'

    def post(self, request, pk):
        try:
            review = Review.objects.get(pk=pk)
            review.status = 'approved'
            review.reviewed_by = request.user
            review.reviewed_at = timezone.now()
            review.admin_notes = request.data.get('admin_notes', '')
            review.save()
            return Response({'message': 'Review approved successfully', 'review': ReviewSerializer(review).data})
        except Review.DoesNotExist:
            return Response({'error': 'Review not found'}, status=status.HTTP_404_NOT_FOUND)


class RejectReviewView(APIView):
    permission_classes = [HasSectionPermission]
    section_id = 'reviews'
    required_level = 'edit'

    def post(self, request, pk):
        try:
            review = Review.objects.get(pk=pk)
            review.status = 'rejected'
            review.reviewed_by = request.user
            review.reviewed_at = timezone.now()
            review.admin_notes = request.data.get('admin_notes', '')
            review.save()
            return Response({'message': 'Review rejected successfully', 'review': ReviewSerializer(review).data})
        except Review.DoesNotExist:
            return Response({'error': 'Review not found'}, status=status.HTTP_404_NOT_FOUND)


class BulkApproveReviewsView(APIView):
    permission_classes = [HasSectionPermission]
    section_id = 'reviews'
    required_level = 'edit'

    def post(self, request):
        review_ids = request.data.get('review_ids', [])
        approved_count = Review.objects.filter(id__in=review_ids).update(
            status='approved', reviewed_by=request.user, reviewed_at=timezone.now()
        )
        return Response({'message': f'{approved_count} review(s) approved', 'approved_count': approved_count})


class BulkRejectReviewsView(APIView):
    permission_classes = [HasSectionPermission]
    section_id = 'reviews'
    required_level = 'edit'

    def post(self, request):
        review_ids = request.data.get('review_ids', [])
        rejected_count = Review.objects.filter(id__in=review_ids).update(
            status='rejected', reviewed_by=request.user, reviewed_at=timezone.now()
        )
        return Response({'message': f'{rejected_count} review(s) rejected', 'rejected_count': rejected_count})


# ─────────────────────────────────────────────────────────────────────────────
# DASHBOARD
# ─────────────────────────────────────────────────────────────────────────────

class AdminDashboardViewSet(viewsets.ViewSet):
    permission_classes = [HasSectionPermission]
    section_id = 'overview'
    required_level = 'view'

    @action(detail=False, methods=['get'])
    def stats(self, request: Request) -> Response:
        try:
            today = timezone.now().date()
            week_ago = timezone.now() - timedelta(days=7)
            month_ago = timezone.now() - timedelta(days=30)

            users = UserProfile.objects.all()
            total_users = users.count()

            all_reports = UserReport.objects.all()

            account_status_dist = {
                'active': users.filter(account_status='active').count(),
                'pending': users.filter(account_status='pending').count(),
                'suspended': users.filter(account_status='suspended').count(),
                'banned': users.filter(account_status='banned').count(),
            }

            recent_actions = AdminAction.objects.filter(
                created_at__gte=week_ago
            ).values('action_type').annotate(count=Count('id'))

            user_growth = []
            for i in range(7):
                date = (timezone.now() - timedelta(days=i)).date()
                user_growth.append({
                    'date': date.isoformat(),
                    'count': users.filter(join_date__date=date).count()
                })
            user_growth.reverse()

            return Response({
                'totalUsers': total_users,
                'activeUsers': users.filter(status='online').count(),
                'suspendedUsers': users.filter(account_status='suspended').count(),
                'bannedUsers': users.filter(account_status='banned').count(),
                'newUsersToday': users.filter(join_date__date=today).count(),
                'newUsersWeek': users.filter(join_date__gte=week_ago).count(),
                'newUsersMonth': users.filter(join_date__gte=month_ago).count(),
                'totalMatches': users.aggregate(Sum('matches'))['matches__sum'] or 0,
                'totalMessages': users.aggregate(Sum('messages'))['messages__sum'] or 0,
                'reportsCount': all_reports.count(),
                'pendingReports': all_reports.filter(status='pending').count(),
                'resolvedReports': all_reports.filter(status='resolved').count(),
                'verifiedUsers': users.filter(verified=True).count(),
                'premiumUsers': users.filter(premium=True).count(),
                'completeProfiles': users.filter(profile_complete=True).count(),
                'accountStatusDistribution': account_status_dist,
                'recentActions': list(recent_actions),
                'userGrowth': user_growth,
            })
        except Exception as e:
            import traceback
            print("Dashboard stats error:", traceback.format_exc())
            return Response({'error': f'Failed to fetch statistics: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ─────────────────────────────────────────────────────────────────────────────
# USER MANAGEMENT
# ─────────────────────────────────────────────────────────────────────────────

class UserManagementViewSet(viewsets.ModelViewSet):
    permission_classes = [HasSectionPermission]
    serializer_class = UserProfileSerializer
    pagination_class = StandardResultsSetPagination
    section_id = 'users'
    required_level = 'view'

    def get_queryset(self) -> QuerySet[UserProfile]:
        queryset = UserProfile.objects.select_related('user').all()

        search = self.request.query_params.get('search')
        status_filter = self.request.query_params.get('status')
        account_status = self.request.query_params.get('account_status')
        verified = self.request.query_params.get('verified')
        premium = self.request.query_params.get('premium')
        ordering = self.request.query_params.get('ordering', '-join_date')

        if search:
            queryset = queryset.filter(
                Q(user__username__icontains=search) | Q(user__email__icontains=search) |
                Q(user__first_name__icontains=search) | Q(user__last_name__icontains=search)
            )
        if status_filter and status_filter != 'all':
            queryset = queryset.filter(status=status_filter)
        if account_status and account_status != 'all':
            queryset = queryset.filter(account_status=account_status)
        if verified is not None:
            queryset = queryset.filter(verified=verified.lower() == 'true')
        if premium is not None:
            queryset = queryset.filter(premium=premium.lower() == 'true')

        allowed_orderings = [
            'join_date', '-join_date', 'last_active', '-last_active',
            'user__username', '-user__username', 'matches', '-matches'
        ]
        queryset = queryset.order_by(ordering if ordering in allowed_orderings else '-join_date')
        return queryset

    def update(self, request, *args, **kwargs):
        self.required_level = 'edit'
        self.check_permissions(request)
        return super().update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        self.required_level = 'edit'
        self.check_permissions(request)
        return super().destroy(request, *args, **kwargs)

    @action(detail=True, methods=['get'])
    def detail_view(self, request, pk=None):
        try:
            profile = self.get_object()
            return Response({
                'profile': UserProfileSerializer(profile).data,
                'reports_made': UserReportSerializer(
                    UserReport.objects.filter(reporter=profile.user).order_by('-created_at')[:10], many=True
                ).data,
                'reports_received': UserReportSerializer(
                    UserReport.objects.filter(reported_user=profile.user).order_by('-created_at')[:10], many=True
                ).data,
                'admin_actions': AdminActionSerializer(
                    AdminAction.objects.filter(target_user=profile.user).order_by('-created_at')[:10], many=True
                ).data,
            })
        except UserProfile.DoesNotExist:
            return Response({'error': 'User profile not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': f'An error occurred: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=True, methods=['post'])
    def user_action(self, request, pk=None):
        self.required_level = 'edit'
        self.check_permissions(request)
        try:
            profile = self.get_object()
            serializer = UserActionSerializer(data=request.data)
            if not serializer.is_valid():
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

            action_type = serializer.validated_data['action']
            reason = serializer.validated_data.get('reason', '')

            if profile.user == request.user:
                return Response({'error': 'You cannot perform actions on your own account'}, status=status.HTTP_400_BAD_REQUEST)
            if profile.user.is_staff and not request.user.is_superuser:
                return Response({'error': 'You cannot perform actions on admin accounts'}, status=status.HTTP_403_FORBIDDEN)

            AdminAction.objects.create(admin=request.user, target_user=profile.user, action_type=action_type, reason=reason)

            if action_type == 'suspend':
                profile.account_status = 'suspended'
                profile.save()
                return Response({'message': 'User suspended successfully', 'user': UserProfileSerializer(profile).data})
            elif action_type == 'ban':
                profile.account_status = 'banned'
                profile.save()
                return Response({'message': 'User banned successfully', 'user': UserProfileSerializer(profile).data})
            elif action_type == 'activate':
                profile.account_status = 'active'
                profile.save()
                return Response({'message': 'User activated successfully', 'user': UserProfileSerializer(profile).data})
            elif action_type == 'delete':
                username = profile.user.username
                profile.user.delete()
                return Response({'message': f'User {username} deleted successfully'})
            elif action_type == 'verify':
                profile.verified = True
                profile.save()
                return Response({'message': 'User verified successfully', 'user': UserProfileSerializer(profile).data})

        except UserProfile.DoesNotExist:
            return Response({'error': 'User profile not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': f'An error occurred: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=False, methods=['post'])
    def bulk_action(self, request):
        self.required_level = 'edit'
        self.check_permissions(request)
        try:
            user_ids = request.data.get('user_ids', [])
            action_type = request.data.get('action')
            reason = request.data.get('reason', 'Bulk action performed')

            if not user_ids:
                return Response({'error': 'No users selected'}, status=status.HTTP_400_BAD_REQUEST)
            if not isinstance(user_ids, list):
                return Response({'error': 'user_ids must be a list'}, status=status.HTTP_400_BAD_REQUEST)
            if action_type not in ['suspend', 'activate', 'verify', 'ban']:
                return Response({'error': 'Invalid action type'}, status=status.HTTP_400_BAD_REQUEST)

            success_count = skipped_count = 0
            errors = []

            for profile in UserProfile.objects.filter(user_id__in=user_ids).select_related('user'):
                if profile.user == request.user:
                    skipped_count += 1
                    errors.append('Skipped: Cannot act on your own account')
                    continue
                if profile.user.is_staff and not request.user.is_superuser:
                    skipped_count += 1
                    errors.append(f'Skipped: {profile.user.username} (admin account)')
                    continue

                try:
                    AdminAction.objects.create(admin=request.user, target_user=profile.user, action_type=action_type, reason=reason)
                    if action_type in ['suspend', 'ban']:
                        profile.account_status = action_type
                    elif action_type == 'activate':
                        profile.account_status = 'active'
                    elif action_type == 'verify':
                        profile.verified = True
                    profile.save()
                    success_count += 1
                except Exception as e:
                    errors.append(f'Error on {profile.user.username}: {str(e)}')

            return Response({
                'message': 'Bulk action completed',
                'success_count': success_count,
                'skipped_count': skipped_count,
                'total_requested': len(user_ids),
                'errors': errors or None
            })
        except Exception as e:
            return Response({'error': f'Bulk action failed: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=False, methods=['get'])
    def export(self, request):
        try:
            serializer = self.get_serializer(self.get_queryset(), many=True)
            return Response({'data': serializer.data, 'count': len(serializer.data)})
        except Exception as e:
            return Response({'error': f'Export failed: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ─────────────────────────────────────────────────────────────────────────────
# REPORTS
# ─────────────────────────────────────────────────────────────────────────────

class ReportManagementViewSet(viewsets.ModelViewSet):
    permission_classes = [HasSectionPermission]
    serializer_class = UserReportSerializer
    pagination_class = StandardResultsSetPagination
    section_id = 'reports'
    required_level = 'view'

    def get_queryset(self) -> QuerySet[UserReport]:
        queryset = UserReport.objects.select_related('reporter', 'reported_user', 'reviewed_by').all()

        status_filter = self.request.query_params.get('status')
        reason_filter = self.request.query_params.get('reason')
        search = self.request.query_params.get('search')
        ordering = self.request.query_params.get('ordering', '-created_at')

        if status_filter and status_filter != 'all':
            queryset = queryset.filter(status=status_filter)
        if reason_filter and reason_filter != 'all':
            queryset = queryset.filter(reason=reason_filter)
        if search:
            queryset = queryset.filter(
                Q(reporter__username__icontains=search) |
                Q(reported_user__username__icontains=search) |
                Q(description__icontains=search)
            )

        allowed = ['created_at', '-created_at', 'status', '-status']
        return queryset.order_by(ordering if ordering in allowed else '-created_at')

    @action(detail=True, methods=['post'])
    def review(self, request, pk=None):
        self.required_level = 'edit'
        self.check_permissions(request)
        try:
            report = self.get_object()
            action = request.data.get('action')
            if action not in ['resolve', 'dismiss']:
                return Response({'error': 'Invalid action. Must be "resolve" or "dismiss"'}, status=status.HTTP_400_BAD_REQUEST)

            report.reviewed_by = request.user
            report.reviewed_at = timezone.now()
            report.admin_notes = request.data.get('admin_notes', '')
            report.status = 'resolved' if action == 'resolve' else 'dismissed'
            report.save()

            return Response({
                'message': f'Report {action}d successfully',
                'report': UserReportSerializer(report).data
            })
        except UserReport.DoesNotExist:
            return Response({'error': 'Report not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': f'An error occurred: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=False, methods=['post'])
    def bulk_review(self, request):
        self.required_level = 'edit'
        self.check_permissions(request)
        try:
            report_ids = request.data.get('report_ids', [])
            action = request.data.get('action')
            admin_notes = request.data.get('admin_notes', 'Bulk review')

            if not report_ids:
                return Response({'error': 'No reports selected'}, status=status.HTTP_400_BAD_REQUEST)
            if action not in ['resolve', 'dismiss']:
                return Response({'error': 'Invalid action'}, status=status.HTTP_400_BAD_REQUEST)

            updated_count = 0
            for report in UserReport.objects.filter(id__in=report_ids):
                report.reviewed_by = request.user
                report.reviewed_at = timezone.now()
                report.admin_notes = admin_notes
                report.status = 'resolved' if action == 'resolve' else 'dismissed'
                report.save()
                updated_count += 1

            return Response({'message': f'{updated_count} reports {action}d successfully', 'updated_count': updated_count})
        except Exception as e:
            return Response({'error': f'Bulk review failed: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ─────────────────────────────────────────────────────────────────────────────
# ADMIN ACTIONS LOG
# ─────────────────────────────────────────────────────────────────────────────

class AdminActionViewSet(viewsets.ReadOnlyModelViewSet):
    permission_classes = [HasSectionPermission]
    serializer_class = AdminActionSerializer
    pagination_class = StandardResultsSetPagination
    section_id = 'analytics'
    required_level = 'view'

    def get_queryset(self) -> QuerySet[AdminAction]:
        queryset = AdminAction.objects.select_related('admin', 'target_user').all()

        user_id = self.request.query_params.get('user_id')
        admin_id = self.request.query_params.get('admin_id')
        action_type = self.request.query_params.get('action_type')
        search = self.request.query_params.get('search')
        ordering = self.request.query_params.get('ordering', '-created_at')

        if user_id:
            queryset = queryset.filter(target_user_id=user_id)
        if admin_id:
            queryset = queryset.filter(admin_id=admin_id)
        if action_type:
            queryset = queryset.filter(action_type=action_type)
        if search:
            queryset = queryset.filter(
                Q(admin__username__icontains=search) |
                Q(target_user__username__icontains=search) |
                Q(reason__icontains=search)
            )

        allowed = ['created_at', '-created_at', 'action_type', '-action_type']
        return queryset.order_by(ordering if ordering in allowed else '-created_at')

    @action(detail=False, methods=['get'])
    def statistics(self, request):
        try:
            week_ago = timezone.now() - timedelta(days=7)
            return Response({
                'total_actions': AdminAction.objects.count(),
                'recent_actions': AdminAction.objects.filter(created_at__gte=week_ago).count(),
                'actions_by_type': list(AdminAction.objects.values('action_type').annotate(count=Count('id')).order_by('-count')),
                'most_active_admins': list(
                    AdminAction.objects.filter(created_at__gte=week_ago)
                    .values('admin__username').annotate(count=Count('id')).order_by('-count')[:5]
                ),
            })
        except Exception as e:
            return Response({'error': f'Failed to fetch statistics: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ─────────────────────────────────────────────────────────────────────────────
# EXPERT TIPS
# ─────────────────────────────────────────────────────────────────────────────

class ExpertTipViewSet(viewsets.ModelViewSet):
    permission_classes = [HasSectionPermission]
    serializer_class = ExpertTipSerializer
    queryset = ExpertTip.objects.all()
    section_id = 'expert-tips'
    required_level = 'view'

    def get_queryset(self) -> QuerySet[ExpertTip]:
        queryset = ExpertTip.objects.all()
        active = self.request.query_params.get('active')
        if active is not None:
            queryset = queryset.filter(active=active.lower() == 'true')
        return queryset.order_by('display_order', '-created_at')

    def create(self, request, *args, **kwargs):
        self.required_level = 'edit'
        self.check_permissions(request)
        return super().create(request, *args, **kwargs)

    def update(self, request, *args, **kwargs):
        self.required_level = 'edit'
        self.check_permissions(request)
        return super().update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        self.required_level = 'edit'
        self.check_permissions(request)
        return super().destroy(request, *args, **kwargs)

    @action(detail=True, methods=['post'])
    def toggle_active(self, request, pk=None):
        self.required_level = 'edit'
        self.check_permissions(request)
        tip = self.get_object()
        tip.active = not tip.active
        tip.save()
        return Response({
            'message': f'Tip {"activated" if tip.active else "deactivated"} successfully',
            'tip': ExpertTipSerializer(tip).data
        })

    @action(detail=False, methods=['post'])
    def reorder(self, request):
        self.required_level = 'edit'
        self.check_permissions(request)
        try:
            for item in request.data.get('orders', []):
                tip_id = item.get('id')
                order = item.get('order')
                if tip_id and order is not None:
                    ExpertTip.objects.filter(id=tip_id).update(display_order=order)
            return Response({'message': 'Tips reordered successfully'})
        except Exception as e:
            return Response({'error': f'Reorder failed: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ─────────────────────────────────────────────────────────────────────────────
# PUBLIC ENDPOINTS
# ─────────────────────────────────────────────────────────────────────────────

@api_view(['GET'])
@permission_classes([AllowAny])
def public_premium_plans(request):
    try:
        plans = PremiumPlan.objects.filter(active=True).order_by('display_order', 'price')
        return Response(PremiumPlanSerializer(plans, many=True).data)
    except Exception as e:
        return Response({'error': f'Failed to fetch plans: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([AllowAny])
def public_premium_features(request):
    try:
        features = PremiumFeature.objects.filter(active=True).order_by('display_order')
        return Response(PremiumFeatureSerializer(features, many=True).data)
    except Exception as e:
        return Response({'error': f'Failed to fetch features: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([AllowAny])
def public_expert_tips(request):
    try:
        limit = request.query_params.get('limit')
        tips = ExpertTip.objects.filter(active=True).order_by('display_order', '-created_at')
        if limit:
            try:
                tips = tips[:int(limit)]
            except ValueError:
                pass
        return Response(ExpertTipSerializer(tips, many=True).data)
    except Exception as e:
        return Response({'error': f'Failed to fetch expert tips: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ─────────────────────────────────────────────────────────────────────────────
# ADMIN ROLE MANAGEMENT - WITH SOFT DELETE IMPLEMENTATION
# ─────────────────────────────────────────────────────────────────────────────

class AdminRoleViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing admin roles and permissions with SOFT DELETE.
    """
    permission_classes = [IsSuperAdmin]
    serializer_class = AdminRoleSerializer
    pagination_class = None  # ✅ Disable pagination - return plain array

    def get_queryset(self):
        """
        ✅ IMPORTANT: Only show active admin roles.
        This filters out soft-deleted admins from the list.
        """
        return AdminRole.objects.select_related('user').filter(
            user__is_active=True,
            is_active=True
        ).order_by('-created_at')

    def get_serializer_class(self):
        if self.action == 'create':
            return AdminRoleCreateSerializer
        return AdminRoleSerializer

    @transaction.atomic
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        email = serializer.validated_data['email']
        username = serializer.validated_data['username']
        role_name = serializer.validated_data['role_name']
        permissions = serializer.validated_data['permissions']
        
        # ✅ Check if there's an inactive user with same username/email
        existing_user = User.objects.filter(
            username=username,
            is_active=False
        ).first()
        
        if existing_user:
            # Option 1: Reactivate the existing user
            logger.info(f"Reactivating previously deleted user: {username}")
            user = existing_user
            user.is_active = True
            user.email = email
            
            password = self.generate_password()
            user.set_password(password)
            user.is_staff = True
            user.save()
            
            admin_role, created = AdminRole.objects.get_or_create(
                user=user,
                defaults={
                    'role_name': role_name,
                    'permissions': permissions,
                    'is_super_admin': False,
                    'is_active': True,
                    'initial_password': password,
                    'password_changed': False,
                }
            )
            
            if not created:
                admin_role.role_name = role_name
                admin_role.permissions = permissions
                admin_role.is_active = True
                admin_role.initial_password = password
                admin_role.password_changed = False
                admin_role.save()
        else:
            password = self.generate_password()
            
            user = User.objects.create_user(
                username=username,
                email=email,
                password=password,
                is_staff=True,
                is_active=True
            )
            
            admin_role = AdminRole.objects.create(
                user=user,
                role_name=role_name,
                permissions=permissions,
                is_super_admin=False,
                is_active=True,
                initial_password=password,
                password_changed=False
            )
        
        response_serializer = AdminRoleSerializer(admin_role)
        response_data = response_serializer.data
        response_data['initial_password'] = password
        
        logger.info(f"Created/reactivated admin: {username} ({email})")
        
        return Response(response_data, status=status.HTTP_201_CREATED)

    @transaction.atomic
    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        user = instance.user
        
        if instance.is_super_admin:
            return Response(
                {"error": "Cannot delete super admin"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        instance.is_active = False
        instance.deleted_at = timezone.now()
        instance.save(update_fields=['is_active', 'deleted_at'])
        
        if user:
            user.is_active = False
            user.save(update_fields=['is_active'])
        
        logger.info(f"Soft deleted admin: {user.username} ({user.email})")
        
        return Response(
            {
                "message": "Admin account deactivated successfully",
                "note": "The account can be restored if needed"
            },
            status=status.HTTP_204_NO_CONTENT
        )

    @action(detail=True, methods=['post'])
    def restore(self, request, pk=None):
        try:
            admin_role = AdminRole.objects.select_related('user').get(pk=pk)
        except AdminRole.DoesNotExist:
            return Response(
                {"error": "Admin role not found"},
                status=status.HTTP_404_NOT_FOUND
            )
        
        if admin_role.is_active:
            return Response(
                {"error": "Admin account is already active"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        admin_role.is_active = True
        admin_role.deleted_at = None
        admin_role.save()
        
        if admin_role.user:
            admin_role.user.is_active = True
            admin_role.user.save()
        
        serializer = self.get_serializer(admin_role)
        logger.info(f"Restored admin: {admin_role.user.username}")
        
        return Response({
            "message": "Admin account restored successfully",
            "admin_role": serializer.data
        })

    @action(detail=True, methods=['post'])
    def toggle_active(self, request, pk=None):
        admin_role = self.get_object()
        
        if admin_role.is_super_admin:
            return Response(
                {"error": "Cannot deactivate super admin"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        admin_role.is_active = not admin_role.is_active
        admin_role.save()
        
        if admin_role.user:
            admin_role.user.is_active = admin_role.is_active
            admin_role.user.save()
        
        serializer = self.get_serializer(admin_role)
        action_type = 'activated' if admin_role.is_active else 'deactivated'
        logger.info(f"{action_type.capitalize()} admin: {admin_role.user.username}")
        
        return Response({
            "message": f"Admin {action_type} successfully",
            "admin_role": serializer.data
        })

    @action(detail=False, methods=['get'])
    def deleted(self, request):
        deleted_admins = AdminRole.objects.select_related('user').filter(
            is_active=False
        ).order_by('-deleted_at')
        
        serializer = self.get_serializer(deleted_admins, many=True)
        
        return Response({
            "count": deleted_admins.count(),
            "results": serializer.data
        })

    @action(detail=True, methods=['delete'])
    def permanent_delete(self, request, pk=None):
        admin_role = AdminRole.objects.select_related('user').get(pk=pk)
        user = admin_role.user
        
        if admin_role.is_super_admin:
            return Response(
                {"error": "Cannot permanently delete super admin"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        logger.warning(
            f"PERMANENT DELETE requested for admin: {user.username} ({user.email}) "
            f"by {request.user.username}"
        )
        
        admin_role.delete()
        
        if user:
            user.delete()
        
        logger.warning(f"Permanently deleted admin and user: {user.username}")
        
        return Response(
            {
                "message": "Admin account permanently deleted",
                "warning": "This action cannot be undone"
            },
            status=status.HTTP_204_NO_CONTENT
        )

    @staticmethod
    def generate_password(length=12):
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        return password


# ─────────────────────────────────────────────────────────────────────────────
# FOOTER MANAGEMENT
# ─────────────────────────────────────────────────────────────────────────────

class FooterSectionViewSet(viewsets.ModelViewSet):
    permission_classes = [HasSectionPermission]
    serializer_class = FooterSectionSerializer
    queryset = FooterSection.objects.all()
    section_id = 'footer'
    required_level = 'view'
    pagination_class = None

    def get_queryset(self):
        queryset = FooterSection.objects.prefetch_related('links').all()
        active = self.request.query_params.get('active')
        if active is not None:
            queryset = queryset.filter(active=active.lower() == 'true')
        return queryset.order_by('display_order', 'title')

    def create(self, request, *args, **kwargs):
        self.required_level = 'edit'
        self.check_permissions(request)
        return super().create(request, *args, **kwargs)

    def update(self, request, *args, **kwargs):
        self.required_level = 'edit'
        self.check_permissions(request)
        return super().update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        self.required_level = 'edit'
        self.check_permissions(request)
        return super().destroy(request, *args, **kwargs)

    @action(detail=True, methods=['post'])
    def toggle_active(self, request, pk=None):
        self.required_level = 'edit'
        self.check_permissions(request)
        section = self.get_object()
        section.active = not section.active
        section.save()
        return Response({
            'message': f'Section {"activated" if section.active else "deactivated"} successfully',
            'section': FooterSectionSerializer(section).data
        })

    @action(detail=False, methods=['post'])
    def reorder(self, request):
        self.required_level = 'edit'
        self.check_permissions(request)
        try:
            for item in request.data.get('orders', []):
                section_id = item.get('id')
                order = item.get('order')
                if section_id and order is not None:
                    FooterSection.objects.filter(id=section_id).update(display_order=order)
            return Response({'message': 'Sections reordered successfully'})
        except Exception as e:
            return Response(
                {'error': f'Reorder failed: {str(e)}'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class FooterLinkViewSet(viewsets.ModelViewSet):
    permission_classes = [HasSectionPermission]
    serializer_class = FooterLinkSerializer
    queryset = FooterLink.objects.all()
    section_id = 'footer'
    required_level = 'view'
    pagination_class = None

    def get_queryset(self):
        queryset = FooterLink.objects.select_related('section').all()
        
        section_id = self.request.query_params.get('section')
        if section_id:
            queryset = queryset.filter(section_id=section_id)
        
        active = self.request.query_params.get('active')
        if active is not None:
            queryset = queryset.filter(active=active.lower() == 'true')
        
        return queryset.order_by('section__display_order', 'display_order', 'title')

    def create(self, request, *args, **kwargs):
        self.required_level = 'edit'
        self.check_permissions(request)
        return super().create(request, *args, **kwargs)

    def update(self, request, *args, **kwargs):
        self.required_level = 'edit'
        self.check_permissions(request)
        return super().update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        self.required_level = 'edit'
        self.check_permissions(request)
        return super().destroy(request, *args, **kwargs)

    @action(detail=True, methods=['post'])
    def toggle_active(self, request, pk=None):
        self.required_level = 'edit'
        self.check_permissions(request)
        link = self.get_object()
        link.active = not link.active
        link.save()
        return Response({
            'message': f'Link {"activated" if link.active else "deactivated"} successfully',
            'link': FooterLinkSerializer(link).data
        })

    @action(detail=False, methods=['post'])
    def reorder(self, request):
        self.required_level = 'edit'
        self.check_permissions(request)
        try:
            for item in request.data.get('orders', []):
                link_id = item.get('id')
                order = item.get('order')
                if link_id and order is not None:
                    FooterLink.objects.filter(id=link_id).update(display_order=order)
            return Response({'message': 'Links reordered successfully'})
        except Exception as e:
            return Response(
                {'error': f'Reorder failed: {str(e)}'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class FooterSettingsViewSet(viewsets.ViewSet):
    permission_classes = [HasSectionPermission]
    section_id = 'footer'
    required_level = 'view'

    def list(self, request):
        """Get footer settings"""
        settings = FooterSettings.get_settings()
        serializer = FooterSettingsSerializer(settings)
        return Response(serializer.data)

    def update(self, request, pk=None):
        """Update footer settings"""
        self.required_level = 'edit'
        self.check_permissions(request)
        
        settings = FooterSettings.get_settings()
        serializer = FooterSettingsSerializer(settings, data=request.data, partial=True)
        
        if serializer.is_valid():
            serializer.save()
            return Response({
                'message': 'Footer settings updated successfully',
                'settings': serializer.data
            })
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# ─────────────────────────────────────────────────────────────────────────────
# PUBLIC FOOTER ENDPOINT
# ─────────────────────────────────────────────────────────────────────────────

@api_view(['GET'])
@permission_classes([AllowAny])
def public_footer_data(request):
    """
    Public endpoint to get complete footer data for frontend
    """
    try:
        # Get active sections with their active links
        sections = FooterSection.objects.filter(active=True).prefetch_related(
            'links'
        ).order_by('display_order', 'title')
        
        # Get settings
        settings = FooterSettings.get_settings()
        
        # Serialize data
        sections_data = []
        for section in sections:
            active_links = section.links.filter(active=True).order_by('display_order', 'title')
            sections_data.append({
                'id': section.id,
                'title': section.title,
                'links': FooterLinkSerializer(active_links, many=True).data
            })
        
        return Response({
            'sections': sections_data,
            'settings': FooterSettingsSerializer(settings).data
        })
    except Exception as e:
        return Response(
            {'error': f'Failed to fetch footer data: {str(e)}'}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


# ─────────────────────────────────────────────────────────────────────────────
# PROMO CODE MANAGEMENT (ADMIN)
# ─────────────────────────────────────────────────────────────────────────────

class PromoCodeViewSet(viewsets.ModelViewSet):
    permission_classes = [HasSectionPermission]
    serializer_class = PromoCodeSerializer
    queryset = PromoCode.objects.all()
    section_id = 'premium'
    required_level = 'view'
    pagination_class = None

    def get_queryset(self):
        queryset = PromoCode.objects.select_related('plan', 'created_by').prefetch_related('usages').all()
        
        # Filter by active status
        active = self.request.query_params.get('active')
        if active is not None:
            queryset = queryset.filter(active=active.lower() == 'true')
        
        # Filter by plan
        plan_id = self.request.query_params.get('plan_id')
        if plan_id:
            queryset = queryset.filter(plan_id=plan_id)
        
        return queryset.order_by('-created_at')

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)

    def create(self, request, *args, **kwargs):
        self.required_level = 'edit'
        self.check_permissions(request)
        return super().create(request, *args, **kwargs)

    def update(self, request, *args, **kwargs):
        self.required_level = 'edit'
        self.check_permissions(request)
        return super().update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        self.required_level = 'edit'
        self.check_permissions(request)
        return super().destroy(request, *args, **kwargs)

    @action(detail=True, methods=['post'])
    def toggle_active(self, request, pk=None):
        self.required_level = 'edit'
        self.check_permissions(request)
        promo = self.get_object()
        promo.active = not promo.active
        promo.save()
        return Response({
            'message': f'Promo code {"activated" if promo.active else "deactivated"} successfully',
            'promo_code': PromoCodeSerializer(promo).data
        })

    @action(detail=True, methods=['get'])
    def usages(self, request, pk=None):
        """Get all usages for a specific promo code"""
        promo = self.get_object()
        usages = promo.usages.select_related('user', 'plan').all()
        
        page = self.paginate_queryset(usages)
        if page is not None:
            serializer = PromoCodeUsageSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        
        serializer = PromoCodeUsageSerializer(usages, many=True)
        return Response({
            'promo_code': promo.code,
            'total_usages': promo.current_uses,
            'max_uses': promo.max_uses,
            'remaining': promo.remaining_uses,
            'usages': serializer.data
        })

    @action(detail=False, methods=['get'])
    def statistics(self, request):
        """Get promo code statistics"""
        total_codes = PromoCode.objects.count()
        active_codes = PromoCode.objects.filter(active=True).count()
        total_redemptions = PromoCodeUsage.objects.count()
        
        # Most used codes
        most_used = PromoCode.objects.annotate(
            usage_count=Count('usages')
        ).order_by('-usage_count')[:5]
        
        return Response({
            'total_codes': total_codes,
            'active_codes': active_codes,
            'inactive_codes': total_codes - active_codes,
            'total_redemptions': total_redemptions,
            'most_used_codes': [{
                'code': code.code,
                'plan': code.plan.name,
                'uses': code.current_uses,
                'max_uses': code.max_uses
            } for code in most_used]
        })


# ─────────────────────────────────────────────────────────────────────────────
# MULTI-AUTHENTICATION BASE VIEW
# ─────────────────────────────────────────────────────────────────────────────

class MultipleAuthenticationView(APIView):
    """
    Base view that accepts multiple authentication methods:
    - JWT (for regular user login)
    - Token (for admin/alternative login)
    - Session (for Django admin)
    """
    authentication_classes = [JWTAuthentication, TokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]


# ─────────────────────────────────────────────────────────────────────────────
# PUBLIC PROMO CODE VALIDATION (for users during checkout)
# ─────────────────────────────────────────────────────────────────────────────

class ValidatePromoCodeView(MultipleAuthenticationView):
    """
    Validate a promo code for a specific plan
    Users call this before checkout to see if code is valid
    """
    def post(self, request):
        code = request.data.get('code', '').upper().strip()
        plan_id = request.data.get('plan_id', '').strip()
        
        if not code or not plan_id:
            return Response({
                'valid': False,
                'message': 'Code and plan ID are required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            promo = PromoCode.objects.select_related('plan').get(
                code=code,
                plan_id=plan_id
            )
            
            # Check if valid
            if not promo.is_valid:
                reasons = []
                if not promo.active:
                    reasons.append('Code is inactive')
                elif promo.valid_until and timezone.now() > promo.valid_until:
                    reasons.append('Code has expired')
                elif timezone.now() < promo.valid_from:
                    reasons.append('Code is not yet valid')
                elif promo.current_uses >= promo.max_uses:
                    reasons.append('Code usage limit reached')
                
                return Response({
                    'valid': False,
                    'message': ', '.join(reasons) if reasons else 'Code is not valid'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Check if user already used it
            if PromoCodeUsage.objects.filter(promo_code=promo, user=request.user).exists():
                return Response({
                    'valid': False,
                    'message': 'You have already used this promo code'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Calculate discounted price
            original_price = float(promo.plan.price)
            discount_amount = original_price * (promo.discount_percentage / 100)
            final_price = max(0, original_price - discount_amount)
            
            return Response({
                'valid': True,
                'promo_code': {
                    'code': promo.code,
                    'discount_percentage': promo.discount_percentage,
                    'plan': {
                        'id': promo.plan.plan_id,
                        'name': promo.plan.name,
                        'original_price': original_price,
                        'discount_amount': discount_amount,
                        'final_price': final_price,
                    }
                },
                'message': f'Promo code valid! {promo.discount_percentage}% off' if promo.discount_percentage < 100 else 'Promo code valid! Plan is FREE!'
            })
            
        except PromoCode.DoesNotExist:
            return Response({
                'valid': False,
                'message': 'Invalid promo code for this plan'
            }, status=status.HTTP_404_NOT_FOUND)


class RedeemPromoCodeView(MultipleAuthenticationView):
    """
    Redeem a promo code (mark as used)
    Call this after payment is successful
    """
    def post(self, request):
        code = request.data.get('code', '').upper().strip()
        plan_id = request.data.get('plan_id', '').strip()
        
        if not code or not plan_id:
            return Response({
                'error': 'Code and plan ID are required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            with transaction.atomic():
                promo = PromoCode.objects.select_for_update().select_related('plan').get(
                    code=code,
                    plan_id=plan_id
                )
                
                # Use the code
                success, message = promo.use_code(request.user)
                
                if success:
                    return Response({
                        'success': True,
                        'message': message,
                        'plan': {
                            'id': promo.plan.plan_id,
                            'name': promo.plan.name
                        }
                    })
                else:
                    return Response({
                        'success': False,
                        'error': message
                    }, status=status.HTTP_400_BAD_REQUEST)
                    
        except PromoCode.DoesNotExist:
            return Response({
                'success': False,
                'error': 'Invalid promo code'
            }, status=status.HTTP_404_NOT_FOUND)


# ─────────────────────────────────────────────────────────────────────────────
# RAZORPAY PAYMENT HANDLING - WITH FREE PLAN SUPPORT (✅ FIXED)
# ─────────────────────────────────────────────────────────────────────────────

class CreateOrderView(MultipleAuthenticationView):
    """
    Create Razorpay order for premium plan purchase.
    
    ✅ HANDLES FREE PLANS (100% discount) - directly activates without payment
    ✅ HANDLES PAID PLANS - creates Razorpay order
    """
    
    def post(self, request):
        try:
            plan_id = request.data.get('plan_id')
            promo_code = request.data.get('promo_code')
            
            if not plan_id:
                return Response(
                    {'error': 'Plan ID is required'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Get the plan
            try:
                plan = PremiumPlan.objects.get(plan_id=plan_id)
            except PremiumPlan.DoesNotExist:
                return Response(
                    {'error': 'Invalid plan'},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # ✅ FIX: Get profile using direct query
            try:
                profile = UserProfile.objects.select_related('user').get(user=request.user)
            except UserProfile.DoesNotExist:
                return Response(
                    {'error': 'User profile not found. Please complete your profile first.'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Calculate final amount
            original_amount = float(plan.price)
            final_amount = original_amount
            promo_discount = None
            promo = None  # Initialize promo variable
            
            # Apply promo code if provided
            if promo_code:
                try:
                    promo = PromoCode.objects.get(
                        code=promo_code.upper().strip(),
                        plan=plan,
                        active=True
                    )
                    
                    # Validate promo code
                    if not promo.is_valid:
                        return Response(
                            {'error': 'Promo code is not valid or has expired'},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                    
                    # Check if user already used it
                    if PromoCodeUsage.objects.filter(
                        promo_code=promo,
                        user=request.user
                    ).exists():
                        return Response(
                            {'error': 'You have already used this promo code'},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                    
                    # Calculate discount
                    final_amount = float(promo.apply_discount(original_amount))
                    promo_discount = {
                        'code': promo.code,
                        'percentage': promo.discount_percentage,
                        'amount_saved': original_amount - final_amount
                    }
                    
                except PromoCode.DoesNotExist:
                    return Response(
                        {'error': 'Invalid promo code for this plan'},
                        status=status.HTTP_404_NOT_FOUND
                    )
            
            # ✅ CRITICAL FIX: Handle FREE plans (100% discount)
            if final_amount == 0:
                # Directly activate premium without payment
                with transaction.atomic():
                    profile.premium = True
                    profile.premium_plan = plan.name
                    profile.premium_activated_at = timezone.now()
                    
                    # Calculate expiry based on plan type
                    months_map = {
                        'monthly': 1,
                        'quarterly': 3,
                        'biannual': 6,
                        'annual': 12
                    }
                    months = months_map.get(plan.plan_type, 1)
                    profile.premium_expires_at = timezone.now() + relativedelta(months=months)
                    profile.save()
                    
                    # 2. Mark promo code as used
                    if promo:
                        promo.use_code(request.user)
                
                return Response({
                    'success': True,
                    'free_activation': True,
                    'message': 'Premium activated successfully!',
                    'plan': {
                        'name': plan.name,
                        'duration': plan.duration,
                    },
                    'promo_discount': promo_discount,
                    'expires_at': profile.premium_expires_at.isoformat()
                }, status=status.HTTP_200_OK)
            
            # ✅ For paid plans: Create Razorpay order
            # Convert to paise (Razorpay requires amount in smallest currency unit)
            amount_in_paise = int(final_amount * 100)
            
            # Razorpay minimum amount check
            if amount_in_paise < 100:  # ₹1 minimum
                return Response(
                    {'error': 'Order amount is below minimum allowed (₹1)'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Create Razorpay order
            order = client.order.create({
                'amount': amount_in_paise,
                'currency': 'INR',
                'payment_capture': 1,
                'notes': {
                    'user_id': request.user.id,
                    'plan_id': plan.plan_id,
                    'promo_code': promo_code or '',
                }
            })
            
            return Response({
                'order_id': order['id'],
                'amount': amount_in_paise,
                'currency': 'INR',
                'razorpay_key': settings.RAZORPAY_KEY_ID,
                'plan_name': plan.name,
                'plan_duration': plan.duration,
                'original_price': original_amount,
                'final_price': final_amount,
                'promo_discount': promo_discount,
                'free_activation': False,
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            import traceback
            print("❌ Create Order Error:", traceback.format_exc())
            return Response(
                {'error': f'Failed to create order: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class VerifyPaymentView(MultipleAuthenticationView):
    """
    Verify Razorpay payment and activate premium subscription.
    """
    
    def post(self, request):
        try:
            # Get payment details from frontend
            razorpay_order_id = request.data.get('razorpay_order_id')
            razorpay_payment_id = request.data.get('razorpay_payment_id')
            razorpay_signature = request.data.get('razorpay_signature')
            plan_id = request.data.get('plan_id')
            
            if not all([razorpay_order_id, razorpay_payment_id, razorpay_signature, plan_id]):
                return Response(
                    {'error': 'Missing payment details'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Verify signature
            params_dict = {
                'razorpay_order_id': razorpay_order_id,
                'razorpay_payment_id': razorpay_payment_id,
                'razorpay_signature': razorpay_signature
            }
            
            try:
                client.utility.verify_payment_signature(params_dict)
            except razorpay.errors.SignatureVerificationError:
                return Response(
                    {'error': 'Payment verification failed'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Get plan
            try:
                plan = PremiumPlan.objects.get(plan_id=plan_id)
            except PremiumPlan.DoesNotExist:
                return Response(
                    {'error': 'Invalid plan'},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # ✅ FIX: Get profile using direct query
            try:
                profile = UserProfile.objects.select_related('user').get(user=request.user)
            except UserProfile.DoesNotExist:
                return Response(
                    {'error': 'User profile not found'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Activate premium subscription
            with transaction.atomic():
                profile.premium = True
                profile.premium_plan = plan.name
                profile.premium_activated_at = timezone.now()
                
                # Calculate expiry
                months_map = {
                    'monthly': 1,
                    'quarterly': 3,
                    'biannual': 6,
                    'annual': 12
                }
                months = months_map.get(plan.plan_type, 1)
                profile.premium_expires_at = timezone.now() + relativedelta(months=months)
                profile.save()
            
            return Response({
                'success': True,
                'message': 'Payment verified and premium activated!',
                'plan': {
                    'name': plan.name,
                    'duration': plan.duration,
                },
                'expires_at': profile.premium_expires_at.isoformat()
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            import traceback
            print("❌ Verify Payment Error:", traceback.format_exc())
            return Response(
                {'error': f'Payment verification failed: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            ) 
    
    def post(self, request):
        try:
            # Get payment details from frontend
            razorpay_order_id = request.data.get('razorpay_order_id')
            razorpay_payment_id = request.data.get('razorpay_payment_id')
            razorpay_signature = request.data.get('razorpay_signature')
            plan_id = request.data.get('plan_id')
            promo_code_str = request.data.get('promo_code')  # ✅ NEW: Get promo code
            
            if not all([razorpay_order_id, razorpay_payment_id, razorpay_signature, plan_id]):
                return Response(
                    {'error': 'Missing payment details'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Verify signature
            params_dict = {
                'razorpay_order_id': razorpay_order_id,
                'razorpay_payment_id': razorpay_payment_id,
                'razorpay_signature': razorpay_signature
            }
            
            try:
                client.utility.verify_payment_signature(params_dict)
            except razorpay.errors.SignatureVerificationError:
                return Response(
                    {'error': 'Payment verification failed'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Get plan
            try:
                plan = PremiumPlan.objects.get(plan_id=plan_id)
            except PremiumPlan.DoesNotExist:
                return Response(
                    {'error': 'Invalid plan'},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Get profile
            try:
                profile = UserProfile.objects.select_related('user').get(user=request.user)
            except UserProfile.DoesNotExist:
                return Response(
                    {'error': 'User profile not found'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # ✅ NEW: Get promo code if provided
            promo = None
            original_amount = float(plan.price)
            final_amount = original_amount
            discount_amount = 0.0
            
            if promo_code_str:
                try:
                    promo = PromoCode.objects.get(
                        code=promo_code_str.upper().strip(),
                        plan=plan
                    )
                    # Calculate discount
                    final_amount = float(promo.apply_discount(original_amount))
                    discount_amount = original_amount - final_amount
                except PromoCode.DoesNotExist:
                    logger.warning(f"Promo code {promo_code_str} not found during payment verification")
            
            # ✅ FIXED: Activate premium and save payment with promo code tracking
            with transaction.atomic():
                # 1. Activate premium on profile
                profile.premium = True
                profile.premium_plan = plan.name
                profile.premium_activated_at = timezone.now()
                
                # Calculate expiry
                months_map = {
                    'monthly': 1,
                    'quarterly': 3,
                    'biannual': 6,
                    'annual': 12
                }
                months = months_map.get(plan.plan_type, 1)
                profile.premium_expires_at = timezone.now() + relativedelta(months=months)
                profile.save()
                
                # 2. ✅ CRITICAL FIX: Save payment record WITH promo code
                from login.models import Payment  # Import Payment model
                
                Payment.objects.create(
                    user=request.user,
                    plan=plan,
                    promo_code=promo,  # ✅ Save promo code reference
                    razorpay_order_id=razorpay_order_id,
                    razorpay_payment_id=razorpay_payment_id,
                    original_amount=original_amount,  # ✅ Save original price
                    discount_amount=discount_amount,  # ✅ Save discount
                    amount=final_amount,  # ✅ Save final amount
                    status='SUCCESS',
                )
                
                # 3. ✅ Mark promo code as used
                if promo:
                    success, message = promo.use_code(request.user)
                    if not success:
                        logger.warning(f"Promo code marking failed: {message}")
            
            return Response({
                'success': True,
                'message': 'Payment verified and premium activated!',
                'plan': {
                    'name': plan.name,
                    'duration': plan.duration,
                },
                'promo_discount': {
                    'code': promo.code,
                    'amount_saved': discount_amount,
                    'percentage': promo.discount_percentage
                } if promo else None,
                'expires_at': profile.premium_expires_at.isoformat()
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            import traceback
            print("❌ Verify Payment Error:", traceback.format_exc())
            return Response(
                {'error': f'Payment verification failed: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )