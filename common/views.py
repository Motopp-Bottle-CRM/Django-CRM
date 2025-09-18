import json
import secrets
from multiprocessing import context
from re import template

import requests
from django.contrib.auth.base_user import BaseUserManager
from django.contrib.auth.hashers import make_password
from rest_framework_simplejwt.tokens import RefreshToken
from django.conf import settings
from django.contrib.auth import authenticate, login
from django.contrib.auth.hashers import make_password
from django.db import transaction
from django.db.models import Q
from django.http.response import JsonResponse
from django.shortcuts import get_object_or_404, render
from django.utils import timezone
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from django.utils.translation import gettext as _
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import OpenApiExample, OpenApiParameter, extend_schema

# from common.external_auth import CustomDualAuthentication
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.pagination import LimitOffsetPagination
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.generics import GenericAPIView

from accounts.models import Account, Contact, Tags
from accounts.serializer import AccountSerializer
from cases.models import Case
from cases.serializer import CaseSerializer


##from common.custom_auth import JSONWebTokenAuthentication
from common import serializer, swagger_params1
from common.models import APISettings, Document, Org, Profile, User, UserInvitation
from common.serializer import *
from common.tasks import send_user_invitation_email
from common.permissions import IsNotDeletedUser

# from common.serializer import (
#     CreateUserSerializer,
#     PasswordChangeSerializer,
#     RegisterOrganizationSerializer,
# )
from common.tasks import (
    resend_activation_link_to_user,
    send_email_to_new_user,
    send_email_to_reset_password,
    send_email_user_delete,
)
from common.token_generator import account_activation_token

# from rest_framework_jwt.serializers import jwt_encode_handler
from common.utils import COUNTRIES, ROLES, jwt_payload_handler
from contacts.serializer import ContactSerializer
from leads.models import Lead
from leads.serializer import LeadSerializer
from opportunity.models import Opportunity
from opportunity.serializer import OpportunitySerializer
from teams.models import Teams
from teams.serializer import TeamsSerializer
from .serializer import SetPasswordSerializer

from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken
import uuid

class GetTeamsAndUsersView(APIView):

    permission_classes = (IsAuthenticated,)

    @extend_schema(tags=["Users"], parameters=swagger_params1.organization_params)
    def get(self, request, *args, **kwargs):
        data = {}
        teams = Teams.objects.filter(org=request.profile.org).order_by("-id")
        teams_data = TeamsSerializer(teams, many=True).data
        profiles = Profile.objects.filter(
            is_active=True, org=request.profile.org
        ).order_by("user__email")
        profiles_data = ProfileSerializer(profiles, many=True).data
        data["teams"] = teams_data
        data["profiles"] = profiles_data
        return Response(data)


class UsersListView(APIView, LimitOffsetPagination):

    permission_classes = (IsAuthenticated,IsNotDeletedUser)

    @extend_schema(tags=["Users"],
        parameters=swagger_params1.organization_params,
        request=UserCreateSwaggerSerializer,
    )
    def post(self, request, format=None):

        if self.request.profile.role != "ADMIN" and not self.request.user.is_superuser:
            return Response(
                {"error": True, "errors": "Permission Denied"},
                status=status.HTTP_403_FORBIDDEN,
            )
        else:
            params = request.data
            if params:
                user_serializer = CreateUserSerializer(
                    data=params, org=request.profile.org
                )
                address_serializer = BillingAddressSerializer(data=params)
                profile_serializer = CreateProfileSerializer(data=params)
                data = {}
                if not user_serializer.is_valid():
                    data["user_errors"] = dict(user_serializer.errors)
                if not profile_serializer.is_valid():
                    data["profile_errors"] = profile_serializer.errors
                if not address_serializer.is_valid():
                    data["address_errors"] = (address_serializer.errors,)
                if data:
                    return Response(
                        {"error": True, "errors": data},
                        status=status.HTTP_400_BAD_REQUEST,
                    )
                if address_serializer.is_valid():
                    address_obj = address_serializer.save()

                    # Check if user already exists
                    existing_user = User.objects.filter(email=params.get("email")).first()
                    if existing_user:
                        return Response(
                            {"error": True, "errors": {"email": "User with this email already exists"}},
                            status=status.HTTP_400_BAD_REQUEST,
                        )

                    # Create user without password (inactive)
                    user = user_serializer.save(
                        is_active=False,  # User will be activated after setting password
                    )
                    user.email = user.email
                    user.save()

                    # Create profile
                    profile = Profile.objects.create(
                        user=user,
                        date_of_joining=timezone.now(),
                        role=params.get("role"),
                        address=address_obj,
                        org=request.profile.org,
                        phone=params.get("phone"),
                        alternate_phone=params.get("alternate_phone"),
                        is_active=False,  # Profile starts as inactive until password is set
                    )
                    print(f"SUCCESS: Profile created for user: {user.email}, is_active: {profile.is_active}, org: {request.profile.org.id}")

                    # Create invitation
                    invitation = UserInvitation.objects.create(
                        email=user.email,
                        invited_by=request.profile,
                        org=request.profile.org,
                        role=params.get("role", "USER"),
                        expires_at=timezone.now() + timezone.timedelta(days=7),
                    )
                    print(f"SUCCESS: Invitation created for user: {user.email}, token: {invitation.token}")

                    # Send invitation email directly (bypassing Celery to avoid issues)
                    try:
                        print(f"Attempting to send invitation email directly for user: {user.email}")
                        send_user_invitation_email(invitation.id)
                        print(f"SUCCESS: Invitation email sent directly for user: {user.email}")
                    except Exception as e:
                        print(f"ERROR: Failed to send invitation email directly: {str(e)}")
                        import traceback
                        traceback.print_exc()

                    return Response(
                        {"error": False, "message": "User invitation sent successfully"},
                        status=status.HTTP_201_CREATED,
                    )

    @extend_schema(tags=["Users"], parameters=swagger_params1.user_list_params)
    def get(self, request, format=None):
        if self.request.profile.role != "ADMIN" and not self.request.user.is_superuser:
            return Response(
                {"error": True, "errors": "Permission Denied"},
                status=status.HTTP_403_FORBIDDEN,
            )
        queryset = Profile.objects.filter(org=request.profile.org).order_by("-id")
        params = request.query_params
        if params:
            if params.get("email"):
                queryset = queryset.filter(user__email__icontains=params.get("email"))
            if params.get("role"):
                queryset = queryset.filter(role=params.get("role"))
            if params.get("status"):
                queryset = queryset.filter(is_active=params.get("status"))

        context = {}
        queryset_active_users = queryset.filter(is_active=True)
        results_active_users = self.paginate_queryset(
            queryset_active_users.distinct(), self.request, view=self
        )
        active_users = ProfileSerializer(results_active_users, many=True).data
        if results_active_users:
            offset = queryset_active_users.filter(
                id__gte=results_active_users[-1].id
            ).count()
            if offset == queryset_active_users.count():
                offset = None
        else:
            offset = 0
        context["active_users"] = {
            "active_users_count": self.count,
            "active_users": active_users,
            "offset": offset,
        }

        queryset_inactive_users = queryset.filter(is_active=False)
        results_inactive_users = self.paginate_queryset(
            queryset_inactive_users.distinct(), self.request, view=self
        )
        inactive_users = ProfileSerializer(results_inactive_users, many=True).data
        if results_inactive_users:
            offset = queryset_inactive_users.filter(
                id__gte=results_inactive_users[-1].id
            ).count()
            if offset == queryset_inactive_users.count():
                offset = None
        else:
            offset = 0
        context["inactive_users"] = {
            "inactive_users_count": self.count,
            "inactive_users": inactive_users,
            "offset": offset,
        }

        context["admin_email"] = settings.ADMIN_EMAIL
        context["roles"] = ROLES
        context["status"] = [("True", "Active"), ("False", "In Active")]
        return Response(context)


class UserDetailView(APIView):
  #  permission_classes = (IsAuthenticated,)
    permission_classes = (IsAuthenticated,IsNotDeletedUser)

    def get_object(self, pk):
        profile = get_object_or_404(Profile, pk=pk)
        return profile

    @extend_schema(tags=["Users"], parameters=swagger_params1.organization_params)
    def get(self, request, pk, format=None):

        profile_obj = self.get_object(pk)
        if (
            self.request.profile.role != "ADMIN"
            and not self.request.profile.is_admin
            and self.request.profile.id != profile_obj.id
        ):
            return Response(
                {"error": True, "errors": "Permission Denied"},
                status=status.HTTP_403_FORBIDDEN,
            )
        if profile_obj.org != request.profile.org:
            return Response(
                {"error": True, "errors": "User company doesnot match with header...."},
                status=status.HTTP_403_FORBIDDEN,
            )
        assigned_data = Profile.objects.filter(
            org=request.profile.org, is_active=True
        ).values("id", "user__email")
        context = {}
        context["profile_obj"] = ProfileSerializer(profile_obj).data
        opportunity_list = Opportunity.objects.filter(assigned_to=profile_obj)
        context["opportunity_list"] = OpportunitySerializer(
            opportunity_list, many=True
        ).data
        contacts = Contact.objects.filter(assigned_to=profile_obj)
        context["contacts"] = ContactSerializer(contacts, many=True).data
        cases = Case.objects.filter(assigned_to=profile_obj)
        context["cases"] = CaseSerializer(cases, many=True).data
        context["assigned_data"] = assigned_data
        comments = profile_obj.user_comments.all()
        context["comments"] = CommentSerializer(comments, many=True).data
        context["countries"] = COUNTRIES
        return Response(
            {"error": False, "data": context},
            status=status.HTTP_200_OK,
        )

    @extend_schema(
        tags=["Users"],
        parameters=swagger_params1.organization_params,
        request=UserCreateSwaggerSerializer,
    )
    def put(self, request, pk, format=None):
        params = request.data
        profile = self.get_object(pk)
        address_obj = profile.address
        if (
            self.request.profile.role != "ADMIN"
            and not self.request.user.is_superuser
            and self.request.profile.id != profile.id
        ):
            return Response(
                {"error": True, "errors": "Permission Denied"},
                status=status.HTTP_403_FORBIDDEN,
            )

        if profile.org != request.profile.org:
            return Response(
                {"error": True, "errors": "User company doesnot match with header...."},
                status=status.HTTP_403_FORBIDDEN,
            )
        serializer = CreateUserSerializer(
            data=params, instance=profile.user, org=request.profile.org
        )
        address_serializer = BillingAddressSerializer(data=params, instance=address_obj)
        profile_serializer = CreateProfileSerializer(data=params, instance=profile)
        data = {}
        if not serializer.is_valid():
            data["contact_errors"] = serializer.errors
        if not address_serializer.is_valid():
            data["address_errors"] = (address_serializer.errors,)
        if not profile_serializer.is_valid():
            data["profile_errors"] = (profile_serializer.errors,)
        if data:
            data["error"] = True
            return Response(
                data,
                status=status.HTTP_400_BAD_REQUEST,
            )
        if address_serializer.is_valid():
            address_obj = address_serializer.save()
            user = serializer.save()
            user.email = user.email
            user.save()
        if profile_serializer.is_valid():
            profile = profile_serializer.save()
            return Response(
                {"error": False, "message": "User Updated Successfully"},
                status=status.HTTP_200_OK,
            )
        return Response(
            {"error": True, "errors": serializer.errors},
            status=status.HTTP_400_BAD_REQUEST,
        )
#Nataliia sprint3
    @extend_schema(tags=["Users"], parameters=swagger_params1.organization_params)
    def delete(self, request, pk, format=None):
        # only Admin can delete other USERs
        if self.request.profile.role != "ADMIN" and not self.request.profile.is_admin:
            return Response(
                {"error": True, "errors": "Permission Denied - you don`t have necessary access"},
                status=status.HTTP_403_FORBIDDEN,
            )

        self.object = self.get_object(pk)

        if self.object.id == request.profile.id:
            return Response(
                {"error": True, "errors": "Permission Denied - not possible to delete your own account"},
                status=status.HTTP_403_FORBIDDEN,
            )

     #     deleted_by = self.request.profile.user.email
    #  send_email_user_delete.delay(
      #      self.object.user.email,
       #     deleted_by=deleted_by,
        #)
# Nataliia comment - here should a notification be sent to deleted user that his account
# has been deleted - temporary commented! - maybe to fix later

        #erasing user data (email,password..)but keeping the user in the database
        deleted_user = User.objects.filter(id=self.object.user.id).first()
        if deleted_user:
            deleted_user.set_unusable_password()
            deleted_user.email = f"deleted_{uuid.uuid4()}@example.com"
            deleted_user.is_active = False
            deleted_user.is_deleted = True
            deleted_user.save()

        #disabling token - set in blacklist - to check! user will be logged out everywhere
        tokens = OutstandingToken.objects.filter(user=deleted_user)
        for token in tokens:
            BlacklistedToken.objects.get_or_create(token=token)

        #deleting related address
        deleted_address = self.object.address
        if deleted_address:
            deleted_address.delete()

        #deleting profile
        self.object.delete()

        return Response({"status": "success"}, status=status.HTTP_200_OK)

# end Nataliia sprint3

# check_header not working
class ApiHomeView(APIView):

    permission_classes = (IsAuthenticated,)

    @extend_schema(parameters=swagger_params1.organization_params)
    def get(self, request, format=None):
        accounts = Account.objects.filter(status="open", org=request.profile.org)
        contacts = Contact.objects.filter(org=request.profile.org)
        leads = Lead.objects.filter(org=request.profile.org).exclude(
            Q(status="converted") | Q(status="closed")
        )
        opportunities = Opportunity.objects.filter(org=request.profile.org)

        if self.request.profile.role != "ADMIN" and not self.request.user.is_superuser:
            accounts = accounts.filter(
                Q(assigned_to=self.request.profile)
                | Q(created_by=self.request.profile.user)
            )
            contacts = contacts.filter(
                Q(assigned_to__id__in=self.request.profile)
                | Q(created_by=self.request.profile.user)
            )
            leads = leads.filter(
                Q(assigned_to__id__in=self.request.profile)
                | Q(created_by=self.request.profile.user)
            ).exclude(status="closed")
            opportunities = opportunities.filter(
                Q(assigned_to__id__in=self.request.profile)
                | Q(created_by=self.request.profile.user)
            )
        context = {}
        context["accounts_count"] = accounts.count()
        context["contacts_count"] = contacts.count()
        context["leads_count"] = leads.count()
        context["opportunities_count"] = opportunities.count()
        context["accounts"] = AccountSerializer(accounts, many=True).data
        context["contacts"] = ContactSerializer(contacts, many=True).data
        context["leads"] = LeadSerializer(leads, many=True).data
        context["opportunities"] = OpportunitySerializer(opportunities, many=True).data
        return Response(context, status=status.HTTP_200_OK)


class OrgProfileCreateView(APIView):
    # authentication_classes = (CustomDualAuthentication,)
    permission_classes = (IsAuthenticated,)

    model1 = Org
    model2 = Profile
    serializer_class = OrgProfileCreateSerializer
    profile_serializer = CreateProfileSerializer

    @extend_schema(
        description="Organization and profile Creation api",
        request=OrgProfileCreateSerializer,
    )
    def post(self, request, format=None):
        data = request.data
        data["api_key"] = secrets.token_hex(16)
        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            org_obj = serializer.save()

            # now creating the profile
            profile_obj = self.model2.objects.create(user=request.user, org=org_obj)
            # now the current user is the admin of the newly created organisation
            profile_obj.is_organization_admin = True
            profile_obj.role = "ADMIN"
            profile_obj.save()

            return Response(
                {
                    "error": False,
                    "message": "New Org is Created.",
                    "org": self.serializer_class(org_obj).data,
                    "status": status.HTTP_201_CREATED,
                }
            )
        else:
            return Response(
                {
                    "error": True,
                    "errors": serializer.errors,
                    "status": status.HTTP_400_BAD_REQUEST,
                }
            )

    @extend_schema(
        description="Just Pass the token, will return ORG list, associated with user"
    )
    def get(self, request, format=None):
        """
        here we are passing profile list of the user, where org details also included
        """
        profile_list = Profile.objects.filter(user=request.user)
        serializer = ShowOrganizationListSerializer(profile_list, many=True)
        return Response(
            {
                "error": False,
                "status": status.HTTP_200_OK,
                "profile_org_list": serializer.data,
            }
        )


class ProfileView(APIView):
    permission_classes = (IsAuthenticated,)

    @extend_schema(parameters=swagger_params1.organization_params)
    def get(self, request, format=None):
        # profile=Profile.objects.get(user=request.user)
        context = {}
        context["user_obj"] = ProfileSerializer(self.request.profile).data
        return Response(context, status=status.HTTP_200_OK)


    @extend_schema(
        parameters=swagger_params1.organization_params,
        request=UserCreateSwaggerSerializer,
    )
    def put(self, request, *args, **kwargs):
        params = request.data.copy()

        # Map frontend "pincode" to backend "postcode"
        if "pincode" in params:
            params["postcode"] = params.pop("pincode")

        # Fetch profile of the logged-in user
        try:
            profile = Profile.objects.get(user=request.user)
        except Profile.DoesNotExist:
            return Response(
                {"error": True, "message": "Profile not found"},
                status=status.HTTP_404_NOT_FOUND,
            )

        # Get or create address
        address_obj = profile.address

        # Initialize serializers
        serializer = CreateUserSerializer(data=params, instance=profile.user, org=profile.org)
        if address_obj:
            address_serializer = BillingAddressSerializer(data=params, instance=address_obj)
        else:
            address_serializer = BillingAddressSerializer(data=params)

        profile_serializer = CreateProfileSerializer(data=params, instance=profile)

        errors = {}
        if not serializer.is_valid():
            errors["contact_errors"] = serializer.errors
        if not address_serializer.is_valid():
            errors["address_errors"] = address_serializer.errors
        if not profile_serializer.is_valid():
            errors["profile_errors"] = profile_serializer.errors

        if errors:
            errors["error"] = True
            return Response(errors, status=status.HTTP_400_BAD_REQUEST)

        # Save data after all serializers are valid
        address_obj = address_serializer.save()
        user = serializer.save()
        user.save()
        profile = profile_serializer.save()

        return Response(
            {"error": False, "message": "Profile updated successfully"},
            status=status.HTTP_200_OK,
        )




class DocumentListView(APIView, LimitOffsetPagination):
    # authentication_classes = (CustomDualAuthentication,)
    permission_classes = (IsAuthenticated,)
    model = Document

    def get_context_data(self, **kwargs):
        params = self.request.query_params
        queryset = self.model.objects.filter(org=self.request.profile.org).order_by(
            "-id"
        )
        if self.request.user.is_superuser or self.request.profile.role == "ADMIN":
            queryset = queryset
        else:
            if self.request.profile.documents():
                doc_ids = self.request.profile.documents().values_list("id", flat=True)
                shared_ids = queryset.filter(
                    Q(status="active") & Q(shared_to__id__in=[self.request.profile.id])
                ).values_list("id", flat=True)
                queryset = queryset.filter(Q(id__in=doc_ids) | Q(id__in=shared_ids))
            else:
                queryset = queryset.filter(
                    Q(status="active") & Q(shared_to__id__in=[self.request.profile.id])
                )

        request_post = params
        if request_post:
            if request_post.get("title"):
                queryset = queryset.filter(title__icontains=request_post.get("title"))
            if request_post.get("status"):
                queryset = queryset.filter(status=request_post.get("status"))

            if request_post.get("shared_to"):
                queryset = queryset.filter(
                    shared_to__id__in=json.loads(request_post.get("shared_to"))
                )

        context = {}
        profile_list = Profile.objects.filter(
            is_active=True, org=self.request.profile.org
        )
        if self.request.profile.role == "ADMIN" or self.request.profile.is_admin:
            profiles = profile_list.order_by("user__email")
        else:
            profiles = profile_list.filter(role="ADMIN").order_by("user__email")
        search = False
        if (
            params.get("document_file")
            or params.get("status")
            or params.get("shared_to")
        ):
            search = True
        context["search"] = search

        queryset_documents_active = queryset.filter(status="active")
        results_documents_active = self.paginate_queryset(
            queryset_documents_active.distinct(), self.request, view=self
        )
        documents_active = DocumentSerializer(results_documents_active, many=True).data
        if results_documents_active:
            offset = queryset_documents_active.filter(
                id__gte=results_documents_active[-1].id
            ).count()
            if offset == queryset_documents_active.count():
                offset = None
        else:
            offset = 0
        context["documents_active"] = {
            "documents_active_count": self.count,
            "documents_active": documents_active,
            "offset": offset,
        }

        queryset_documents_inactive = queryset.filter(status="inactive")
        results_documents_inactive = self.paginate_queryset(
            queryset_documents_inactive.distinct(), self.request, view=self
        )
        documents_inactive = DocumentSerializer(
            results_documents_inactive, many=True
        ).data
        if results_documents_inactive:
            offset = queryset_documents_inactive.filter(
                id__gte=results_documents_active[-1].id
            ).count()
            if offset == queryset_documents_inactive.count():
                offset = None
        else:
            offset = 0
        context["documents_inactive"] = {
            "documents_inactive_count": self.count,
            "documents_inactive": documents_inactive,
            "offset": offset,
        }

        context["users"] = ProfileSerializer(profiles, many=True).data
        context["status_choices"] = Document.DOCUMENT_STATUS_CHOICE
        return context

    @extend_schema(tags=["documents"], parameters=swagger_params1.document_get_params)
    def get(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        return Response(context)

    @extend_schema(
        tags=["documents"],
        parameters=swagger_params1.organization_params,
        request=DocumentCreateSwaggerSerializer,
    )
    def post(self, request, *args, **kwargs):
        params = request.data
        serializer = DocumentCreateSerializer(data=params, request_obj=request)
        if serializer.is_valid():
            doc = serializer.save(
                created_by=request.profile.user,
                org=request.profile.org,
                document_file=request.FILES.get("document_file"),
            )
            if params.get("shared_to"):
                assinged_to_list = params.get("shared_to")
                profiles = Profile.objects.filter(
                    id__in=assinged_to_list, org=request.profile.org, is_active=True
                )
                if profiles:
                    doc.shared_to.add(*profiles)
            if params.get("teams"):
                teams_list = params.get("teams")
                teams = Teams.objects.filter(id__in=teams_list, org=request.profile.org)
                if teams:
                    doc.teams.add(*teams)

            return Response(
                {"error": False, "message": "Document Created Successfully"},
                status=status.HTTP_201_CREATED,
            )
        return Response(
            {"error": True, "errors": serializer.errors},
            status=status.HTTP_400_BAD_REQUEST,
        )


class DocumentDetailView(APIView):
    # authentication_classes = (CustomDualAuthentication,)
    permission_classes = (IsAuthenticated,)

    def get_object(self, pk):
        return Document.objects.filter(id=pk).first()

    @extend_schema(tags=["documents"], parameters=swagger_params1.organization_params)
    def get(self, request, pk, format=None):
        self.object = self.get_object(pk)
        if not self.object:
            return Response(
                {"error": True, "errors": "Document does not exist"},
                status=status.HTTP_403_FORBIDDEN,
            )
        if self.object.org != self.request.profile.org:
            return Response(
                {"error": True, "errors": "User company doesnot match with header...."},
                status=status.HTTP_403_FORBIDDEN,
            )
        if self.request.profile.role != "ADMIN" and not self.request.user.is_superuser:
            if not (
                (self.request.profile == self.object.created_by)
                or (self.request.profile in self.object.shared_to.all())
            ):
                return Response(
                    {
                        "error": True,
                        "errors": "You do not have Permission to perform this action",
                    },
                    status=status.HTTP_403_FORBIDDEN,
                )
        profile_list = Profile.objects.filter(org=self.request.profile.org)
        if request.profile.role == "ADMIN" or request.user.is_superuser:
            profiles = profile_list.order_by("user__email")
        else:
            profiles = profile_list.filter(role="ADMIN").order_by("user__email")
        context = {}
        context.update(
            {
                "doc_obj": DocumentSerializer(self.object).data,
                "file_type_code": self.object.file_type()[1],
                "users": ProfileSerializer(profiles, many=True).data,
            }
        )
        return Response(context, status=status.HTTP_200_OK)

    @extend_schema(tags=["documents"], parameters=swagger_params1.organization_params)
    def delete(self, request, pk, format=None):
        document = self.get_object(pk)
        if not document:
            return Response(
                {"error": True, "errors": "Documdnt does not exist"},
                status=status.HTTP_403_FORBIDDEN,
            )
        if document.org != self.request.profile.org:
            return Response(
                {"error": True, "errors": "User company doesnot match with header...."},
                status=status.HTTP_403_FORBIDDEN,
            )

        if self.request.profile.role != "ADMIN" and not self.request.user.is_superuser:
            if (
                self.request.profile != document.created_by
            ):  # or (self.request.profile not in document.shared_to.all()):
                return Response(
                    {
                        "error": True,
                        "errors": "You do not have Permission to perform this action",
                    },
                    status=status.HTTP_403_FORBIDDEN,
                )
        document.delete()
        return Response(
            {"error": False, "message": "Document deleted Successfully"},
            status=status.HTTP_200_OK,
        )

    @extend_schema(
        tags=["documents"],
        parameters=swagger_params1.organization_params,
        request=DocumentEditSwaggerSerializer,
    )
    def put(self, request, pk, format=None):
        self.object = self.get_object(pk)
        params = request.data
        if not self.object:
            return Response(
                {"error": True, "errors": "Document does not exist"},
                status=status.HTTP_403_FORBIDDEN,
            )
        if self.object.org != self.request.profile.org:
            return Response(
                {"error": True, "errors": "User company doesnot match with header...."},
                status=status.HTTP_403_FORBIDDEN,
            )
        if self.request.profile.role != "ADMIN" and not self.request.user.is_superuser:
            if not (
                (self.request.profile == self.object.created_by)
                or (self.request.profile in self.object.shared_to.all())
            ):
                return Response(
                    {
                        "error": True,
                        "errors": "You do not have Permission to perform this action",
                    },
                    status=status.HTTP_403_FORBIDDEN,
                )
        serializer = DocumentCreateSerializer(
            data=params, instance=self.object, request_obj=request
        )
        if serializer.is_valid():
            doc = serializer.save(
                document_file=request.FILES.get("document_file"),
                status=params.get("status"),
                org=request.profile.org,
            )
            doc.shared_to.clear()
            if params.get("shared_to"):
                assinged_to_list = params.get("shared_to")
                profiles = Profile.objects.filter(
                    id__in=assinged_to_list, org=request.profile.org, is_active=True
                )
                if profiles:
                    doc.shared_to.add(*profiles)

            doc.teams.clear()
            if params.get("teams"):
                teams_list = params.get("teams")
                teams = Teams.objects.filter(id__in=teams_list, org=request.profile.org)
                if teams:
                    doc.teams.add(*teams)
            return Response(
                {"error": False, "message": "Document Updated Successfully"},
                status=status.HTTP_200_OK,
            )
        return Response(
            {"error": True, "errors": serializer.errors},
            status=status.HTTP_400_BAD_REQUEST,
        )


class UserStatusView(APIView):
    permission_classes = (IsAuthenticated,)

    @extend_schema(tags=["Users"],
        description="User Status View",
        parameters=swagger_params1.organization_params,
        request=UserUpdateStatusSwaggerSerializer,
    )
    def post(self, request, pk, format=None):
        if self.request.profile.role != "ADMIN" and not self.request.user.is_superuser:
            return Response(
                {
                    "error": True,
                    "errors": "You do not have permission to perform this action",
                },
                status=status.HTTP_403_FORBIDDEN,
            )
        params = request.data
        profiles = Profile.objects.filter(org=request.profile.org)
        profile = profiles.get(id=pk)

        if params.get("status"):
            user_status = params.get("status")
            if user_status == "Active":
                profile.is_active = True
            elif user_status == "Inactive":
                profile.is_active = False
            else:
                return Response(
                    {"error": True, "errors": "Please enter Valid Status for user"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            profile.save()

        context = {}
        active_profiles = profiles.filter(is_active=True)
        inactive_profiles = profiles.filter(is_active=False)
        context["active_profiles"] = ProfileSerializer(active_profiles, many=True).data
        context["inactive_profiles"] = ProfileSerializer(
            inactive_profiles, many=True
        ).data
        return Response(context)


class DomainList(APIView):
    model = APISettings
    permission_classes = (IsAuthenticated,)

    @extend_schema(tags=["Settings"], parameters=swagger_params1.organization_params)
    def get(self, request, *args, **kwargs):
        api_settings = APISettings.objects.filter(org=request.profile.org)
        users = Profile.objects.filter(
            is_active=True, org=request.profile.org
        ).order_by("user__email")
        return Response(
            {
                "error": False,
                "api_settings": APISettingsListSerializer(api_settings, many=True).data,
                "users": ProfileSerializer(users, many=True).data,
            },
            status=status.HTTP_200_OK,
        )

    @extend_schema(
        tags=["Settings"],
        parameters=swagger_params1.organization_params,
        request=APISettingsSwaggerSerializer,
    )
    def post(self, request, *args, **kwargs):
        params = request.data
        assign_to_list = []
        if params.get("lead_assigned_to"):
            assign_to_list = params.get("lead_assigned_to")
        serializer = APISettingsSerializer(data=params)
        if serializer.is_valid():
            settings_obj = serializer.save(
                created_by=request.profile.user, org=request.profile.org
            )
            if params.get("tags"):
                tags = params.get("tags")
                for tag in tags:
                    tag_obj = Tags.objects.filter(name=tag).first()
                    if not tag_obj:
                        tag_obj = Tags.objects.create(name=tag)
                    settings_obj.tags.add(tag_obj)
            if assign_to_list:
                settings_obj.lead_assigned_to.add(*assign_to_list)
            return Response(
                {"error": False, "message": "API key added sucessfully"},
                status=status.HTTP_201_CREATED,
            )
        return Response(
            {"error": True, "errors": serializer.errors},
            status=status.HTTP_400_BAD_REQUEST,
        )


class DomainDetailView(APIView):
    model = APISettings
    # authentication_classes = (CustomDualAuthentication,)
    permission_classes = (IsAuthenticated,)

    @extend_schema(tags=["Settings"], parameters=swagger_params1.organization_params)
    def get(self, request, pk, format=None):
        api_setting = self.get_object(pk)
        return Response(
            {"error": False, "domain": APISettingsListSerializer(api_setting).data},
            status=status.HTTP_200_OK,
        )

    @extend_schema(
        tags=["Settings"],
        parameters=swagger_params1.organization_params,
        request=APISettingsSwaggerSerializer,
    )
    def put(self, request, pk, **kwargs):
        api_setting = self.get_object(pk)
        params = request.data
        assign_to_list = []
        if params.get("lead_assigned_to"):
            assign_to_list = params.get("lead_assigned_to")
        serializer = APISettingsSerializer(data=params, instance=api_setting)
        if serializer.is_valid():
            api_setting = serializer.save()
            api_setting.tags.clear()
            api_setting.lead_assigned_to.clear()
            if params.get("tags"):
                tags = params.get("tags")
                for tag in tags:
                    tag_obj = Tags.objects.filter(name=tag).first()
                    if not tag_obj:
                        tag_obj = Tags.objects.create(name=tag)
                    api_setting.tags.add(tag_obj)
            if assign_to_list:
                api_setting.lead_assigned_to.add(*assign_to_list)
            return Response(
                {"error": False, "message": "API setting Updated sucessfully"},
                status=status.HTTP_200_OK,
            )
        return Response(
            {"error": True, "errors": serializer.errors},
            status=status.HTTP_400_BAD_REQUEST,
        )

    @extend_schema(tags=["Settings"], parameters=swagger_params1.organization_params)
    def delete(self, request, pk, **kwargs):
        api_setting = self.get_object(pk)
        if api_setting:
            api_setting.delete()
        return Response(
            {"error": False, "message": "API setting deleted sucessfully"},
            status=status.HTTP_200_OK,
        )


class GoogleLoginView(APIView):
    """
    Check for authentication with google
    post:
        Returns token of logged In user
    """
    permission_classes = []  # Allow unauthenticated access

    @extend_schema(
        description="Login through Google",
        request=SocialLoginSerializer,
    )
    def post(self, request):
        try:
            # Get token from request
            token = request.data.get("token")
            if not token:
                return Response(
                    {"error": "Token is required"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Validate the token with Google
            payload = {"access_token": token}
            r = requests.get(
                "https://www.googleapis.com/oauth2/v2/userinfo",
                params=payload,
                timeout=10
            )

            if r.status_code != 200:
                return Response(
                    {"error": "Invalid Google token"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            data = r.json()
            print("Google user data:", data)

            if "error" in data:
                return Response(
                    {"error": "Invalid or expired Google token"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Get or create user
            try:
                user = User.objects.get(email=data["email"])
            except User.DoesNotExist:
                user = User()
                user.email = data["email"]
                user.profile_pic = data.get("picture", "")
                # Provide random default password
                user.password = make_password(BaseUserManager().make_random_password())
                user.save()

            # Generate JWT token
            refresh_token = RefreshToken.for_user(user)
            access_token = refresh_token.access_token

            response = {
                "username": user.email,
                "access_token": str(access_token),
                "refresh_token": str(refresh_token),
                "user_id": user.id,
                "email": user.email,
                "profile_pic": user.profile_pic
            }
            return Response(response, status=status.HTTP_200_OK)

        except requests.RequestException as e:
            return Response(
                {"error": "Failed to validate Google token"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        except Exception as e:
            print(f"Google auth error: {str(e)}")
            return Response(
                {"error": "Authentication failed"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class FormLoginView(APIView):
    """
    Check for authentication with form login
    post:
        Returns token of logged In user
    """
    permission_classes = []  # No authentication required for login
    authentication_classes = []  # No authentication required for login

    @extend_schema(
        description="Login through Form",
        request=FormLoginSerializer,
    )
    def post(self, request):
        serializer = FormLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        tokens = serializer.save()

        return Response(tokens, status=status.HTTP_200_OK)


class SetPasswordView(GenericAPIView):
    """
    Set password for user who has no password yet
    """
    permission_classes = []  # No authentication required
    authentication_classes = []  # No authentication required

    serializer_class = SetPasswordSerializer

    @extend_schema(
        description="set password through Form",
        request=SetPasswordSerializer,
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(
            {"message": "Password set successfully"}, status=status.HTTP_200_OK
        )


class SetPasswordFromInvitationView(APIView):
    """View to handle password setting from invitation link"""
    permission_classes = []  # No authentication required for invitation links
    authentication_classes = []  # No authentication required for invitation links

    @extend_schema(
        tags=["api"],
        request=SetPasswordFromInvitationSerializer,
        responses={
            200: OpenApiExample(
                "Success",
                value={"error": False, "message": "Password set successfully"},
            ),
            400: OpenApiExample(
                "Error",
                value={"error": True, "errors": "Invalid or expired invitation"},
            ),
        },
    )
    def post(self, request, token):
        """Set password using invitation token"""
        try:
            invitation = UserInvitation.objects.get(token=token)

            # Check if invitation is valid
            if invitation.is_expired():
                return Response(
                    {"error": True, "errors": "Invitation has expired"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if invitation.is_accepted:
                return Response(
                    {"error": True, "errors": "Invitation has already been used"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Get the user
            user = User.objects.get(email=invitation.email)

            # Validate password
            serializer = SetPasswordFromInvitationSerializer(data=request.data)
            if not serializer.is_valid():
                return Response(
                    {"error": True, "errors": serializer.errors},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Set password and activate user
            user.set_password(serializer.validated_data['password'])
            user.is_active = True
            user.save()

            # Activate the profile as well
            try:
                profile = Profile.objects.get(user=user, org=invitation.org)
                profile.is_active = True
                profile.save()
                print(f"SUCCESS: Profile activated for user: {user.email}, profile.is_active: {profile.is_active}")
            except Profile.DoesNotExist:
                print(f"ERROR: Profile not found for user: {user.email}, org: {invitation.org}")
                # Profile doesn't exist, skip
                pass

            # Mark invitation as accepted
            invitation.is_accepted = True
            invitation.accepted_at = timezone.now()
            invitation.save()

            return Response(
                {"error": False, "message": "Password set successfully. You can now log in."},
                status=status.HTTP_200_OK,
            )

        except UserInvitation.DoesNotExist:
            return Response(
                {"error": True, "errors": "Invalid invitation link"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except User.DoesNotExist:
            return Response(
                {"error": True, "errors": "User not found"},
                status=status.HTTP_400_BAD_REQUEST,
            )

    def get(self, request, token):
        """Get invitation details for frontend"""
        try:
            invitation = UserInvitation.objects.get(token=token)

            if invitation.is_expired():
                return Response(
                    {"error": True, "errors": "Invitation has expired"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if invitation.is_accepted:
                return Response(
                    {"error": True, "errors": "Invitation has already been used"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            return Response({
                "error": False,
                "data": {
                    "email": invitation.email,
                    "org_name": invitation.org.name,
                    "role": invitation.get_role_display(),
                    "invited_by": invitation.invited_by.user.email,
                    "expires_at": invitation.expires_at,
                }
            })

        except UserInvitation.DoesNotExist:
            return Response(
                {"error": True, "errors": "Invalid invitation link"},
                status=status.HTTP_400_BAD_REQUEST,
            )


class InactiveUsersListView(APIView, LimitOffsetPagination):
    """View to list inactive users and their invitation status"""
    permission_classes = (IsAuthenticated, IsNotDeletedUser)

    @extend_schema(tags=["Users"], parameters=swagger_params1.organization_params)
    def get(self, request, format=None):
        if self.request.profile.role != "ADMIN" and not self.request.user.is_superuser:
            return Response(
                {"error": True, "errors": "Permission Denied"},
                status=status.HTTP_403_FORBIDDEN,
            )

        # Get inactive users from the organization
        queryset = Profile.objects.filter(
            org=request.profile.org,
            is_active=False
        ).order_by("-created_at")

        # Get pending invitations
        pending_invitations = UserInvitation.objects.filter(
            org=request.profile.org,
            is_accepted=False
        ).order_by("-created_at")

        # Paginate inactive users
        results_inactive_users = self.paginate_queryset(
            queryset.distinct(), self.request, view=self
        )
        inactive_users = ProfileSerializer(results_inactive_users, many=True).data

        # Add invitation status to each user
        for user_data in inactive_users:
            user_email = user_data.get('user', {}).get('email')
            if user_email:
                invitation = pending_invitations.filter(email=user_email).first()
                if invitation:
                    user_data['invitation_status'] = {
                        'token': invitation.token,
                        'invited_by': invitation.invited_by.user.email,
                        'invited_at': invitation.created_at,
                        'expires_at': invitation.expires_at,
                        'is_expired': invitation.is_expired(),
                        'role': invitation.get_role_display(),
                    }
                else:
                    user_data['invitation_status'] = None

        context = {
            "inactive_users": inactive_users,
            "inactive_users_count": queryset.count(),
            "pending_invitations_count": pending_invitations.count(),
            "expired_invitations_count": pending_invitations.filter(
                expires_at__lt=timezone.now()
            ).count(),
        }

        return Response(context)


class ResendInvitationView(APIView):
    """View to resend invitation email"""
    permission_classes = (IsAuthenticated, IsNotDeletedUser)

    @extend_schema(tags=["Users"], parameters=swagger_params1.organization_params)
    def post(self, request, user_id):
        if self.request.profile.role != "ADMIN" and not self.request.user.is_superuser:
            return Response(
                {"error": True, "errors": "Permission Denied"},
                status=status.HTTP_403_FORBIDDEN,
            )

        try:
            profile = Profile.objects.get(id=user_id, org=request.profile.org)
            user = profile.user

            if user.is_active:
                return Response(
                    {"error": True, "errors": "User is already active"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Check if there's an existing invitation
            existing_invitation = UserInvitation.objects.filter(
                email=user.email,
                org=request.profile.org,
                is_accepted=False
            ).first()

            if existing_invitation and not existing_invitation.is_expired():
                return Response(
                    {"error": True, "errors": "Active invitation already exists for this user"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Create new invitation or update existing one
            if existing_invitation:
                # Update existing invitation
                existing_invitation.token = generate_invitation_token()
                existing_invitation.expires_at = timezone.now() + timezone.timedelta(days=7)
                existing_invitation.invited_by = request.profile
                existing_invitation.save()
                invitation = existing_invitation
            else:
                # Create new invitation
                invitation = UserInvitation.objects.create(
                    email=user.email,
                    invited_by=request.profile,
                    org=request.profile.org,
                    role=profile.role,
                )

            # Send invitation email
            send_user_invitation_email.delay(invitation.id)

            return Response(
                {"error": False, "message": "Invitation sent successfully"},
                status=status.HTTP_200_OK,
            )

        except Profile.DoesNotExist:
            return Response(
                {"error": True, "errors": "User not found"},
                status=status.HTTP_404_NOT_FOUND,
            )
