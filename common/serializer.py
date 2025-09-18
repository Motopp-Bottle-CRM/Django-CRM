import re

from django.contrib.auth import authenticate
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_decode
from rest_framework import serializers
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken

from common.models import (
    Address,
    APISettings,
    Attachments,
    Comment,
    Document,
    Org,
    Profile,
    User,
)


class OrganizationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Org
        fields = ("id", "name", "api_key")


class SocialLoginSerializer(serializers.Serializer):
    token = serializers.CharField()


class CommentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Comment
        fields = (
            "id",
            "comment",
            "commented_on",
            "commented_by",
            "account",
            "lead",
            "opportunity",
            "contact",
            "case",
            "task",
            "invoice",
            "event",
            "profile",
        )


class LeadCommentSerializer(serializers.ModelSerializer):
    commented_by = serializers.SerializerMethodField()


    class Meta:
        model = Comment
        fields = (
            "id",
            "comment",
            "commented_on",
            "commented_by",
            "lead",
        )
    def get_commented_by(self, obj):
        # Make sure commented_by and its user exist
        if obj.commented_by and obj.commented_by.user:
            return {
                "id": str(obj.commented_by.id),
                "email": obj.commented_by.user.email,
                "profile_pic": obj.commented_by.user.profile_pic,
            }
        return None



class OrgProfileCreateSerializer(serializers.ModelSerializer):
    """
    It is for creating organization
    """

    name = serializers.CharField(max_length=255)

    class Meta:
        model = Org
        fields = ["name"]
        extra_kwargs = {"name": {"required": True}}

    def validate_name(self, name):
        if bool(re.search(r"[~\!_.@#\$%\^&\*\ \(\)\+{}\":;'/\[\]]", name)):
            raise serializers.ValidationError(
                "organization name should not contain any special characters"
            )
        if Org.objects.filter(name=name).exists():
            raise serializers.ValidationError(
                "Organization already exists with this name"
            )
        return name


class ShowOrganizationListSerializer(serializers.ModelSerializer):
    """
    we are using it for show orjanization list
    """

    org = OrganizationSerializer()

    class Meta:
        model = Profile
        fields = (
            "role",
            "alternate_phone",
            "has_sales_access",
            "has_marketing_access",
            "is_organization_admin",
            "org",
        )


class BillingAddressSerializer(serializers.ModelSerializer):
    country = serializers.SerializerMethodField()

    def get_country(self, obj):
        return obj.get_country_display()

    class Meta:
        model = Address
        fields = ("address_line", "street", "city", "state", "postcode", "country")

    def __init__(self, *args, **kwargs):
        account_view = kwargs.pop("account", False)
        user_creation = kwargs.pop("user_creation", False)

        super().__init__(*args, **kwargs)

        if account_view:
            self.fields["address_line"].required = True
            self.fields["street"].required = True
            self.fields["city"].required = True
            self.fields["state"].required = True
            self.fields["postcode"].required = True
            self.fields["country"].required = True
        elif user_creation:
            # For user creation, make address fields optional
            self.fields["address_line"].required = False
            self.fields["street"].required = False
            self.fields["city"].required = False
            self.fields["state"].required = False
            self.fields["postcode"].required = False
            self.fields["country"].required = False


class CreateUserSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = (
            "email",
            "profile_pic",
        )

    def __init__(self, *args, **kwargs):
        self.org = kwargs.pop("org", None)
        super().__init__(*args, **kwargs)
        self.fields["email"].required = True

    def validate_email(self, email):
        if self.instance:
            if self.instance.email != email:
                if not Profile.objects.filter(user__email=email, org=self.org).exists():
                    return email
                raise serializers.ValidationError("Email already exists")
            return email

        # For new users, check if User already exists (not Profile)
        if User.objects.filter(email=email.lower()).exists():
            raise serializers.ValidationError("User with this email already exists")

        return email.lower()


class CreateProfileSerializer(serializers.ModelSerializer):
    # Add address fields as optional
    address_line = serializers.CharField(required=False, allow_blank=True)
    street = serializers.CharField(required=False, allow_blank=True)
    city = serializers.CharField(required=False, allow_blank=True)
    state = serializers.CharField(required=False, allow_blank=True)
    pincode = serializers.CharField(required=False, allow_blank=True)
    country = serializers.CharField(required=False, allow_blank=True)

    class Meta:
        model = Profile
        fields = (
            "role",
            "phone",
            "alternate_phone",
            "has_sales_access",
            "has_marketing_access",
            "is_organization_admin",
            "address_line",
            "street",
            "city",
            "state",
            "pincode",
            "country",
        )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["alternate_phone"].required = False
        self.fields["role"].required = True
        self.fields["phone"].required = True

    def validate_phone(self, value):
        """Custom validation for phone numbers to accept international formats"""
        if value:
            # Remove any spaces and ensure it starts with +
            cleaned_phone = value.strip()
            if not cleaned_phone.startswith('+'):
                # If it doesn't start with +, assume it's a local number and add +91
                cleaned_phone = '+91' + cleaned_phone
            return cleaned_phone
        return value

    def validate_alternate_phone(self, value):
        """Custom validation for alternate phone numbers to accept international formats"""
        if value:
            # Remove any spaces and ensure it starts with +
            cleaned_phone = value.strip()
            if not cleaned_phone.startswith('+'):
                # If it doesn't start with +, assume it's a local number and add +91
                cleaned_phone = '+91' + cleaned_phone
            return cleaned_phone
        return value


class UserSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ["id", "email", "profile_pic"]


class ProfileSerializer(serializers.ModelSerializer):
    address = BillingAddressSerializer()

    class Meta:
        model = Profile
        fields = (
            "id",
            "user_details",
            "role",
            "address",
            "has_marketing_access",
            "has_sales_access",
            "phone",
            "alternate_phone",
            "date_of_joining",
            "is_active",
        )


class AttachmentsSerializer(serializers.ModelSerializer):
    file_path = serializers.SerializerMethodField()


    def get_file_path(self, obj):
        request = self.context.get("request")
        if obj.attachment and request:
            return request.build_absolute_uri(obj.attachment.url)
        elif obj.attachment:
            return obj.attachment.url  # fallback if no request in context
        return None

    class Meta:
        model = Attachments
        fields = ["id", "attachment","file_name","file_path"]


class DocumentSerializer(serializers.ModelSerializer):
    shared_to = ProfileSerializer(read_only=True, many=True)
    teams = serializers.SerializerMethodField()
    created_by = UserSerializer()
    org = OrganizationSerializer()

    def get_teams(self, obj):
        return obj.teams.all().values()

    class Meta:
        model = Document
        fields = [
            "id",
            "title",
            "document_file",
            "status",
            "shared_to",
            "teams",
            "created_at",
            "created_by",
            "org",
        ]


class DocumentCreateSerializer(serializers.ModelSerializer):
    def __init__(self, *args, **kwargs):
        request_obj = kwargs.pop("request_obj", None)
        super().__init__(*args, **kwargs)
        self.fields["title"].required = True
        self.org = request_obj.profile.org

    def validate_title(self, title):
        if self.instance:
            if (
                Document.objects.filter(title__iexact=title, org=self.org)
                .exclude(id=self.instance.id)
                .exists()
            ):
                raise serializers.ValidationError(
                    "Document with this Title already exists"
                )
        if Document.objects.filter(title__iexact=title, org=self.org).exists():
            raise serializers.ValidationError("Document with this Title already exists")
        return title

    class Meta:
        model = Document
        fields = ["title", "document_file", "status", "org"]


def find_urls(string):
    # website_regex = "^((http|https)://)?([A-Za-z0-9.-]+\.[A-Za-z]{2,63})?$"  # (http(s)://)google.com or google.com
    # website_regex = "^https?://([A-Za-z0-9.-]+\.[A-Za-z]{2,63})?$"  # (http(s)://)google.com
    # http(s)://google.com
    website_regex = "^https?://[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$"
    # http(s)://google.com:8000
    website_regex_port = "^https?://[A-Za-z0-9.-]+\.[A-Za-z]{2,63}:[0-9]{2,4}$"
    url = re.findall(website_regex, string)
    url_port = re.findall(website_regex_port, string)
    if url and url[0] != "":
        return url
    return url_port


class APISettingsSerializer(serializers.ModelSerializer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    class Meta:
        model = APISettings
        fields = ("title", "website")

    def validate_website(self, website):
        if website and not (
            website.startswith("http://") or website.startswith("https://")
        ):
            raise serializers.ValidationError("Please provide valid schema")
        if not len(find_urls(website)) > 0:
            raise serializers.ValidationError(
                "Please provide a valid URL with schema and without trailing slash - Example: http://google.com"
            )
        return website


class APISettingsListSerializer(serializers.ModelSerializer):
    created_by = UserSerializer()
    lead_assigned_to = ProfileSerializer(read_only=True, many=True)
    tags = serializers.SerializerMethodField()
    org = OrganizationSerializer()

    def get_tags(self, obj):
        return obj.tags.all().values()

    class Meta:
        model = APISettings
        fields = [
            "title",
            "apikey",
            "website",
            "created_at",
            "created_by",
            "lead_assigned_to",
            "tags",
            "org",
        ]


class APISettingsSwaggerSerializer(serializers.ModelSerializer):
    class Meta:
        model = APISettings
        fields = [
            "title",
            "website",
            "lead_assigned_to",
            "tags",
        ]


class DocumentCreateSwaggerSerializer(serializers.ModelSerializer):
    class Meta:
        model = Document
        fields = [
            "title",
            "document_file",
            "teams",
            "shared_to",
        ]


class DocumentEditSwaggerSerializer(serializers.ModelSerializer):
    class Meta:
        model = Document
        fields = ["title", "document_file", "teams", "shared_to", "status"]


class UserCreateSwaggerSerializer(serializers.Serializer):
    """
    It is swagger for creating or updating user
    """

    ROLE_CHOICES = ["ADMIN", "USER"]

    email = serializers.CharField(max_length=1000, required=True)
    role = serializers.ChoiceField(choices=ROLE_CHOICES, required=True)
    phone = serializers.CharField(max_length=12)
    alternate_phone = serializers.CharField(max_length=12)
    address_line = serializers.CharField(max_length=10000, required=True)
    street = serializers.CharField(max_length=1000)
    city = serializers.CharField(max_length=1000)
    state = serializers.CharField(max_length=1000)
    pincode = serializers.CharField(max_length=1000)
    country = serializers.CharField(max_length=1000)


class UserUpdateStatusSwaggerSerializer(serializers.Serializer):

    STATUS_CHOICES = ["Active", "Inactive"]

    status = serializers.ChoiceField(choices=STATUS_CHOICES, required=True)


class SetPasswordSerializer(serializers.Serializer):
    """
    Serializer for setting a new password for a user who has no password yet.

    """

    User = get_user_model()

    email = serializers.EmailField(required=True, write_only=True)
    password = serializers.CharField(max_length=128, write_only=True, required=True)
    confirmPassword = serializers.CharField(
        max_length=128, write_only=True, required=True
    )

    def validate_password(self, value):
        """Validate password strength."""
        if len(value) < 8:
            raise serializers.ValidationError(
                "Password must be at least 8 characters long."
            )

        if not re.search(r"[A-Z]", value):
            raise serializers.ValidationError(
                "Password must contain at least one uppercase letter."
            )
        if not re.search(r"[a-z]", value):
            raise serializers.ValidationError(
                "Password must contain at least one lowercase letter."
            )
        if not re.search(r"[0-9]", value):
            raise serializers.ValidationError(
                "Password must contain at least one digit."
            )
        return value

    def validate(self, attrs):
        """Cross-field validation."""
        if attrs["password"] != attrs["confirmPassword"]:
            raise serializers.ValidationError(
                {"confirmPassword": "Passwords do not match."}
            )
        return attrs

    def save(self, **kwargs):
        email = self.validated_data["email"]
        password = self.validated_data["password"]
        confirm_password = self.validated_data["confirmPassword"]

        try:
            user = User.objects.get(email=email)

        except User.DoesNotExist:
            raise serializers.ValidationError(
                {"email": "User with this email does not exist."}
            )

        user.set_password(password)
        user.is_active = True  # Activate the user if they were inactive
        user.save()

        # Also activate the profile
        try:
            from common.models import Profile
            profile = Profile.objects.get(user=user)
            profile.is_active = True
            profile.save()
            print(f"SUCCESS: Profile activated for user: {user.email}, profile.is_active: {profile.is_active}")
        except Profile.DoesNotExist:
            print(f"WARNING: No profile found for user: {user.email}")

        return user


class FormLoginSerializer(serializers.Serializer):
    """
    Serializer for user login.
    """

    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True, write_only=True)

    def validate(self, attrs):
        email = attrs.get("email")
        password = attrs.get("password")
        if not email or not password:
            raise serializers.ValidationError("Email and password are required.")

        print(f"DEBUG: Attempting to authenticate user: {email}")
        user = authenticate(username=email, password=password)
        print(f"DEBUG: Authentication result: {user}")

        if user is None:
            print(f"DEBUG: Authentication failed for user: {email}")
            raise serializers.ValidationError("Invalid email or password.")

        print(f"DEBUG: User found: {user.email}, is_active: {user.is_active}")
        if not user.is_active:
            print(f"DEBUG: User account is inactive: {user.email}")
            raise serializers.ValidationError("User account is inactive.")

        attrs["user"] = user
        return attrs

    def create_tokens(self, user):
        """
        Create JWT tokens for the authenticated user.
        """
        refresh = RefreshToken.for_user(user)
        access = refresh.access_token

        access["user_id"] = str(user.id)
        access["email"] = user.email
        
        # Get the user's primary organization
        try:
            profile = Profile.objects.filter(user=user, is_active=True).first()
            print(f"DEBUG: Found profile for user {user.email}: {profile}")
            if profile:
                print(f"DEBUG: Profile org: {profile.org}")
                org_id = str(profile.org.id) if profile.org else None
            else:
                print(f"DEBUG: No active profile found for user {user.email}")
                org_id = None
        except Exception as e:
            print(f"DEBUG: Error getting profile for user {user.email}: {e}")
            org_id = None
            
        return {
            "refresh": str(refresh),
            "access": str(access),
            "user_id": str(user.id),
            "email": user.email,
            "org_id": org_id,
        }

    def save(self):
        user = self.validated_data["user"]
        tokens = self.create_tokens(user)
        return tokens


class SetPasswordFromInvitationSerializer(serializers.Serializer):
    """Serializer for setting password from invitation"""
    password = serializers.CharField(write_only=True, min_length=8)
    confirm_password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        if attrs['password'] != attrs['confirm_password']:
            raise serializers.ValidationError("Passwords don't match.")
        return attrs

    def validate_password(self, value):
        # Basic password validation
        if len(value) < 8:
            raise serializers.ValidationError("Password must be at least 8 characters long.")
        if not re.search(r'[A-Z]', value):
            raise serializers.ValidationError("Password must contain at least one uppercase letter.")
        if not re.search(r'[a-z]', value):
            raise serializers.ValidationError("Password must contain at least one lowercase letter.")
        if not re.search(r'\d', value):
            raise serializers.ValidationError("Password must contain at least one digit.")
        return value