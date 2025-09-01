# Testing the User Invitation System

This guide explains how to test the user invitation system in the Django CRM application.

## Prerequisites

1. **Django Server Running**: Make sure your Django server is running on `localhost:8000`
2. **MailHog Running**: Ensure MailHog is running to capture emails
3. **Database**: Make sure your database is up to date with migrations

## Testing Steps

### Step 1: Test the Management Command

Use the management command to create a test user and invitation:

```bash
python manage.py test_invitation --email test@example.com --org "Test Organization"
```

This will:
- Create a test organization
- Create a test user (inactive)
- Create a profile for the user
- Create an invitation
- Send an invitation email
- Display the invitation URL

### Step 2: Check MailHog

1. Open MailHog in your browser: `http://localhost:8025`
2. Look for the invitation email sent to `test@example.com`
3. Copy the invitation link from the email

### Step 3: Test the Invitation Link

1. **As Admin (Wrong Way)**: 
   - Click the invitation link while logged in as admin
   - This should NOT work and should show an error or redirect

2. **As New User (Correct Way)**:
   - Open a new incognito/private browser window
   - Navigate to the invitation link
   - You should see the set-password page
   - Set a password following the requirements:
     - At least 8 characters
     - Contains uppercase letter
     - Contains lowercase letter
     - Contains number

### Step 4: Verify User Activation

1. **Check Admin Panel**:
   - Go to Django admin: `http://localhost:8000/django/admin/`
   - Check Users section - the test user should now be active
   - Check Profiles section - the profile should now be active
   - Check User Invitations section - the invitation should show as accepted

2. **Check API Endpoints**:
   - Active users: `GET /api/users/` (should include the test user)
   - Inactive users: `GET /api/users/inactive/` (should not include the test user)

### Step 5: Test Login

1. Go to the login page
2. Use the test user credentials:
   - Email: `test@example.com`
   - Password: (the password you set)
3. You should be able to log in successfully

## Testing Different Scenarios

### Scenario 1: Expired Invitation

1. Create a user with an expired invitation
2. Try to access the invitation link
3. Should show "Invitation has expired" error

### Scenario 2: Already Used Invitation

1. Use an invitation link to set a password
2. Try to use the same link again
3. Should show "Invitation has already been used" error

### Scenario 3: Invalid Token

1. Modify the invitation URL to have an invalid token
2. Should show "Invalid invitation link" error

### Scenario 4: Admin Creates User Through Admin Panel

1. Log in to Django admin as admin
2. Create a new user through the User admin
3. Create a profile for the user through Profile admin
4. Check that invitation is automatically created and sent
5. Verify the user appears in inactive users list

## Troubleshooting

### Issue: Invitation Link Not Working

**Symptoms**: Clicking invitation link doesn't navigate to set-password page

**Possible Causes**:
1. Wrong domain in settings
2. Frontend routing issues
3. Backend URL configuration problems

**Solutions**:
1. Check `DOMAIN_NAME` in your environment variables
2. Verify the invitation URL format in MailHog
3. Check browser console for errors

### Issue: User Not Appearing in Inactive Users

**Symptoms**: New user doesn't show up in inactive users list

**Possible Causes**:
1. Profile not created
2. Profile.is_active set to True
3. Organization mismatch

**Solutions**:
1. Check if Profile exists for the user
2. Verify Profile.is_active is False
3. Ensure Profile.org matches the current organization

### Issue: Email Not Sent

**Symptoms**: No invitation email appears in MailHog

**Possible Causes**:
1. Celery not running
2. Email configuration issues
3. Task not queued properly

**Solutions**:
1. Start Celery worker: `celery -A crm worker -l info`
2. Check email settings in Django
3. Verify MailHog is running on port 1025

### Issue: User Cannot Set Password

**Symptoms**: User gets error when trying to set password

**Possible Causes**:
1. Invitation expired
2. Invitation already used
3. Password validation failed

**Solutions**:
1. Check invitation expiration date
2. Verify invitation status
3. Ensure password meets requirements (8+ chars, uppercase, lowercase, number)

## API Testing

### Test Set Password Endpoint

```bash
# Get invitation details
curl -X GET "http://localhost:8000/api/set-password/{token}/"

# Set password
curl -X POST "http://localhost:8000/api/set-password/{token}/" \
  -H "Content-Type: application/json" \
  -d '{"password": "TestPass123", "confirm_password": "TestPass123"}'
```

### Test User Management Endpoints

```bash
# List all users (admin only)
curl -X GET "http://localhost:8000/api/users/" \
  -H "Authorization: Bearer {your_token}"

# List inactive users (admin only)
curl -X GET "http://localhost:8000/api/users/inactive/" \
  -H "Authorization: Bearer {your_token}"
```

## Expected Behavior Summary

1. **New User Creation**: Automatically creates inactive user, profile, and invitation
2. **Invitation Email**: Sent automatically with valid link
3. **Password Setting**: User can set password through invitation link
4. **User Activation**: Both User and Profile become active after password set
5. **Status Updates**: User moves from inactive to active users list
6. **Admin Actions**: Admin can manually create invitations, activate users, etc.

## Security Features

- Invitation tokens expire after 7 days
- Tokens are unique and cannot be reused
- Only admin users can create invitations
- Invitation links are public but secure
- Password requirements enforced (8+ chars, uppercase, lowercase, number)
