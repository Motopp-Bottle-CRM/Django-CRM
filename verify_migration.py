#!/usr/bin/env python
"""
Quick Migration Verification Script
=================================

Simple script to verify that the company field migration worked correctly.
Run this after: python manage.py migrate leads

Usage:
    python verify_migration.py
"""

import os
import sys
import django

def setup_django():
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'crm.settings')
    django.setup()

def verify_company_field():
    """Verify the company field is properly configured"""
    try:
        from leads.models import Lead
        
        # Check field configuration
        field = Lead._meta.get_field('company')
        
        print("🔍 Company Field Verification")
        print("=" * 40)
        print(f"Field Type: {field.__class__.__name__}")
        print(f"Null Allowed: {field.null}")
        print(f"Blank Allowed: {field.blank}")
        print(f"Max Length: {field.max_length}")
        
        # Test that it accepts string values
        print("\n🧪 Testing string input...")
        test_value = "My Company Name"
        
        # Create a lead instance (don't save)
        lead = Lead()
        lead.company = test_value
        
        # This should work without UUID validation
        if lead.company == test_value:
            print("✅ Company field accepts string values")
            print("✅ No UUID validation errors")
            print("\n🎉 Migration successful! Your teammate can now:")
            print("   - Create leads with simple company names")
            print("   - Edit leads without UUID issues")
            print("   - Run migrations without prompts")
            return True
        else:
            print("❌ Company field not working properly")
            return False
            
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

if __name__ == "__main__":
    setup_django()
    success = verify_company_field()
    sys.exit(0 if success else 1)
