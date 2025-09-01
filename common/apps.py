from django.apps import AppConfig


class CommonConfig(AppConfig):
    name = "common"
    
    def ready(self):
        """Import signals when the app is ready"""
        try:
            import common.signals
            print("SUCCESS: Common signals loaded successfully")
        except Exception as e:
            print(f"ERROR: Failed to load common signals: {str(e)}")
            import traceback
            traceback.print_exc()
