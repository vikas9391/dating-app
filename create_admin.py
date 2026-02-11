import os
import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
django.setup()

from django.contrib.auth import get_user_model

User = get_user_model()

if not User.objects.filter(username="admin").exists():
    User.objects.create_superuser(
        "admin",
        "datingapp896@gmail.com",
        "123123a@"
    )
    print("Admin created successfully!")
else:
    print("Admin already exists.")
