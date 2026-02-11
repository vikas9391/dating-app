# backend/login/models_photos.py
from django.db import models
from django.conf import settings

class UserPhoto(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    image = models.ImageField(upload_to="uploads/")  # -> MEDIA_ROOT/uploads/...
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return f"{self.user.username} - {self.image.name}"

    @property
    def url(self) -> str:
        if self.image and hasattr(self.image, "url"):
            return self.image.url
        return ""
