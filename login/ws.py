# ws.py

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer

channel_layer = get_channel_layer()

def notify_user(email: str, payload: dict):
    group = "user_" + email.lower().replace("@", "_at_")
    async_to_sync(channel_layer.group_send)(
        group,
        {
            "type": "notification_event",
            "payload": payload,
        }
    )
