from pyfcm import FCMNotification
from dotenv import load_dotenv
import os

load_dotenv(override=True)

push_service = FCMNotification(api_key=os.getenv('FCM_SERVER_KEY'))

def send_push_notification(device_token, title, body):
    result = push_service.notify_single_device(registration_id=device_token, message_title=title, message_body=body, sound='default')
    return result

