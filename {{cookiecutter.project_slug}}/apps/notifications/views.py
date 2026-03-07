from rest_framework.response import Response
from rest_framework import status
from apps.notifications.models import NotificationModel, FirebaseNotifiationModel
from apps.notifications.serializers import NotificationSerializer
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated



class NotificationView(APIView):
    permission_classes = [IsAuthenticated]

    serializers_class = NotificationSerializer

    def get(self, request):
        notifications = NotificationModel.objects.filter(user=request.user)
        serializer = NotificationSerializer(notifications, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    def post(self, request):
        serializer = NotificationSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(user=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class MarkAllNotificationsReadView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # Update all notifications for the authenticated user to is_read=True
        updated_count = NotificationModel.objects.filter(user=request.user, is_read=False).update(is_read=True)
        return Response({'message': f'{updated_count} notifications marked as read'}, status=status.HTTP_200_OK)


class FirebaseNotificationView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        device_token = request.data.get('device_token')
        if not device_token:
            return Response({'error': 'Device token is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        FirebaseNotifiationModel.objects.update_or_create(user=request.user, device_token=device_token)
        return Response({'message': 'Device token registered successfully'}, status=status.HTTP_201_CREATED)