import { Notification, ShowNotificationInput } from '@/types/notification';

export function hasRichNotificationContent(notification: ShowNotificationInput | Notification) {
  return Boolean(notification.title || notification.body || notification.actionHref);
}
