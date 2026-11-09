export type NotificationType = 'default' | 'error' | 'success';

export type Notification = {
  actionHref?: string;
  actionLabel?: string;
  autoDismiss?: boolean;
  body?: string;
  id: number;
  message: string;
  title?: string;
  type: NotificationType;
};

export type ShowNotificationInput = {
  actionHref?: string;
  actionLabel?: string;
  autoDismiss?: boolean;
  body?: string;
  message: string;
  title?: string;
  type: NotificationType;
};

export type NotificationContextValue = {
  showNotification: (notification: ShowNotificationInput) => void;
};

export type RealtimeNotificationPayload = {
  body?: unknown;
  data?: RealtimeNotificationPayload;
  /** The domain event behind the frame, e.g. `tenant.domain_verified`. */
  event_type?: unknown;
  message?: unknown;
  notification?: RealtimeNotificationPayload;
  title?: unknown;
};
