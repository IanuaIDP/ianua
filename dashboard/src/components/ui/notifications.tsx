'use client';

import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react';

import { hasRichNotificationContent } from '@/components/notifications/notification-content';
import { NotificationStack } from '@/components/notifications/notification-stack';
import {
  Notification,
  NotificationContextValue,
  ShowNotificationInput,
} from '@/types/notification';
import { COMPACT_NOTIFICATION_THRESHOLD } from '@/constants/notification';

const NotificationContext = createContext<NotificationContextValue | null>(null);

type NotificationProviderProps = {
  children: ReactNode;
};

let nextNotificationId = 0;

function createNotificationId() {
  nextNotificationId += 1;

  return nextNotificationId;
}

export function NotificationProvider({ children }: NotificationProviderProps) {
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const dismissTimeoutsRef = useRef(new Map<number, number>());

  const dismissNotification = useCallback((id: number) => {
    const pendingTimeoutId = dismissTimeoutsRef.current.get(id);

    if (pendingTimeoutId !== undefined) {
      window.clearTimeout(pendingTimeoutId);
      dismissTimeoutsRef.current.delete(id);
    }

    setNotifications((currentNotifications) =>
      currentNotifications.filter((notification) => notification.id !== id),
    );
  }, []);

  const dismissAllNotifications = useCallback(() => {
    for (const timeoutId of dismissTimeoutsRef.current.values()) {
      window.clearTimeout(timeoutId);
    }

    dismissTimeoutsRef.current.clear();
    setNotifications([]);
  }, []);

  const showNotification = useCallback(
    ({
      actionHref,
      actionLabel,
      autoDismiss,
      body,
      message,
      title,
      type,
    }: ShowNotificationInput) => {
      const id = createNotificationId();
      const nextNotification = {
        actionHref,
        actionLabel,
        autoDismiss,
        body,
        id,
        message,
        title,
        type,
      };

      setNotifications((currentNotifications) => [...currentNotifications, nextNotification]);

      const shouldAutoDismiss = autoDismiss ?? !hasRichNotificationContent(nextNotification);

      if (shouldAutoDismiss) {
        const timeoutId = window.setTimeout(() => dismissNotification(id), 5000);
        dismissTimeoutsRef.current.set(id, timeoutId);
      }
    },
    [dismissNotification],
  );

  const contextValue = useMemo(() => ({ showNotification }), [showNotification]);
  const richNotifications = notifications.filter(hasRichNotificationContent);
  const simpleNotifications = notifications.filter(
    (notification) => !hasRichNotificationContent(notification),
  );

  const persistentRichNotifications = richNotifications.filter(
    (notification) => !notification.autoDismiss,
  );
  const autoDismissingRichNotifications = richNotifications.filter(
    (notification) => notification.autoDismiss,
  );
  const hasCompactNotifications =
    persistentRichNotifications.length > COMPACT_NOTIFICATION_THRESHOLD;
  const latestPersistentRichNotification = persistentRichNotifications.at(-1);
  const displayedPersistentRichNotifications =
    hasCompactNotifications && latestPersistentRichNotification
      ? [latestPersistentRichNotification]
      : persistentRichNotifications;
  const displayedNotifications = [
    ...simpleNotifications,
    ...autoDismissingRichNotifications,
    ...displayedPersistentRichNotifications,
  ];
  const hiddenNotificationCount = hasCompactNotifications
    ? persistentRichNotifications.length - 1
    : 0;

  return (
    <NotificationContext.Provider value={contextValue}>
      {children}
      <NotificationStack
        compactSlotNotificationId={latestPersistentRichNotification?.id}
        hiddenNotificationCount={hiddenNotificationCount}
        notifications={displayedNotifications}
        notificationCount={notifications.length}
        onDismiss={dismissNotification}
        onDismissAll={dismissAllNotifications}
      />
    </NotificationContext.Provider>
  );
}

export function useNotification() {
  const context = useContext(NotificationContext);

  if (!context) {
    throw new Error('useNotification must be used within NotificationProvider.');
  }

  return context;
}
