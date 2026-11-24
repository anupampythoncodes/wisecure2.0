(function () {
  "use strict";

  const POLL_INTERVAL = 5000;
  const STORAGE_KEY = "wisecure_last_desktop_notification";

  let lastNotificationId = localStorage.getItem(STORAGE_KEY) || "";

  let isChecking = false;

  // Display desktop notification
  function showDesktopNotification(item) {
    if (!("Notification" in window)) {
      console.warn("Browser notifications are not supported.");
      return false;
    }

    if (Notification.permission !== "granted") {
      console.warn("Notification permission is not granted.");
      return false;
    }

    if (!item || !item.notification_id) {
      return false;
    }

    if (item.notification_id === lastNotificationId) {
      return false;
    }

    const risk = String(item.risk_level || "MEDIUM").toUpperCase();

    const title = "WiSecure - " + risk + " Risk Detected";

    const body =
      "Source: " +
      (item.source_ip || "Unknown") +
      "\nDestination: " +
      (item.destination_ip || "Unknown") +
      "\nProtocol: " +
      (item.protocol || "Unknown") +
      "\nReason: " +
      (item.reason || "Suspicious activity detected");

    try {
      const notification = new Notification(title, {
        body: body,
        tag: "wisecure-" + item.notification_id,
        requireInteraction: risk === "HIGH",
      });

      // Remember only after successful creation
      lastNotificationId = item.notification_id;

      localStorage.setItem(STORAGE_KEY, lastNotificationId);

      notification.onclick = function () {
        window.focus();
        window.location.assign("/notifications");
        notification.close();
      };

      notification.onerror = function (event) {
        console.error("WiSecure desktop notification error:", event);
      };

      console.log(
        "WiSecure desktop notification created:",
        item.notification_id,
      );

      return true;
    } catch (error) {
      console.error("Unable to create desktop notification:", error);

      return false;
    }
  }

  // Fetch latest unread notification
  async function checkNotifications() {
    if (isChecking) {
      return;
    }

    if (!("Notification" in window)) {
      return;
    }

    if (Notification.permission !== "granted") {
      return;
    }

    isChecking = true;

    try {
      const response = await fetch("/api/notifications/latest", {
        method: "GET",
        cache: "no-store",
        headers: {
          Accept: "application/json",
        },
      });

      if (!response.ok) {
        console.error("WiSecure API error:", response.status);
        return;
      }

      const data = await response.json();

      if (
        !data ||
        !Array.isArray(data.notifications) ||
        data.notifications.length === 0
      ) {
        return;
      }

      // API currently returns the latest unread notification
      const latest = data.notifications[0];

      if (!latest || !latest.notification_id) {
        return;
      }

      if (latest.notification_id === lastNotificationId) {
        return;
      }

      showDesktopNotification(latest);
    } catch (error) {
      console.error("WiSecure notification polling error:", error);
    } finally {
      isChecking = false;
    }
  }

  // Start notification monitoring
  function start() {
    console.log("WiSecure notification monitoring started.");

    if (!("Notification" in window)) {
      console.warn("This browser does not support desktop notifications.");
      return;
    }

    if (Notification.permission !== "granted") {
      console.warn("Enable Chrome notifications for WiSecure.");
      return;
    }

    // Initial notification check
    checkNotifications();

    // Check every five seconds
    setInterval(checkNotifications, POLL_INTERVAL);
  }

  // Wait until page is ready
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start, { once: true });
  } else {
    start();
  }
})();
