import logging

class EventBus:
    """
    A simple thread-safe Event Bus for decoupled communication between modules.
    """
    def __init__(self):
        self.subscribers = {}
        self.logger = logging.getLogger("EventBus")

    def subscribe(self, event_type, callback):
        if event_type not in self.subscribers:
            self.subscribers[event_type] = []
        self.subscribers[event_type].append(callback)
        self.logger.debug(f"Subscribed to {event_type}")

    def emit(self, event_type, data):
        if event_type in self.subscribers:
            for callback in self.subscribers[event_type]:
                try:
                    callback(data)
                except Exception as e:
                    self.logger.error(f"Error in callback for {event_type}: {e}")
        else:
            self.logger.debug(f"No subscribers for {event_type}")

# Singleton instance for global use
bus = EventBus()
