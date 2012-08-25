from django.dispatch import Signal

user_logged_in = Signal(providing_args=["request", "user"])

# Typically followed by `user_logged_in` (unless, e-mail verification kicks in)
user_signed_up = Signal(providing_args=["request", "user"])

user_set_password = Signal(providing_args=["request", "user"])
user_changed_password = Signal(providing_args=["request", "user"])
user_reset_password = Signal(providing_args=["request", "user"])
