import django.dispatch


user_logged_in        = django.dispatch.Signal(providing_args=["request", "user"])
user_set_password = django.dispatch.Signal(providing_args=["request", "user"])
user_changed_password = django.dispatch.Signal(providing_args=["request", "user"])
user_reset_password = django.dispatch.Signal(providing_args=["request", "user"])
user_signed_up        = django.dispatch.Signal(providing_args=["request", "user"])
