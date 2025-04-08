def is_user_authenticated(request):
    if not request.user.is_authenticated:
        return False, "Please login first to perform this action."
    if not getattr(request.user, 'login_status', False):
        return False, "You are not logged in properly."
    if getattr(request.user, 'user_type', '').lower() != 'user':
        return False, "You are not authorized. User access required."
    return True, None
