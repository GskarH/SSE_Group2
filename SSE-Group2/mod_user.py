from flask import Blueprint, render_template, redirect
from flask import request, g, session, make_response, flash, escape
import libmfa
import libuser
import libsession

mod_user = Blueprint('mod_user', __name__, template_folder='templates')


@mod_user.route('/login', methods=['GET', 'POST'])
def do_login():
    # clear session before each login attempt
    session.pop('username', None)
## Escape () added to remove special characters
## Changed by SSE_Group2
    if request.method == 'POST':
        username = escape(request.form.get('username'))
        password = escape(request.form.get('password'))
        otp = request.form.get('otp')

        # validate username and password
        username = libuser.login(username, password)
        if not username:
            flash("Invalid user or password")
            return render_template('user.login.mfa.html')

        # check if MFA is enabled for this user
        if libmfa.mfa_is_enabled(username):
            # validate OTP
            if not libmfa.mfa_validate(username, otp):
                flash("Invalid OTP")
                return render_template('user.login.mfa.html')

        # create session for the authenticated user
        response = make_response(redirect('/'))
        response = libsession.create(response=response, username=username)
        response = html.escape(response) # Changed by SSE_Group2
        return response

    return render_template('user.login.mfa.html')


@mod_user.route('/create', methods=['GET', 'POST'])
def do_create():
    # clear session before each create attempt
    session.pop('username', None)

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # validate username and password
        if not username or not password:
            flash("Please, complete username and password")
            return render_template('user.create.html')

        # create new user
        libuser.create(username, password)
        flash("User created. Please login.")
        return redirect('/user/login')

    return render_template('user.create.html')


@mod_user.route('/chpasswd', methods=['GET', 'POST'])
def do_chpasswd():
    # validate session
    if 'username' not in g.session:
        return redirect('/user/login')

    if request.method == 'POST':
        password = request.form.get('password')
        password_again = request.form.get('password_again')

        # validate password complexity
        if password != password_again:
            flash("The passwords don't match")
            return render_template('user.chpasswd.html')

        if not libuser.password_complexity(password):
            flash("The password doesn't comply with our \
            complexity requirements")
            return render_template('user.chpasswd.html')

        # update password for the authenticated user
        libuser.password_change(g.session['username'], password)
        flash("Password changed")

    return render_template('user.chpasswd.html')
