from flask import Blueprint

mod_hello = Blueprint('mod_hello', __name__, template_folder='templates')


@mod_hello.route('/')
def do_hello():
    return 'hello :)'
