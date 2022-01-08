from flask import Blueprint, session, request, redirect
from mysql.connector.errors import IntegrityError

from tools import dbm, display_message


sm = Blueprint('shares_management', __name__, static_folder='static', template_folder='templates')

@sm.route('/add', methods=['POST'])
def share():
    if not 'username' in session:
        return redirect('/account/login')

    if request.form['owner'] == session['username']:
        try:
            dbm.share_password(int(request.form['id']), request.form['username'])    
        except IntegrityError:
            return display_message('Nie znaleziono użytkownika o podanej nazwie.', '/passwords')
        except Exception:
            return display_message('Błąd.', '/passwords')

    return redirect('/passwords')

@sm.route('/delete-as-owner', methods=['POST'])
def unshare_as_owner():
    if not 'username' in session:
        return redirect('/account/login')

    if request.form['owner'] == session['username']:
        dbm.unshare_password(int(request.form['share_id']))

    return redirect('/passwords')

@sm.route('/delete-as-receiver', methods=['POST'])
def unshare_as_receiver():
    if not 'username' in session:
        return redirect('/account/login')

    id_of_share = int(request.form['share_id'])
    receiver = dbm.get_user_that_password_is_shared_to(id_of_share)

    if receiver == session['username']:
        dbm.unshare_password(id_of_share)

    return redirect('/passwords')
