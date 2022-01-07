from flask import Blueprint, session, request, redirect, render_template

from tools import dbm, display_message


pm = Blueprint('password_management', __name__, static_folder='static', template_folder='templates')

@pm.route('/action', methods=['POST'])
def choose_action():
    if not 'username' in session:
        return redirect('/account/login')

    password_id = int(request.form['id'])
    password_name = request.form['name']
    password_value = request.form['value']
    password_owner = request.form['owner']
    action = request.form['action']
    
    if action == 'update':
        return render_template(
            'password_update.html',
            id=password_id,
            name=password_name,
            value=password_value,
            owner=password_owner
        )
        
    elif action == 'delete':
        return render_template(
            'password_delete.html',
            id=password_id,
            name=password_name,
            value=password_value,
            owner=password_owner
        )
        
    elif action == 'share':
        return render_template(
            'sharing_panel.html',
            users_and_share_ids=dbm.get_users_that_got_password_through_sharing_and_share_ids(password_id),
            passwords_id=password_id,
            passwords_name=password_name,
            owner=password_owner
        )

    else:
        return redirect('/passwords')

@pm.route('/add', methods=['POST'])
def add_password():
    if not 'username' in session:
        return redirect('/account/login')

    try:
        dbm.add_password(
            session['username'],
            request.form['name'],
            request.form['password']
        )

    except:
        return display_message(
            'Wystąpił błąd. Prawdopodobnie został spowodowany zbyt długą nazwą hasła.',
            '/passwords'
        )

    return redirect('/passwords')

@pm.route('/update', methods=['POST'])
def update_password(): 
    if not 'username' in session:
        return redirect('/account/login')
    
    if request.form['owner'] == session['username']:
        try:
            dbm.update_password(
                int(request.form['id']),
                request.form['name'],
                request.form['value']
            )

        except:
            return display_message(
                'Wystąpił błąd. Prawdopodobnie został spowodowany zbyt długą nazwą hasła.',
                '/passwords'
            )

    return redirect('/passwords')

@pm.route('/delete', methods=['POST'])
def delete_password():
    if not 'username' in session:
        return redirect('/account/login')

    if request.form['owner'] == session['username']:
        dbm.delete_password(int(request.form['id']))
    
    return redirect('/passwords') 
