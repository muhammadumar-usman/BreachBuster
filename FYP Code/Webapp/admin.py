# admin.py

from flask import Blueprint, render_template, flash, redirect, url_for
from database import get_pending_users, get_approved_users, approve_user, reject_user

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

@admin_bp.route('/')
def index():
    pending_users = get_pending_users()
    approved_users = get_approved_users()  # Retrieve approved users
    return render_template('admin.html', pending_users=pending_users, approved_users=approved_users)

@admin_bp.route('/approve/<username>', methods=['POST'])
def approve(username):
    if approve_user(username):
        flash(f'User {username} approved successfully', 'success')
    else:
        flash(f'Failed to approve user {username}', 'error')
    return redirect(url_for('admin.index'))

@admin_bp.route('/reject/<username>', methods=['POST'])
def reject(username):
    if reject_user(username):
        flash(f'User {username} rejected successfully', 'success')
    else:
        flash(f'Failed to reject user {username}', 'error')
    return redirect(url_for('admin.index'))
