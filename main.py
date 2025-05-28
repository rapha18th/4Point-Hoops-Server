import os
import io
import uuid
import re
import time
import tempfile
import requests
import json
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS, cross_origin
from firebase_admin import credentials, db, storage, auth
import firebase_admin
import logging
import traceback
import unicodedata # For accent normalization
from bs4 import BeautifulSoup, Comment

try:
    from BRScraper import nba
    BRSCRAPER_AVAILABLE = True
except ImportError:
    BRSCRAPER_AVAILABLE = False
    logging.error("BRScraper not found. Please install with: `pip install BRScraper`")

app = Flask(__name__)
CORS(app)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

Firebase_DB = os.getenv("Firebase_DB")
Firebase_Storage = os.getenv("Firebase_Storage")

FIREBASE_INITIALIZED = False

try:
    credentials_json_string = os.environ.get("FIREBASE")
    if credentials_json_string:
        credentials_json = json.loads(credentials_json_string)
        cred = credentials.Certificate(credentials_json)
        firebase_admin.initialize_app(cred, {
            'databaseURL': f'{Firebase_DB}',
            'storageBucket': f'{Firebase_Storage}'
        })
        FIREBASE_INITIALIZED = True
        logging.info("Firebase Admin SDK initialized successfully.")
    else:
        logging.warning("FIREBASE secret not set. Firebase Admin SDK not initialized.")
except Exception as e:
    logging.error(f"Error initializing Firebase: {e}")
    traceback.print_exc()

bucket = storage.bucket() if FIREBASE_INITIALIZED else None

def verify_token(token):
    try:
        decoded_token = auth.verify_id_token(token)
        return decoded_token['uid']
    except Exception as e:
        logging.error(f"Token verification failed: {e}")
        return None

def verify_admin(auth_header):
    if not auth_header or not auth_header.startswith('Bearer '):
        raise ValueError('Invalid token format')
    token = auth_header.split(' ')[1]
    uid = verify_token(token)
    if not uid:
        raise PermissionError('Invalid user token')
    user_ref = db.reference(f'users/{uid}')
    user_data = user_ref.get()
    if not user_data or not user_data.get('is_admin', False):
        raise PermissionError('Admin access required')
    return uid

def credit_required(cost=1):
    def decorator(f):
        def wrapper(*args, **kwargs):
            auth_header = request.headers.get('Authorization', '')
            if not auth_header.startswith('Bearer '):
                return jsonify({'error': 'Authorization header missing or malformed'}), 401
            token = auth_header.split(' ')[1]
            uid = verify_token(token)
            if not uid:
                return jsonify({'error': 'Invalid or expired token'}), 401

            user_ref = db.reference(f'users/{uid}')
            user_data = user_ref.get()
            if not user_data:
                return jsonify({'error': 'User not found'}), 404
            
            if user_data.get('suspended', False):
                return jsonify({'error': 'Account suspended. Please contact support.'}), 403

            current_credits = user_data.get('credits', 0)
            if current_credits < cost:
                return jsonify({'error': f'Insufficient credits. You need {cost} credits, but have {current_credits}.'}), 403

            try:
                if cost > 0:
                    user_ref.update({'credits': current_credits - cost})
                    logging.info(f"Deducted {cost} credits from user {uid}. New balance: {current_credits - cost}")
                return f(*args, **kwargs)
            except Exception as e:
                logging.error(f"Failed to process credits for user {uid}: {e}")
                return jsonify({'error': 'Failed to process credits. Please try again.'}), 500
        wrapper.__name__ = f.__name__
        return wrapper
    return decorator


@app.route('/api/auth/signup', methods=['POST'])
def signup():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400

        user = auth.create_user(email=email, password=password)
        user_ref = db.reference(f'users/{user.uid}')
        user_data = {
            'email': email,
            'credits': 10,
            'is_admin': False,
            'created_at': datetime.utcnow().isoformat()
        }
        user_ref.set(user_data)
        return jsonify({
            'success': True,
            'user': {
                'uid': user.uid,
                **user_data
            }
        }), 201
    except Exception as e:
        logging.error(f"Signup error: {e}")
        return jsonify({'error': str(e)}), 400

@app.route('/api/user/profile', methods=['GET'])
def get_user_profile():
    try:
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing or invalid token'}), 401

        token = auth_header.split(' ')[1]
        uid = verify_token(token)
        if not uid:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        user_data = db.reference(f'users/{uid}').get()
        if not user_data:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify({
            'uid': uid,
            'email': user_data.get('email'),
            'credits': user_data.get('credits', 0),
            'is_admin': user_data.get('is_admin', False)
        })
    except Exception as e:
        logging.error(f"Error fetching user profile: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/auth/google-signin', methods=['POST'])
def google_signin():
    try:
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing or invalid token'}), 401
        
        token = auth_header.split(' ')[1]
        decoded_token = auth.verify_id_token(token)
        uid = decoded_token['uid']
        email = decoded_token.get('email')

        user_ref = db.reference(f'users/{uid}')
        user_data = user_ref.get()

        if not user_data:
            user_data = {
                'email': email,
                'credits': 10,
                'is_admin': False,
                'created_at': datetime.utcnow().isoformat(),
            }
            user_ref.set(user_data)

        return jsonify({
            'success': True,
            'user': {
                'uid': uid,
                **user_data
            }
        }), 200

    except Exception as e:
        logging.error(f"Google sign-in error: {e}")
        return jsonify({'error': str(e)}), 400 

@app.route('/api/user/request-credits', methods=['POST'])
@credit_required(cost=0)
def request_credits():
    try:
        auth_header = request.headers.get('Authorization', '')
        token = auth_header.split(' ')[1]
        uid = verify_token(token)
        
        data = request.get_json()
        requested_credits = data.get('requested_credits')
        if requested_credits is None:
            return jsonify({'error': 'requested_credits is required'}), 400

        credit_request_ref = db.reference('credit_requests').push()
        credit_request_ref.set({
            'user_id': uid,
            'requested_credits': requested_credits,
            'status': 'pending',
            'requested_at': datetime.utcnow().isoformat()
        })
        return jsonify({'success': True, 'request_id': credit_request_ref.key})
    except Exception as e:
        logging.error(f"Request credits error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/user/submit_feedback', methods=['POST'])
@credit_required(cost=0)
@cross_origin()
def submit_feedback():
    try:
        auth_header = request.headers.get('Authorization', '')
        token = auth_header.split(' ')[1]
        uid = verify_token(token)

        data = request.get_json()
        feedback_type = data.get('type')
        message = data.get('message')

        if not feedback_type or not message:
            return jsonify({'error': 'Feedback type and message are_required'}), 400

        user_data = db.reference(f'users/{uid}').get()
        user_email = user_data.get('email', 'unknown_email')

        feedback_ref = db.reference('feedback').push()
        feedback_ref.set({
            'user_id': uid,
            'user_email': user_email,
            'type': feedback_type,
            'message': message,
            'created_at': datetime.utcnow().isoformat(),
            'status': 'open'
        })
        return jsonify({'success': True, 'feedback_id': feedback_ref.key}), 201
    except Exception as e:
        logging.error(f"Submit feedback error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/profile', methods=['GET'])
def get_admin_profile():
    try:
        admin_uid = verify_admin(request.headers.get('Authorization', ''))
        admin_data = db.reference(f'users/{admin_uid}').get()
        if not admin_data:
            return jsonify({'error': 'Admin user not found'}), 404

        all_users_data = db.reference('users').get() or {}
        total_users = len(all_users_data)
        
        normal_users_data = [user for user in all_users_data.values() if not user.get('is_admin', False)]
        total_normal_users = len(normal_users_data)
        
        total_current_credits = sum(user.get('credits', 0) for user in all_users_data.values())
        total_normal_current_credits = sum(user.get('credits', 0) for user in normal_users_data)
        
        total_initial_credits = total_normal_users * 10 
        credit_usage = total_initial_credits - total_normal_current_credits

        return jsonify({
            'uid': admin_uid,
            'email': admin_data.get('email'),
            'credits': admin_data.get('credits', 0),
            'is_admin': True,
            'aggregated_stats': {
                'total_users': total_users,
                'total_normal_users': total_normal_users,
                'total_current_credits': total_current_credits,
                'total_normal_current_credits': total_normal_current_credits,
                'total_initial_credits_normal_users': total_initial_credits,
                'credit_usage': credit_usage
            }
        })
    except Exception as e:
        logging.error(f"Error fetching admin profile: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/credit_requests', methods=['GET'])
def list_credit_requests():
    try:
        verify_admin(request.headers.get('Authorization', ''))
        requests_ref = db.reference('credit_requests')
        credit_requests = requests_ref.get() or {}
        requests_list = [{'id': req_id, **data} for req_id, data in credit_requests.items()]
        return jsonify({'credit_requests': requests_list})
    except Exception as e:
        logging.error(f"List credit requests error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/credit_requests/<string:request_id>', methods=['PUT'])
def process_credit_request(request_id):
    try:
        admin_uid = verify_admin(request.headers.get('Authorization', ''))
        req_ref = db.reference(f'credit_requests/{request_id}')
        req_data = req_ref.get()
        if not req_data:
            return jsonify({'error': 'Credit request not found'}), 404

        data = request.get_json()
        decision = data.get('decision')
        if decision not in ['approved', 'declined']:
            return jsonify({'error': 'decision must be "approved" or "declined"'}), 400

        if decision == 'approved':
            user_ref = db.reference(f'users/{req_data["user_id"]}')
            user_data = user_ref.get()
            if not user_data:
                return jsonify({'error': 'User not found'}), 404
            new_total = user_data.get('credits', 0) + float(req_data.get('requested_credits', 0))
            user_ref.update({'credits': new_total})
            req_ref.update({
                'status': 'approved',
                'processed_by': admin_uid,
                'processed_at': datetime.utcnow().isoformat()
            })
            return jsonify({'success': True, 'new_user_credits': new_total})
        else:
            req_ref.update({
                'status': 'declined',
                'processed_by': admin_uid,
                'processed_at': datetime.utcnow().isoformat()
            })
            return jsonify({'success': True, 'message': 'Credit request declined'})
    except Exception as e:
        logging.error(f"Process credit request error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/users', methods=['GET'])
def admin_list_users():
    try:
        verify_admin(request.headers.get('Authorization', ''))
        users_ref = db.reference('users')
        all_users = users_ref.get() or {}
        
        user_list = []
        for uid, user_data in all_users.items():
            user_list.append({
                'uid': uid,
                'email': user_data.get('email'),
                'credits': user_data.get('credits', 0),
                'is_admin': user_data.get('is_admin', False),
                'created_at': user_data.get('created_at', ''),
                'suspended': user_data.get('suspended', False)
            })
        return jsonify({'users': user_list}), 200
    except Exception as e:
        logging.error(f"Admin list users error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/users/search', methods=['GET'])
def admin_search_users():
    try:
        verify_admin(request.headers.get('Authorization', ''))
        email_query = request.args.get('email', '').lower().strip()
        if not email_query:
            return jsonify({'error': 'email query param is required'}), 400

        users_ref = db.reference('users')
        all_users = users_ref.get() or {}

        matched_users = []
        for uid, user_data in all_users.items():
            user_email = user_data.get('email', '').lower()
            if email_query in user_email:
                matched_users.append({
                    'uid': uid,
                    'email': user_data.get('email'),
                    'credits': user_data.get('credits', 0),
                    'is_admin': user_data.get('is_admin', False),
                    'created_at': user_data.get('created_at', ''),
                    'suspended': user_data.get('suspended', False)
                })
        return jsonify({'matched_users': matched_users}), 200
    except Exception as e:
        logging.error(f"Admin search users error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/users/<string:uid>/suspend', methods=['PUT'])
def admin_suspend_user(uid):
    try:
        verify_admin(request.headers.get('Authorization', ''))
        data = request.get_json()
        action = data.get('action')
        if action not in ["suspend", "unsuspend"]:
            return jsonify({'error': 'action must be "suspend" or "unsuspend"'}), 400

        user_ref = db.reference(f'users/{uid}')
        user_data = user_ref.get()
        if not user_data:
            return jsonify({'error': 'User not found'}), 404

        if action == "suspend":
            user_ref.update({'suspended': True})
        else:
            user_ref.update({'suspended': False})

        return jsonify({'success': True, 'message': f'User {uid} is now {action}ed'})
    except Exception as e:
        logging.error(f"Admin suspend user error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/notifications', methods=['POST'])
def send_notifications():
    try:
        admin_uid = verify_admin(request.headers.get('Authorization', ''))
        data = request.get_json()
        message = data.get('message')
        if not message:
            return jsonify({'error': 'message is required'}), 400

        recipients = data.get('recipients', "all")
        all_users_ref = db.reference('users')
        all_users_data = all_users_ref.get() or {}

        user_ids_to_notify = []
        if recipients == "all":
            user_ids_to_notify = list(all_users_data.keys())
        elif isinstance(recipients, list):
            user_ids_to_notify = [uid for uid in recipients if uid in all_users_data]
        elif isinstance(recipients, str):
            if recipients in all_users_data:
                user_ids_to_notify = [recipients]
            else:
                return jsonify({'error': 'Invalid single user_id'}), 400
        else:
            return jsonify({'error': 'recipients must be "all", a user_id, or a list of user_ids'}), 400

        now_str = datetime.utcnow().isoformat()
        for user_id in user_ids_to_notify:
            notif_id = str(uuid.uuid4())
            notif_ref = db.reference(f'notifications/{user_id}/{notif_id}')
            notif_data = {
                "from_admin": admin_uid,
                "message": message,
                "created_at": now_str,
                "read": False
            }
            notif_ref.set(notif_data)

        return jsonify({
            'success': True,
            'message': f"Notification sent to {len(user_ids_to_notify)} user(s)."
        }), 200

    except Exception as e:
        logging.error(f"Send notifications error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/feedback', methods=['GET'])
def admin_view_feedback():
    try:
        admin_uid = verify_admin(request.headers.get('Authorization', ''))
        feedback_type = request.args.get('type')
        feedback_status = request.args.get('status')

        feedback_ref = db.reference('feedback')
        all_feedback = feedback_ref.get() or {}

        feedback_list = []
        for fb_id, fb_data in all_feedback.items():
            if feedback_type and fb_data.get('type') != feedback_type:
                continue
            if feedback_status and fb_data.get('status') != feedback_status:
                continue

            feedback_list.append({
                'feedback_id': fb_id,
                'user_id': fb_data.get('user_id'),
                'user_email': fb_data.get('user_email'),
                'type': fb_data.get('type', 'general'),
                'message': fb_data.get('message', ''),
                'created_at': fb_data.get('created_at'),
                'status': fb_data.get('status', 'open')
            })
        return jsonify({'feedback': feedback_list}), 200
    except Exception as e:
        logging.error(f"Admin view feedback error: {e}")
        return jsonify({'error': str(e)}), 500
        
@app.route('/api/admin/users/<string:uid>/credits', methods=['PUT'])
def admin_update_credits(uid):
    try:
        verify_admin(request.headers.get('Authorization', ''))
        data = request.get_json()
        add_credits = data.get('add_credits')
        if add_credits is None:
            return jsonify({'error': 'add_credits is required'}), 400

        user_ref = db.reference(f'users/{uid}')
        user_data = user_ref.get()
        if not user_data:
            return jsonify({'error': 'User not found'}), 404

        new_total = user_data.get('credits', 0) + float(add_credits)
        user_ref.update({'credits': new_total})
        return jsonify({'success': True, 'new_total_credits': new_total})
    except Exception as e:
        logging.error(f"Admin update credits error: {e}")
        return jsonify({'error': str(e)}), 500


# ——————————————————————————————————————————————
# NBA Analytics Hub Data Fetching Utilities
# ——————————————————————————————————————————————

def normalize_string(s):
    """Removes accent marks and converts to lowercase for consistent comparison."""
    if not isinstance(s, str):
        return str(s)
    s = unicodedata.normalize('NFKD', s).encode('ascii', 'ignore').decode('utf-8')
    return s.strip()

def clean_firebase_keys(key_name):
    if not isinstance(key_name, str):
        key_name = str(key_name)
    cleaned_key = key_name.replace('.', '_').replace('$', '').replace('#', '').replace('[', '').replace(']', '').replace('/', '_')
    cleaned_key = cleaned_key.replace('%', 'Pct')
    if not cleaned_key:
        return "empty_key_" + str(uuid.uuid4())[:8]
    return cleaned_key

def clean_df_for_firebase(df):
    if df.empty:
        return df
    df.columns = [clean_firebase_keys(col) for col in df.columns]
    return df

def clean_team_name(team_name):
    if pd.isna(team_name):
        return team_name
    team_name = str(team_name).strip()
    team_name = re.sub(r'\s*\(\d+\)$', '', team_name)
    team_name = team_name.replace('*', '')
    return team_name

def is_data_stale(timestamp_str, max_age_hours=24):
    if not timestamp_str:
        return True
    try:
        last_updated = datetime.fromisoformat(timestamp_str)
        return (datetime.utcnow() - last_updated) > timedelta(hours=max_age_hours)
    except ValueError:
        logging.error(f"Invalid timestamp format: {timestamp_str}")
        return True

def get_team_standings_brscraper(year):
    if not FIREBASE_INITIALIZED:
        logging.warning("Firebase not initialized. Cannot use caching for team standings. Scraping directly.")
        return _scrape_team_standings_brscraper(year)

    db_ref = db.reference(f'scraped_data/team_standings/{year}')
    cached_data = db_ref.get()

    if cached_data and not is_data_stale(cached_data.get('last_updated'), max_age_hours=12):
        logging.info(f"Loading team standings for {year} from Firebase cache.")
        return pd.DataFrame.from_records(cached_data['data'])
    else:
        logging.info(f"Scraping team standings for {year} (cache stale or not found).")
        df = _scrape_team_standings_brscraper(year)
        if not df.empty:
            df_cleaned_for_firebase = clean_df_for_firebase(df.copy())
            db_ref.set({
                'last_updated': datetime.utcnow().isoformat(),
                'data': df_cleaned_for_firebase.to_dict(orient='records')
            })
            logging.info(f"Team standings for {year} saved to Firebase cache.")
        return df

def _scrape_team_standings_brscraper(year):
    if not BRSCRAPER_AVAILABLE:
        logging.error("BRScraper not available for team standings.")
        return pd.DataFrame()
    try:
        df = nba.get_standings(year, info='total')
        if df.empty:
            logging.warning(f"Could not find team standings for {year} using BRScraper.")
            return pd.DataFrame()

        column_mapping = {
            'Tm': 'Team', 'W': 'WINS', 'L': 'LOSSES', 'W/L%': 'WIN_LOSS_PCT',
            'Rk': 'RANK'
        }
        df = df.rename(columns={old_col: new_col for old_col, new_col in column_mapping.items() if old_col in df.columns})

        if 'Team' in df.columns:
            df['Team'] = df['Team'].astype(str)
            df['Team'] = df['Team'].apply(clean_team_name)

        numeric_cols = [col for col in df.columns if col not in ['Team']]
        for col in numeric_cols:
            df[col] = pd.to_numeric(df[col], errors="coerce")

        df = df.replace({np.nan: None})
        return df
    except Exception as e:
        logging.error(f"Error scraping team standings with BRScraper for {year}: {e}")
        return pd.DataFrame()

def get_available_seasons_util(num_seasons=6):
    current_year = datetime.now().year
    current_month = datetime.now().month
    latest_season_end_year = current_year
    if current_month >= 7:
        latest_season_end_year += 1
    seasons_list = []
    for i in range(num_seasons):
        end_year = latest_season_end_year - i
        start_year = end_year - 1
        seasons_list.append(f"{start_year}–{end_year}")
    return sorted(seasons_list, reverse=True)

def get_player_index_brscraper():
    if not BRSCRAPER_AVAILABLE:
        return pd.DataFrame(columns=['name'])
    
    if not FIREBASE_INITIALIZED:
        logging.warning("Firebase not initialized. Cannot use caching for player index. Scraping directly.")
        return _scrape_player_index_brscraper()

    db_ref = db.reference('scraped_data/player_index')
    cached_data = db_ref.get()

    if cached_data and not is_data_stale(cached_data.get('last_updated')):
        logging.info("Loading player index from Firebase cache.")
        return pd.DataFrame.from_records(cached_data['data'])
    else:
        logging.info("Scraping player index (cache stale or not found).")
        df = _scrape_player_index_brscraper()
        if not df.empty:
            db_ref.set({
                'last_updated': datetime.utcnow().isoformat(),
                'data': df.to_dict(orient='records')
            })
            logging.info("Player index saved to Firebase cache.")
        return df

def _scrape_player_index_brscraper():
    # Prioritize getting real player data from recent seasons
    seasons_to_try_for_index = get_available_seasons_util(num_seasons=2) # Try current and previous season
    
    for season_str in seasons_to_try_for_index:
        end_year = int(season_str.split('–')[1])
        try:
            logging.info(f"Attempting to get player index for year: {end_year} from BRScraper...")
            df = nba.get_stats(end_year, info='per_game', rename=False)
            
            if not df.empty and 'Player' in df.columns:
                player_names = df['Player'].dropna().unique().tolist()
                # Normalize player names before returning
                player_names = [normalize_string(name) for name in player_names]
                logging.info(f"Successfully retrieved {len(player_names)} players for index from {season_str}.")
                return pd.DataFrame({'name': player_names})
            else:
                logging.warning(f"Player index DataFrame empty or 'Player' column missing for {season_str}. Trying next season.")
        except Exception as e:
            logging.warning(f"Error fetching player index with BRScraper for {season_str}: {e}. Trying next season.")

    # Fallback to a curated list if recent seasons fail
    logging.error("Failed to fetch player index from recent seasons. Falling back to curated common players list.")
    common_players = [
        'LeBron James', 'Stephen Curry', 'Kevin Durant', 'Giannis Antetokounmpo',
        'Nikola Jokic', # No accent here, as it will be normalized
        'Joel Embiid', 'Jayson Tatum', 'Luka Doncic', # No accent here, as it will be normalized
        'Damian Lillard', 'Jimmy Butler', 'Kawhi Leonard', 'Paul George',
        'Anthony Davis', 'Rudy Gobert', 'Donovan Mitchell', 'Trae Young',
        'Devin Booker', 'Karl-Anthony Towns', 'Zion Williamson', 'Ja Morant',
        'Shai Gilgeous-Alexander', 'Tyrese Maxey', 'Anthony Edwards', 'Victor Wembanyama',
        'Jalen Brunson', 'Paolo Banchero', 'Franz Wagner', 'Cade Cunningham'
    ]
    return pd.DataFrame({'name': common_players})

def get_player_career_stats_brscraper(player_name, seasons_to_check=10, playoffs=False):
    if not BRSCRAPER_AVAILABLE:
        logging.error("BRScraper is not available. Cannot fetch player career stats.")
        return pd.DataFrame()
    all_rows = []
    
    # Normalize the input player name for consistent lookup
    normalized_player_name = normalize_string(player_name)

    seasons_to_try = get_available_seasons_util(seasons_to_check)
    
    for season_str in seasons_to_try:
        end_year = int(season_str.split('–')[1])
        
        # Implement retry logic for each season fetch
        for attempt in range(3): # Try up to 3 times
            try:
                logging.info(f"DEBUG: Attempt {attempt+1} for nba.get_stats for player '{player_name}' in season {season_str} (year: {end_year}, playoffs: {playoffs})...")
                
                df_season = nba.get_stats(end_year, info='per_game', playoffs=playoffs, rename=False)
                
                if df_season.empty:
                    logging.warning(f"DEBUG: nba.get_stats returned empty DataFrame for {player_name} in {season_str} on attempt {attempt+1}. Retrying...")
                    time.sleep(1) # Wait a bit before retrying
                    continue # Go to next attempt
                
                if 'Player' not in df_season.columns:
                    logging.warning(f"DEBUG: DataFrame for {player_name} in {season_str} has no 'Player' column on attempt {attempt+1}. Columns: {df_season.columns.tolist()}. Retrying...")
                    time.sleep(1)
                    continue

                # Normalize player names in the DataFrame for comparison
                df_season['Player_Normalized'] = df_season['Player'].apply(normalize_string)
                
                row = df_season[df_season['Player_Normalized'] == normalized_player_name]
                
                if not row.empty:
                    row = row.copy()
                    row['Season'] = season_str
                    # Remove the temporary normalized column before appending
                    row = row.drop(columns=['Player_Normalized'], errors='ignore')
                    all_rows.append(row)
                    logging.info(f"DEBUG: Found stats for {player_name} in {season_str} on attempt {attempt+1}. Appending row.")
                    break # Break retry loop if successful
                else:
                    logging.info(f"DEBUG: Player {player_name} not found in {season_str} stats (after getting season data) on attempt {attempt+1}. Retrying...")
                    time.sleep(1)
                    continue # Go to next attempt

            except Exception as e:
                logging.warning(f"DEBUG: Exception on attempt {attempt+1} when fetching {season_str} {'playoff' if playoffs else 'regular season'} stats for {player_name}: {e}")
                time.sleep(1) # Wait before next retry
                if attempt == 2: # If last attempt failed
                    logging.error(f"DEBUG: All 3 attempts failed for {player_name} in {season_str}. Giving up on this season.")
                continue # Go to next attempt

    if not all_rows:
        logging.warning(f"DEBUG: No stats found for {player_name} across all attempted seasons. Returning empty DataFrame.")
        return pd.DataFrame()
    
    df = pd.concat(all_rows, ignore_index=True)

    mapping = {
        'G':'GP','GS':'GS','MP':'MIN', 'FG%':'FG_PCT','3P%':'FG3_PCT','FT%':'FT_PCT',
        'TRB':'REB','AST':'AST','STL':'STL','BLK':'BLK','TOV':'TO',
        'PF':'PF','PTS':'PTS','ORB':'OREB','DRB':'DREB',
        'FG':'FGM','FGA':'FGA','3P':'FG3M','3PA':'FG3A',
        '2P':'FGM2','2PA':'FGA2','2P%':'FG2_PCT','eFG%':'EFG_PCT',
        'FT':'FTM','FTA':'FTA'
    }
    df = df.rename(columns={o:n for o,n in mapping.items() if o in df.columns})

    non_num = {'Season','Player','Tm','Lg','Pos'}
    for col in df.columns:
        if col not in non_num:
            df[col] = pd.to_numeric(df[col], errors='coerce')

    df['Player'] = player_name # Ensure original player name is kept
    df = df.replace({np.nan: None})
    return df

def get_dashboard_info_brscraper():
    if not BRSCRAPER_AVAILABLE:
        logging.error("BRScraper not available for dashboard info.")
        return {}

    if not FIREBASE_INITIALIZED:
        logging.warning("Firebase not initialized. Cannot use caching for dashboard info. Scraping directly.")
        return _scrape_dashboard_info_brscraper()

    db_ref = db.reference('scraped_data/dashboard_info')
    cached_data = db_ref.get()

    if cached_data and not is_data_stale(cached_data.get('last_updated'), max_age_hours=24):
        logging.info("Loading dashboard info from Firebase cache.")
        return cached_data['data']
    else:
        logging.info("Scraping dashboard info (cache stale or not found).")
        data = _scrape_dashboard_info_brscraper()
        if data:
            db_ref.set({
                'last_updated': datetime.utcnow().isoformat(),
                'data': data
            })
            logging.info("Dashboard info saved to Firebase cache.")
        return data

def _scrape_dashboard_info_brscraper():
    dashboard_data = {}
    try:
        mvp_2025_df = nba.get_award_votings('mvp', 2025)
        if not mvp_2025_df.empty:
            if 'Share' in mvp_2025_df.columns:
                mvp_2025_df = mvp_2025_df.rename(columns={'Share': 'Votes'})
            if 'Votes' in mvp_2025_df.columns:
                mvp_2025_df['Votes'] = pd.to_numeric(mvp_2025_df['Votes'], errors='coerce') * 100
            
            mvp_2025_df = clean_df_for_firebase(mvp_2025_df)
            dashboard_data['mvp_2025_votings'] = mvp_2025_df.replace({np.nan: None}).to_dict(orient='records')
        else:
            dashboard_data['mvp_2025_votings'] = []
            logging.warning("Could not retrieve 2025 MVP votings.")

        east_probs_df = nba.get_playoffs_probs('east')
        if not east_probs_df.empty:
            if 'Eastern Conference' in east_probs_df.columns:
                east_probs_df = east_probs_df.rename(columns={'Eastern Conference': 'Team'})
            elif 'Tm' in east_probs_df.columns:
                east_probs_df = east_probs_df.rename(columns={'Tm': 'Team'})
            
            if 'Team' in east_probs_df.columns:
                east_probs_df['Team'] = east_probs_df['Team'].astype(str).apply(clean_team_name)

            east_probs_df = clean_df_for_firebase(east_probs_df)
            dashboard_data['playoff_probs_east'] = east_probs_df.replace({np.nan: None}).to_dict(orient='records')
        else:
            dashboard_data['playoff_probs_east'] = []
            logging.warning("Could not retrieve Eastern Conference playoff probabilities.")

        west_probs_df = nba.get_playoffs_probs('west')
        if not west_probs_df.empty:
            if 'Western Conference' in west_probs_df.columns:
                west_probs_df = west_probs_df.rename(columns={'Western Conference': 'Team'})
            elif 'Tm' in west_probs_df.columns:
                west_probs_df = west_probs_df.rename(columns={'Tm': 'Team'})

            if 'Team' in west_probs_df.columns:
                west_probs_df['Team'] = west_probs_df['Team'].astype(str).apply(clean_team_name)

            west_probs_df = clean_df_for_firebase(west_probs_df)
            dashboard_data['playoff_probs_west'] = west_probs_df.replace({np.nan: None}).to_dict(orient='records')
        else:
            dashboard_data['playoff_probs_west'] = []
            logging.warning("Could not retrieve Western Conference playoff probabilities.")

    except Exception as e:
        logging.error(f"Error scraping dashboard info with BRScraper: {e}")
    return dashboard_data


PERP_KEY = os.getenv("PERPLEXITY_API_KEY")
PERP_URL = "https://api.perplexity.ai/chat/completions"

NBA_ANALYST_SYSTEM_PROMPT = (
    "You are a sharp, insightful NBA analyst AI with the tone and knowledge of a seasoned sports commentator. "
    "Your expertise spans the entire history of basketball—from hardwood legends to rising stars, tactical evolutions, "
    "advanced stats, trades, rivalries, and playoff lore. Speak with authority, depth, and the occasional flair of broadcast commentary. "
    "Your job is to help users explore basketball with analytical rigor and passion. You draw on statistics, game film analysis, "
    "player tendencies, team dynamics, historical context, and front-office strategy. You may reference key metrics like PER, TS%, "
    "on-off splits, or synergy data when relevant. You provide takes that are well-reasoned, never vague, and always rooted in basketball-specific insight. "
    "CRITICAL: Stay strictly within basketball. When discussing 'rookie performances' or any basketball topic, ONLY reference NBA/basketball players and stats - never NFL or other sports. "
    "Do not respond to questions outside the world of basketball. If asked, steer the conversation back to the NBA with finesse, "
    "perhaps by connecting a topic metaphorically to hoops. Your personality is that of a knowledgeable but approachable analyst—"
    "a cross between a basketball scout, play-by-play commentator, and sportswriter. You love the game, and it shows."
)

def ask_perp(prompt, system=NBA_ANALYST_SYSTEM_PROMPT, max_tokens=1000, temp=0.2):
    if not PERP_KEY:
        logging.error("PERPLEXITY_API_KEY env var not set.")
        return "Perplexity API key is not configured."

    headers = {
        'Authorization': f'Bearer {PERP_KEY}',
        'Content-Type': 'application/json'
    }

    payload = {
        "model": "sonar-pro",
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": f"BASKETBALL ONLY: {prompt}"}
        ],
        "max_tokens": max_tokens,
        "temperature": temp,
        "web_search_options": {
            "search_context_size": "high",
            "search_domain_filter": ["nba.com", "espn.com", "basketball-reference.com"]
        },
        "emit_sources": True
    }

    try:
        response = requests.post(PERP_URL, json=payload, headers=headers, timeout=45)
        response.raise_for_status()
        return response.json().get("choices", [])[0].get("message", {}).get("content", "")
    except requests.exceptions.RequestException as e:
        error_message = f"Error communicating with Perplexity API: {e}"
        if hasattr(e, 'response') and e.response is not None:
            try:
                error_detail = e.response.json().get("error", {}).get("message", e.response.text)
                error_message = f"Perplexity API error: {e.response.status_code} - {e.response.reason}"
            except ValueError:
                error_message = f"Perplexity API error: {e.response.status_code} - {e.response.reason}"
        logging.error(f"Perplexity API request failed: {error_message}")
        return f"Error from AI: {error_message}"
    except Exception as e:
        logging.error(f"An unexpected error occurred with Perplexity API: {e}")
        return f"An unexpected error occurred with AI: {str(e)}"

@app.route('/api/nba/players', methods=['GET'])
@cross_origin()
def get_players():
    try:
        players_df = get_player_index_brscraper()
        if players_df.empty:
            return jsonify({'error': 'Could not retrieve player list'}), 500
        return jsonify({'players': players_df['name'].tolist()})
    except Exception as e:
        logging.error(f"Error in /api/nba/players: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/nba/seasons', methods=['GET'])
@cross_origin()
def get_seasons():
    try:
        seasons_list = get_available_seasons_util()
        return jsonify({'seasons': seasons_list})
    except Exception as e:
        logging.error(f"Error in /api/nba/seasons: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/nba/player_stats', methods=['POST'])
@cross_origin()
def get_player_stats():
    try:
        data = request.get_json()
        selected_players = data.get('players')
        selected_seasons = data.get('seasons')

        if not selected_players or not selected_seasons:
            return jsonify({'error': 'Players and seasons are required'}), 400

        all_player_season_data = []
        players_with_no_data = []

        for player_name in selected_players:
            df_player_career = get_player_career_stats_brscraper(player_name, playoffs=False)
            
            if df_player_career.empty:
                logging.info(f"No career data found for {player_name}. Adding to no_data list.")
                players_with_no_data.append(player_name)
                continue

            filtered_df = df_player_career[df_player_career['Season'].isin(selected_seasons)].copy()
            
            if not filtered_df.empty:
                all_player_season_data.append(filtered_df)
                logging.info(f"Successfully filtered data for {player_name} in requested seasons.")
            else:
                logging.info(f"No data found for {player_name} in the specific requested seasons: {selected_seasons}. Adding to no_data list.")
                players_with_no_data.append(player_name)

        if not all_player_season_data:
            logging.warning("After processing all players, 'all_player_season_data' is empty. Returning 404.")
            return jsonify({
                'error': 'No data available for selected players and seasons.',
                'players_with_no_data': players_with_no_data
            }), 404

        comparison_df_raw = pd.concat(all_player_season_data, ignore_index=True)

        if len(selected_seasons) > 1:
            basic_display_df = comparison_df_raw.groupby('Player').mean(numeric_only=True).reset_index()
        else:
            basic_display_df = comparison_df_raw.copy()
        
        basic_cols = ['Player', 'Season', 'GP', 'MIN', 'PTS', 'REB', 'AST', 'STL', 'BLK', 'FG_PCT', 'FT_PCT', 'FG3_PCT']
        basic_display_df = basic_display_df[[c for c in basic_cols if c in basic_display_df.columns]].round(2)

        advanced_df = comparison_df_raw.copy()
        advanced_df['FGA'] = pd.to_numeric(advanced_df.get('FGA', 0), errors='coerce').fillna(0)
        advanced_df['FTA'] = pd.to_numeric(advanced_df.get('FTA', 0), errors='coerce').fillna(0)
        advanced_df['PTS'] = pd.to_numeric(advanced_df.get('PTS', 0), errors='coerce').fillna(0)
        advanced_df['TS_PCT'] = advanced_df.apply(
            lambda r: r['PTS'] / (2 * (r['FGA'] + 0.44 * r['FTA'])) if (r['FGA'] + 0.44 * r['FTA']) else 0,
            axis=1
        )
        if len(selected_seasons) > 1:
            advanced_display_df = advanced_df.groupby('Player').mean(numeric_only=True).reset_index()
        else:
            advanced_display_df = advanced_df.copy()
        
        advanced_cols = ['Player', 'Season', 'PTS', 'REB', 'AST', 'FG_PCT', 'TS_PCT']
        advanced_display_df = advanced_display_df[[c for c in advanced_cols if c in advanced_display_df.columns]].round(3)

        return jsonify({
            'basic_stats': basic_display_df.to_dict(orient='records'),
            'advanced_stats': advanced_display_df.to_dict(orient='records'),
            'players_with_no_data': players_with_no_data
        })
    except Exception as e:
        logging.error(f"Error in /api/nba/player_stats: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/nba/player_playoff_stats', methods=['POST'])
@cross_origin()
def get_player_playoff_stats():
    try:
        data = request.get_json()
        selected_players = data.get('players')
        selected_seasons = data.get('seasons')

        if not selected_players or not selected_seasons:
            return jsonify({'error': 'Players and seasons are required'}), 400

        all_player_season_data = []
        players_with_no_data = []

        for player_name in selected_players:
            df_player_career = get_player_career_stats_brscraper(player_name, playoffs=True)
            if df_player_career.empty:
                logging.info(f"No career playoff data found for {player_name}. Adding to no_data list.")
                players_with_no_data.append(player_name)
                continue

            filtered_df = df_player_career[df_player_career['Season'].isin(selected_seasons)].copy()
            
            if not filtered_df.empty:
                all_player_season_data.append(filtered_df)
                logging.info(f"Successfully filtered playoff data for {player_name} in requested seasons.")
            else:
                logging.info(f"No playoff data found for {player_name} in the specific requested seasons: {selected_seasons}. Adding to no_data list.")
                players_with_no_data.append(player_name)

        if not all_player_season_data:
            logging.warning("After processing all players, 'all_player_season_data' is empty for playoffs. Returning 404.")
            return jsonify({
                'error': 'No data available for selected players and seasons.',
                'players_with_no_data': players_with_no_data
            }), 404

        comparison_df_raw = pd.concat(all_player_season_data, ignore_index=True)

        if len(selected_seasons) > 1:
            basic_display_df = comparison_df_raw.groupby('Player').mean(numeric_only=True).reset_index()
        else:
            basic_display_df = comparison_df_raw.copy()
        
        basic_cols = ['Player', 'Season', 'GP', 'MIN', 'PTS', 'REB', 'AST', 'STL', 'BLK', 'FG_PCT', 'FT_PCT', 'FG3_PCT']
        basic_display_df = basic_display_df[[c for c in basic_cols if c in basic_display_df.columns]].round(2)

        advanced_df = comparison_df_raw.copy()
        advanced_df['FGA'] = pd.to_numeric(advanced_df.get('FGA', 0), errors='coerce').fillna(0)
        advanced_df['FTA'] = pd.to_numeric(advanced_df.get('FTA', 0), errors='coerce').fillna(0)
        advanced_df['PTS'] = pd.to_numeric(advanced_df.get('PTS', 0), errors='coerce').fillna(0)
        advanced_df['TS_PCT'] = advanced_df.apply(
            lambda r: r['PTS'] / (2 * (r['FGA'] + 0.44 * r['FTA'])) if (r['FGA'] + 0.44 * r['FTA']) else 0,
            axis=1
        )
        if len(selected_seasons) > 1:
            advanced_display_df = advanced_df.groupby('Player').mean(numeric_only=True).reset_index()
        else:
            advanced_display_df = advanced_df.copy()
        
        advanced_cols = ['Player', 'Season', 'PTS', 'REB', 'AST', 'FG_PCT', 'TS_PCT']
        advanced_display_df = advanced_display_df[[c for c in advanced_cols if c in advanced_display_df.columns]].round(3)

        return jsonify({
            'basic_stats': basic_display_df.to_dict(orient='records'),
            'advanced_stats': advanced_display_df.to_dict(orient='records'),
            'players_with_no_data': players_with_no_data
        })
    except Exception as e:
        logging.error(f"Error in /api/nba/player_playoff_stats: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/nba/team_stats', methods=['POST'])
@cross_origin()
def get_team_stats():
    logging.info("DEBUG: Request successfully entered get_team_stats function!")
    try:
        data = request.get_json()
        selected_teams_abbrs = data.get('teams')
        selected_season_str = data.get('season')

        if not selected_teams_abbrs or not selected_season_str:
            return jsonify({'error': 'Teams and season are required'}), 400

        year_for_team_stats = int(selected_season_str.split('–')[1])
        tm_df = get_team_standings_brscraper(year_for_team_stats)

        if tm_df.empty:
            return jsonify({'error': f'No team data available for {selected_season_str}'}), 404

        full_team_names_map = {
            "ATL": "Atlanta Hawks", "BOS": "Boston Celtics", "BRK": "Brooklyn Nets",
            "CHO": "Charlotte Hornets", "CHI": "Chicago Bulls", "CLE": "Cleveland Cavaliers",
            "DAL": "Dallas Mavericks", "DEN": "Denver Nuggets", "DET": "Detroit Pistons",
            "GSW": "Golden State Warriors", "HOU": "Houston Rockets", "IND": "Indiana Pacers",
            "LAC": "Los Angeles Clippers", "LAL": "Los Angeles Lakers", "MEM": "Memphis Grizzlies",
            "MIA": "Miami Heat", "MIL": "Milwaukee Bucks", "MIN": "Minnesota Timberwolves",
            "NOP": "New Orleans Pelicans", "NYK": "New York Knicks", "OKC": "Oklahoma City Thunder",
            "ORL": "Orlando Magic", "PHI": "Philadelphia 76ers", "PHX": "Phoenix Suns",
            "POR": "Portland Trail Blazers", "SAC": "Sacramento Kings", "SAS": "San Antonio Spurs",
            "TOR": "Toronto Raptors", "UTA": "Utah Jazz", "WAS": "Washington Wizards"
        }
        selected_teams_full_names = [full_team_names_map.get(abbr, abbr) for abbr in selected_teams_abbrs]

        stats = []
        teams_with_no_data = []

        for team_full_name_lookup in selected_teams_full_names:
            df_row = tm_df[tm_df.Team == team_full_name_lookup].copy()
            if not df_row.empty:
                df_dict = df_row.iloc[0].to_dict()
                df_dict['Season'] = selected_season_str
                stats.append(df_dict)
            else:
                original_abbr = next((abbr for abbr, name in full_team_names_map.items() if name == team_full_name_lookup), team_full_name_lookup)
                teams_with_no_data.append(original_abbr)

        if not stats:
            return jsonify({
                'error': 'No data available for selected teams.',
                'teams_with_no_data': teams_with_no_data
            }), 404

        comp = pd.DataFrame(stats)
        for col in ['WINS', 'LOSSES', 'WIN_LOSS_PCT', 'RANK']:
            if col in comp.columns:
                comp[col] = pd.to_numeric(comp[col], errors='coerce')
        comp = comp.replace({np.nan: None})

        return jsonify({
            'team_stats': comp.to_dict(orient='records'),
            'teams_with_no_data': teams_with_no_data
        })
    except Exception as e:
        logging.error(f"Error in /api/nba/team_stats: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/nba/dashboard_info', methods=['GET'])
@credit_required(cost=0)
@cross_origin()
def dashboard_info():
    try:
        dashboard_data = get_dashboard_info_brscraper()
        if not dashboard_data:
            return jsonify({'error': 'Could not retrieve dashboard information.'}), 500
        return jsonify(dashboard_data)
    except Exception as e:
        logging.error(f"Error in /api/nba/dashboard_info: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/nba/perplexity_explain', methods=['POST'])
@credit_required(cost=1)
@cross_origin()
def perplexity_explain():
    try:
        data = request.get_json()
        prompt = data.get('prompt')
        
        if not prompt:
            return jsonify({'error': 'Prompt is required'}), 400
        
        explanation = ask_perp(prompt)
        if "Error from AI" in explanation:
            return jsonify({'error': explanation}), 500
        
        auth_header = request.headers.get('Authorization', '')
        token = auth_header.split(' ')[1]
        uid = verify_token(token)

        if FIREBASE_INITIALIZED:
            user_analyses_ref = db.reference(f'user_analyses/{uid}')
            analysis_id = str(uuid.uuid4())
            analysis_data = {
                'prompt': prompt,
                'explanation': explanation,
                'created_at': datetime.utcnow().isoformat()
            }
            user_analyses_ref.child(analysis_id).set(analysis_data)
            logging.info(f"Analysis stored for user {uid} with ID: {analysis_id}")
        else:
            logging.warning("Firebase not initialized. Analysis will not be saved.")

        return jsonify({'explanation': explanation, 'analysis_id': analysis_id})
    except Exception as e:
        logging.error(f"Error in /api/nba/perplexity_explain: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/user/analyses', methods=['GET'])
@credit_required(cost=0)
@cross_origin()
def get_user_analyses():
    try:
        auth_header = request.headers.get('Authorization', '')
        token = auth_header.split(' ')[1]
        uid = verify_token(token)

        if not FIREBASE_INITIALIZED:
            return jsonify({'error': 'Firebase not initialized. Cannot retrieve analyses.'}), 500

        user_analyses_ref = db.reference(f'user_analyses/{uid}')
        analyses_data = user_analyses_ref.get() or {}

        analyses_list = []
        for analysis_id, data in analyses_data.items():
            analyses_list.append({
                'analysis_id': analysis_id,
                'prompt': data.get('prompt'),
                'explanation': data.get('explanation'),
                'created_at': data.get('created_at')
            })
        
        analyses_list.sort(key=lambda x: x.get('created_at', ''), reverse=True)

        return jsonify({'analyses': analyses_list})
    except Exception as e:
        logging.error(f"Error in /api/user/analyses: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/user/analyses/<string:analysis_id>', methods=['DELETE'])
@credit_required(cost=0)
@cross_origin()
def delete_user_analysis(analysis_id):
    try:
        auth_header = request.headers.get('Authorization', '')
        token = auth_header.split(' ')[1]
        uid = verify_token(token)

        if not FIREBASE_INITIALIZED:
            return jsonify({'error': 'Firebase not initialized. Cannot delete analysis.'}), 500

        analysis_ref = db.reference(f'user_analyses/{uid}/{analysis_id}')
        analysis_data = analysis_ref.get()

        if not analysis_data:
            return jsonify({'error': 'Analysis not found or does not belong to this user'}), 404
        
        analysis_ref.delete()
        logging.info(f"Analysis {analysis_id} deleted for user {uid}.")
        return jsonify({'success': True, 'message': 'Analysis deleted successfully'})
    except Exception as e:
        logging.error(f"Error in /api/user/analyses/<id> DELETE: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/nba/perplexity_chat', methods=['POST'])
@credit_required(cost=1)
@cross_origin()
def perplexity_chat():
    try:
        data = request.get_json()
        prompt = data.get('prompt')
        
        if not prompt:
            return jsonify({'error': 'Prompt is required'}), 400
        
        auth_header = request.headers.get('Authorization', '')
        token = auth_header.split(' ')[1]
        uid = verify_token(token)

        response_content = ask_perp(prompt)
        if "Error from AI" in response_content:
            return jsonify({'error': response_content}), 500
        
        if FIREBASE_INITIALIZED:
            user_chat_ref = db.reference(f'users/{uid}/chat_history')
            user_chat_ref.push({
                'role': 'user',
                'content': prompt,
                'timestamp': datetime.utcnow().isoformat()
            })
            user_chat_ref.push({
                'role': 'assistant',
                'content': response_content,
                'timestamp': datetime.utcnow().isoformat()
            })
            logging.info(f"Chat history updated for user {uid}.")
        else:
            logging.warning("Firebase not initialized. Chat history will not be saved.")

        return jsonify({'response': response_content})
    except Exception as e:
        logging.error(f"Error in /api/nba/perplexity_chat: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/nba/awards_predictor', methods=['POST'])
@credit_required(cost=1)
@cross_origin()
def awards_predictor():
    try:
        data = request.get_json()
        award_type = data.get('award_type')
        criteria = data.get('criteria')
        
        if not award_type or not criteria:
            return jsonify({'error': 'Award type and criteria are required'}), 400
        
        prompt = f"Predict top 5 {award_type} candidates based on {criteria}. Focus on 2024-25 season."
        prediction = ask_perp(prompt)
        if "Error from AI" in prediction:
            return jsonify({'error': prediction}), 500
        
        return jsonify({'prediction': prediction})
    except Exception as e:
        logging.error(f"Error in /api/nba/awards_predictor: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/nba/young_player_projection', methods=['POST'])
@credit_required(cost=1)
@cross_origin()
def young_player_projection():
    try:
        data = request.get_json()
        player_name = data.get('player_name')
        age = data.get('age')
        years_in_nba = data.get('years_in_nba')
        ppg = data.get('ppg')
        rpg = data.get('rpg')
        apg = data.get('apg')

        if not all([player_name, age, years_in_nba, ppg, rpg, apg]):
            return jsonify({'error': 'All player details are required for projection'}), 400
        
        prompt = (
            f"Analyze and project the future potential of NBA player {player_name}: "
            f"Current Stats: Age={age}, Years in NBA={years_in_nba}, PPG={ppg}, RPG={rpg}, APG={apg}. "
            "Please provide: 1. 3-year projection of their stats. "
            "2. Peak potential analysis. 3. Areas for improvement. "
            "4. Comparison to similar players at the same age. 5. Career trajectory prediction. "
            "Base your analysis on historical player development patterns and current NBA trends."
        )
        projection = ask_perp(prompt)
        if "Error from AI" in projection:
            return jsonify({'error': projection}), 500
        
        return jsonify({'projection': projection})
    except Exception as e:
        logging.error(f"Error in /api/nba/young_player_projection: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/nba/similar_players', methods=['POST'])
@credit_required(cost=1)
@cross_origin()
def similar_players():
    try:
        data = request.get_json()
        target_player = data.get('target_player')
        criteria = data.get('criteria')

        if not target_player or not criteria:
            return jsonify({'error': 'Target player and criteria are required'}), 400
        
        prompt = f"Find top 3 current and top 3 historical players similar to {target_player} based on the following criteria: {', '.join(criteria)}. Provide detailed reasoning."
        similar_players_analysis = ask_perp(prompt)
        if "Error from AI" in similar_players_analysis:
            return jsonify({'error': similar_players_analysis}), 500
        
        auth_header = request.headers.get('Authorization', '')
        token = auth_header.split(' ')[1]
        uid = verify_token(token)

        analysis_id = str(uuid.uuid4())

        if FIREBASE_INITIALIZED:
            user_analyses_ref = db.reference(f'user_analyses/{uid}')
            analysis_data = {
                'type': 'similar_players',
                'target_player': target_player,
                'criteria': criteria,
                'prompt': prompt,
                'explanation': similar_players_analysis,
                'created_at': datetime.utcnow().isoformat()
            }
            user_analyses_ref.child(analysis_id).set(analysis_data)
            logging.info(f"Similar players analysis stored for user {uid} with ID: {analysis_id}")
        else:
            logging.warning("Firebase not initialized. Similar players analysis will not be saved.")

        return jsonify({'similar_players': similar_players_analysis, 'analysis_id': analysis_id})
    
    except Exception as e:
        logging.error(f"Error in /api/nba/similar_players: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/nba/manual_player_compare', methods=['POST'])
@credit_required(cost=1)
@cross_origin()
def manual_player_compare():
    try:
        data = request.get_json()
        player1_name = data.get('player1_name')
        player1_season = data.get('player1_season')
        player2_name = data.get('player2_name')
        player2_season = data.get('player2_season')

        if not player1_name or not player2_name:
            return jsonify({'error': 'Both player names are required'}), 400

        player1_str = f"{player1_name} ({player1_season} season)" if player1_season else player1_name
        player2_str = f"{player2_name} ({player2_season} season)" if player2_season else player2_name

        comparison_context = "Statistical comparison"
        if player1_season and player2_season:
            comparison_context += f" (specifically {player1_season} vs {player2_season} seasons)"
        elif player1_season:
            comparison_context += f" (specifically {player1_season} season for {player1_name} vs {player2_name}'s career/prime)"
        elif player2_season:
            comparison_context += f" (specifically {player1_name}'s career/prime vs {player2_season} season for {player2_name})"
        else:
            comparison_context += " (career/prime comparison)"

        prompt = (
            f"Compare {player1_str} vs {player2_str} in detail: "
            f"1. {comparison_context}. "
            "2. Playing style similarities and differences. 3. Strengths and weaknesses of each. "
            "4. Team impact and role. 5. Overall similarity score (1-10). "
            "Provide a comprehensive comparison with specific examples."
        )
        
        comparison = ask_perp(prompt)
        if "Error from AI" in comparison:
            return jsonify({'error': comparison}), 500
        
        return jsonify({'comparison': comparison})
    except Exception as e:
        logging.error(f"Error in /api/nba/manual_player_compare: {e}")
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=7860)
