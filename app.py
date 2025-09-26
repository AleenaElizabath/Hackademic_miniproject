from flask import Flask, request, jsonify, send_from_directory, abort, render_template
from flask_cors import CORS
from pymongo import MongoClient, ReturnDocument
from pymongo.errors import DuplicateKeyError
import os
import numpy as np
import json
import threading
from stable_baselines3 import DQN
from phishing_env import PhishingInboxEnv
MODEL_PATH = "dqn_phishing_agent.zip"
model = DQN.load(MODEL_PATH)
print("DQN model loaded successfully!")
# Attempt to import stable_baselines3 (optional; endpoint will error clearly if missing)
try:
    from stable_baselines3 import DQN
except Exception:
    DQN = None


app = Flask(__name__)
CORS(app)  # allow frontend (JS) to call backend


# Base directory for serving the static/html files that live alongside this script
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


# --- MongoDB Connection ---
client = MongoClient("mongodb://localhost:27017/")
db = client["hackademic_db"]
users_collection = db["users"]
scores_collection = db["scores"]

# Global per-user totals collection (single document per user with an accumulating score)
global_scores_collection = db['user_totals']


# Ensure we don't create duplicate score documents for the same user/week
try:
    scores_collection.create_index([('username', 1), ('week', 1)], unique=True)
except Exception:
    # non-fatal if the DB doesn't allow index creation in this environment
    pass

try:
    global_scores_collection.create_index([('username', 1)], unique=True)
except Exception:
    # non-fatal
    pass


# Lazy-loaded RL model (trained with DQN)
MODEL = None
MODEL_PATH = os.path.join(BASE_DIR, 'models', 'dqn_phishing_model.zip')


# --- Phishing game email pool (in-memory) ---
import uuid
import random
from datetime import datetime


EMAILS = []          # list of {sender,subject,body,label}
SAMPLES = {}         # ephemeral map id -> email
SAMPLES_LOCK = threading.Lock()


attempts_collection = db['phish_attempts']
@app.route('/phishing-detection')
def load_email_pool():
    """
    Loads the phishing/legit email dataset into the global EMAILS list.
    Priority:
      1. CSV file at 'synthetic_phishing_dataset.csv'
      2. phishing.py generator (if exists)
      3. tiny hardcoded fallback dataset
    """
    global EMAILS
    EMAILS = []
    loaded = []
    # Construct absolute CSV path relative to this script
    csv_path = os.path.join(BASE_DIR, 'synthetic_phishing_dataset.csv')
    print(f"[load_email_pool] Looking for CSV at: {csv_path}")
    print(f"File exists? {os.path.exists(csv_path)}")
    # --- 1. Try loading CSV ---
    print("PATH:", csv_path)
    if os.path.exists(csv_path):
        print(f"[load_email_pool] CSV found, loading...")
        import csv
        try:
            with open(csv_path, newline='', encoding='utf-8') as fh:
                reader = csv.DictReader(fh)
                all_rows = list(reader)
                print("LENGTH OF ALL ROWS:", len(all_rows))
                loaded=[]  # Use this for all further processing
                for row in all_rows:
                    sender = (row.get('sender') or '').strip()
                    subject = (row.get('subject') or '').strip()
                    body = (row.get('body') or '').strip()
                    if not (sender or subject or body):
                        continue  # skip empty rows

                    # normalize label
                    raw_label = (row.get('label') or '').strip().lower()
                    if raw_label in ('1', 'true', 't', 'yes', 'y', 'phish', 'phishing'):
                        label = 'phish'
                    else:
                        label = 'legit'

                    loaded.append({
                        'sender': sender,
                        'subject': subject,
                        'body': body,
                        'label': label
                    })
                print("SIZE OF LOADED:", len(loaded))
                EMAILS = loaded
                print(f"[load_email_pool] Loaded {len(EMAILS)} emails from CSV")
                #return  # success
        except Exception as e:
            print(f"[load_email_pool] Error reading CSV: {e}")
    return render_template('games/test.html', items=loaded[0:30])


    # --- 2. Try importing phishing.py module ---
    '''try:
        import phishing as ph
        EMAILS = getattr(ph, 'emails', None)
        if EMAILS:
            print(f"[load_email_pool] Loaded {len(EMAILS)} emails from phishing.py")
            #return
        else:
            print("[load_email_pool] phishing.py exists but no emails found")
    except ModuleNotFoundError:
        print("[load_email_pool] phishing.py module not found")
    except Exception as e:
        print(f"[load_email_pool] Error importing phishing.py: {e}")
    return render_template('games/phishing-detection.html', items=EMAILS)'''


    # --- 3. Fallback tiny dataset ---
    '''EMAILS = [
        {'sender':'support@bank.com','subject':'Monthly statement','body':'Your statement is attached.','label':'legit'},
        {'sender':'bank.verify@secure-login.com','subject':'Account Suspended!','body':'Click the link to verify your account immediately.','label':'phish'}
    ]'''
    #print(f"[load_email_pool] Using fallback dataset with {len(EMAILS)} emails")
    #return render_template('games/phishing-detection.html', items=EMAILS)



# load pool at startup
#load_email_pool()


def load_model():
    global MODEL
    if MODEL is not None:
        return MODEL
    if DQN is None:
        raise RuntimeError('stable_baselines3 is not installed in the environment')
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(f'Model file not found at {MODEL_PATH}')
    MODEL = DQN.load(MODEL_PATH)
    return MODEL


def extract_features_from_email(payload):
    """Accepts either a dict with keys sender/subject/body or a features array.
    Returns a numpy array matching the env observation [sender_type, subject_type, body_type]."""
    # If user already supplied features
    if isinstance(payload, dict) and 'features' in payload:
        arr = np.array(payload['features'], dtype=np.int8)
        if arr.size != 3:
            raise ValueError('features must be an array of 3 binary values')
        return arr

    sender = (payload.get('sender') or '') if isinstance(payload, dict) else ''
    subject = (payload.get('subject') or '') if isinstance(payload, dict) else ''
    body = (payload.get('body') or '') if isinstance(payload, dict) else ''

    sender_type = 1 if ('@' in sender and 'secure-login' in sender) else 0
    subject_type = 1 if any(word in subject.lower() for word in ['verify','urgent','prize','suspended']) else 0
    body_type = 1 if any(word in body.lower() for word in ['click','update','claim','suspended']) else 0
    return np.array([sender_type, subject_type, body_type], dtype=np.int8)


# --- Routes ---


# Serve the main frontend page (index2.html)
@app.route('/')
def index():
    return send_from_directory(BASE_DIR, 'index2.html')


# Serve any other static files (css, js, images, html) that are requested
@app.route('/<path:filename>')
def serve_file(filename):
    # Prevent serving files outside the backend directory
    safe_path = os.path.abspath(os.path.join(BASE_DIR, filename))
    if not safe_path.startswith(BASE_DIR):
        abort(403)
    return send_from_directory(BASE_DIR, filename)



# Register (Sign Up)
@app.route("/api/signup", methods=["POST"])
def signup():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    email = data.get("email")

    if not username or not password or not email:
        return jsonify({"message": "All fields are required"}), 400

    # check if user exists
    if users_collection.find_one({"username": username}):
        return jsonify({"message": "User already exists"}), 400

    users_collection.insert_one({
        "username": username,
        "password": password,  # ⚠️ plain text for now
        "email": email
    })

    return jsonify({"message": "User registered successfully"}), 201



# Login (Sign In)
@app.route("/api/signin", methods=["POST"])
def signin():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    user = users_collection.find_one({"username": username, "password": password})
    if not user:
        return jsonify({"message": "Invalid credentials"}), 401

    return jsonify({"message": "Login successful"}), 200



# Phishing model prediction endpoint
'''@app.route('/api/predict_email', methods=['POST'])
def predict_email():
    """POST JSON: { sender, subject, body } or { features: [0,1,0] }
    Returns: { label: 'phish'|'legit', action: 0|1, message }
    """
    try:
        payload = request.get_json(force=True)
    except Exception:
        return jsonify({'message': 'Invalid JSON payload'}), 400

    try:
        obs = extract_features_from_email(payload)
    except Exception as e:
        return jsonify({'message': str(e)}), 400

    # Ensure model is available
    try:
        model = load_model()
    except FileNotFoundError as fe:
        return jsonify({'message': str(fe)}), 500
    except RuntimeError as re:
        return jsonify({'message': str(re)}), 500
    except Exception as e:
        return jsonify({'message': 'Error loading model: ' + str(e)}), 500

    # model.predict expects a 1D array-like observation
    try:
        action, _ = model.predict(obs, deterministic=True)
    except Exception:
        # Some models expect a batch dimension
        try:
            action, _ = model.predict(obs.reshape(1, -1), deterministic=True)
            if isinstance(action, (list, np.ndarray)):
                action = int(action[0])
        except Exception as e:
            return jsonify({'message': 'Prediction failed: ' + str(e)}), 500

    # action: 0 = mark legit, 1 = mark phish (per environment)
    label = 'phish' if int(action) == 1 else 'legit'
    return jsonify({'label': label, 'action': int(action), 'message': 'Prediction successful'}), 200


'''
# --- Phishing game endpoints ---
@app.route('/api/phish/sample', methods=['GET'])
def phish_sample():
    """Return a random email sample (without label) and a generated email_id to evaluate later."""
    if not EMAILS:
        return jsonify({'message': 'No email pool available'}), 500
    email = random.choice(EMAILS)
    eid = uuid.uuid4().hex
    with SAMPLES_LOCK:
        SAMPLES[eid] = {'email': email, 'ts': datetime.utcnow().isoformat()}

    # send only visible fields
    return jsonify({
        'email_id': eid,
        'sender': email['sender'],
        'subject': email['subject'],
        'body': email['body']
    }), 200



@app.route('/api/phish/evaluate', methods=['POST'])
def phish_evaluate():
    """Evaluate a user's action on a previously-served email.
    Payload: { email_id, action } where action: 0=legit,1=phish
    Returns: { correct: bool, points: int, correct_label }
    """
    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({'message': 'Invalid JSON'}), 400

    eid = data.get('email_id')
    action = data.get('action')
    username = data.get('username')

    if not eid or action is None:
        return jsonify({'message': 'email_id and action are required'}), 400

    with SAMPLES_LOCK:
        rec = SAMPLES.get(eid)

    if not rec:
        return jsonify({'message': 'email_id not found or expired'}), 404

    email = rec['email']
    correct_label = 1 if email.get('label') == 'phish' else 0
    correct = (int(action) == int(correct_label))
    points = 5 if correct else -5

    # store attempt for analytics
    attempt = {
        'email_id': eid,
        'username': username or '',
        'action': int(action),
        'correct_label': int(correct_label),
        'correct': bool(correct),
        'points': int(points),
        'ts': datetime.utcnow()
    }
    try:
        attempts_collection.insert_one(attempt)
    except Exception:
        # non-fatal if DB isn't available
        pass

    # remove the sample so it can't be re-used
    with SAMPLES_LOCK:
        if eid in SAMPLES:
            del SAMPLES[eid]

    return jsonify({'correct': correct, 'points': points, 'correct_label': int(correct_label)}), 200



# --- Leaderboard API ---
@app.route('/api/score', methods=['GET','POST'])
def submit_score():
    """Accepts JSON: { username, school, points, accuracy, week }
    Stores the score in MongoDB with a timestamp.
    """
    data = request.get_json(force=True)
    username = data.get('username')
    points = data.get('points')
    accuracy = data.get('accuracy')
    week = data.get('week')

    if not username or points is None or not week:
        return jsonify({'message': 'username, points and week are required'}), 400

    # normalize points
    try:
        pts = int(points)
    except Exception:
        return jsonify({'message': 'points must be an integer'}), 400

    # parse accuracy (accept '85%' or '85' or numeric)
    def parse_accuracy(a):
        if a is None:
            return None
        try:
            if isinstance(a, str) and a.strip().endswith('%'):
                return float(a.strip().strip('%'))
            return float(a)
        except Exception:
            return None

    acc_val = parse_accuracy(accuracy)
    congrats = (acc_val is not None and acc_val >= 90.0)

    # Normalize week input to ISO week string YYYY-Www
    week_iso = None
    try:
        if isinstance(week, str) and week.strip():
            w = week.strip()
            # if already ISO-week like '2025-W39'
            import re
            if re.match(r'^\d{4}-W\d{2}$', w):
                week_iso = w
            else:
                # try parse as date YYYY-MM-DD
                try:
                    from datetime import date
                    d = date.fromisoformat(w)
                    y, wk, _ = d.isocalendar()
                    week_iso = f"{y}-W{wk:02d}"
                except Exception:
                    # fallback: use current date's ISO week
                    from datetime import date
                    d = date.today()
                    y, wk, _ = d.isocalendar()
                    week_iso = f"{y}-W{wk:02d}"
        else:
            from datetime import date
            d = date.today()
            y, wk, _ = d.isocalendar()
            week_iso = f"{y}-W{wk:02d}"
    except Exception:
        # safest fallback
        from datetime import date
        d = date.today()
        y, wk, _ = d.isocalendar()
        week_iso = f"{y}-W{wk:02d}"

    # Upsert behavior: overwrite the score for (username, week) with the new submission
    now = __import__('datetime').datetime.utcnow()
    filter_doc = {'username': username, 'week': week_iso}
    try:
        # Always update the user's global total points (single document per user).
        try:
            totals_doc = global_scores_collection.find_one_and_update(
                {'username': username},
                {'$inc': {'total_points': pts}, '$set': {'ts': now}},
                upsert=True,
                return_document=ReturnDocument.AFTER
            )
            global_total = int(totals_doc.get('total_points', 0)) if totals_doc else 0
        except Exception:
            # non-fatal; if totals update fails we'll still attempt to save the weekly score
            global_total = None

        # Increment (existing score + new points) the weekly score document atomically.
        update_ops = {
            '$inc': {'points': pts},
            '$set': {'accuracy': f"{acc_val}%" if acc_val is not None else (accuracy or ''), 'ts': now},
            '$setOnInsert': {'username': username, 'week': week_iso}
        }

        # Use find_one_and_update to return the updated document after increment.
        try:
            updated_week_doc = scores_collection.find_one_and_update(
                filter_doc,
                update_ops,
                upsert=True,
                return_document=ReturnDocument.AFTER
            )
        except Exception:
            # fallback to a safer update if find_one_and_update fails for any reason
            scores_collection.update_one(filter_doc, update_ops, upsert=True)
            updated_week_doc = scores_collection.find_one(filter_doc)

        weekly_total = int(updated_week_doc.get('points', 0)) if updated_week_doc else None

        resp = {'message': 'Score saved', 'congrats': congrats, 'updated': True, 'week': week_iso}
        if weekly_total is not None:
            resp['weekly_total'] = weekly_total
        if global_total is not None:
            resp['global_total'] = global_total
        return jsonify(resp), 200
    except Exception as e:
        # If DB is unavailable or other unexpected error, return a 500
        return jsonify({'message': 'Database error: ' + str(e)}), 500


@app.route('/api/leaderboard', methods=['GET'])
def get_leaderboard():
    """Query param: ?week=YYYY-Www  optional: ?limit=10
    Returns top players ordered by points descending.
    """
    week = request.args.get('week')
    if not week:
        return jsonify({'message': 'week parameter is required'}), 400
    try:
        limit = int(request.args.get('limit', 10))
    except Exception:
        limit = 10

    cursor = scores_collection.find({'week': week}).sort('points', -1).limit(limit)
    results = []
    for doc in cursor:
        results.append({
            'username': doc.get('username'),
            'school': doc.get('school'),
            'points': doc.get('points'),
            'accuracy': doc.get('accuracy')
        })

    # last-updated timestamp for this week's scores
    last_doc = scores_collection.find({'week': week}).sort('ts', -1).limit(1)
    last_updated = None
    for d in last_doc:
        ts = d.get('ts')
        if ts:
            try:
                last_updated = ts.isoformat()
            except Exception:
                last_updated = str(ts)

    return jsonify({'week': week, 'leaders': results, 'last_updated': last_updated}), 200


# Debug: fetch latest saved score for a user (optional: ?week=YYYY-Www)
@app.route('/api/score/latest', methods=['GET'])
def get_latest_score():
    username = request.args.get('username')
    week = request.args.get('week')
    if not username:
        return jsonify({'message': 'username query param required'}), 400
    q = {'username': username}
    if week:
        q['week'] = week
    # return the most recent (by ts) matching document
    doc = scores_collection.find(q).sort('ts', -1).limit(1)
    out = None
    for d in doc:
        out = {
            'username': d.get('username'),
            'points': d.get('points'),
            'accuracy': d.get('accuracy'),
            'week': d.get('week'),
            'ts': d.get('ts').isoformat() if hasattr(d.get('ts'), 'isoformat') else str(d.get('ts'))
        }
    if not out:
        return jsonify({'message': 'no score found'}), 404
    return jsonify(out), 200


# Debug: quick DB connectivity check
@app.route('/api/db/status', methods=['GET'])
def db_status():
    try:
        # ping the server
        server_info = client.server_info()
        return jsonify({'ok': True, 'version': server_info.get('version')}), 200
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/api/quiz/questions', methods=['GET'])
def api_quiz_questions():
    """Return quiz questions read from quiz_dataset.csv as JSON.
    Query params: ?limit=20
    """
    import csv
    limit = int(request.args.get('limit', 20))
    csv_path = os.path.join(BASE_DIR, 'quiz_dataset.csv')
    if not os.path.exists(csv_path):
        return jsonify({'message': 'quiz_dataset.csv not found'}), 404
    questions = []
    try:
        with open(csv_path, newline='', encoding='utf-8') as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                q = (row.get('question') or '').strip()
                opts = [ (row.get('option1') or '').strip(), (row.get('option2') or '').strip(), (row.get('option3') or '').strip(), (row.get('option4') or '').strip() ]
                ans = (row.get('answer') or '').strip()
                if not q:
                    continue
                questions.append({'question': q, 'options': opts, 'answer': ans})
                if len(questions) >= limit:
                    break
        return jsonify({'questions': questions}), 200
    except Exception as e:
        return jsonify({'message': 'error reading dataset', 'error': str(e)}), 500


@app.route("/api/predict_mail", methods=["GET","POST"])
def predict_email():
    data = request.json
    if not data:
        return jsonify({"error": "No email data provided"}), 400

    # Expecting email as dict with 'sender', 'subject', 'body'
    email = data.get("email")
    if not email:
        return jsonify({"error": "Email field missing"}), 400

    # Wrap in environment for the agent
    env = PhishingInboxEnv([email])  # single email
    obs, info = env.reset()

    # Get model action
    action, _states = model.predict(obs, deterministic=True)
    action_label = "phish" if action == 1 else "legit"

    return jsonify({
        "email": email,
        "predicted_action": action_label
    })


if __name__ == "__main__":
    app.run(debug=True, port=5000)
