from flask import Flask, request, jsonify, send_from_directory, session
from flask_cors import CORS
import os
import json
import smtplib
import requests
from email.mime.text import MIMEText
from pymongo import MongoClient
from pymongo.server_api import ServerApi
from dotenv import load_dotenv
import secrets
import string
from datetime import datetime
from bson import ObjectId
from functools import wraps

# Load configuration
load_dotenv()

# Initialize Flask app
app = Flask(__name__, static_folder='public')
app.secret_key = os.getenv("SECRET_KEY")
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'fallback_key')
# Session configuration
app.config.update(
    PERMANENT_SESSION_LIFETIME=3600,  # 1 hour session lifetime
    SESSION_COOKIE_SECURE=True,       # Requires HTTPS in production
    SESSION_COOKIE_HTTPONLY=True,     # Prevent client-side JS access
    SESSION_COOKIE_SAMESITE='Lax'     # CSRF protection
)
CORS(app)  # Enable CORS for all routes
# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'officer_id' not in session:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated_function
# API and Database Configuration
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
MONGO_URI = os.getenv("MONGO_URI")
YOUR_EMAIL = os.getenv("YOUR_EMAIL")
YOUR_PASSWORD = os.getenv("YOUR_PASSWORD")

# MongoDB setup
# client = MongoClient(MONGO_URI)
# db = client["petition_system"]
# petitions_collection = db["petitions"]
# users_collection = db["users"]  # For department officers
# officers_collection = db["officers"]  # For tracking officer actions


# Get MongoDB URI
mongo_uri = os.getenv("MONGO_URI")

if not mongo_uri:
    raise ValueError("MONGO_URI not found in .env file.")

# Optional: fix scheme if someone adds without it
if not mongo_uri.startswith(("mongodb://", "mongodb+srv://")):
    mongo_uri = f"mongodb+srv://{mongo_uri}"

# Connect to MongoDB
client = MongoClient(mongo_uri, server_api=ServerApi('1'), tls=True)


db = client["petition_system"]
petitions_collection = db["petitions"]
users_collection = db["users"]  # For department officers
officers_collection = db["officers"]  # For tracking officer actions
# Test the connection
try:
    client.admin.command('ping')
    print("Successfully connected to MongoDB Atlas!")
except Exception as e:
    print(f"Connection failed: {e}")



@app.route('/api/check-session', methods=['GET'])
def check_session():
    """
    Validate active session and return officer data if authenticated
    Returns:
        - 200 with officer data if valid session
        - 401 if no valid session
    """
    try:
        # Check if session contains required officer data
        if not all(key in session for key in ['officer_id', 'name', 'department']):
            app.logger.warning("Session missing required fields")
            return jsonify({"error": "Session invalid", "message": "Missing session data"}), 401
        
        # Verify session expiration (optional additional check)
        if 'last_activity' in session:
            last_active = datetime.strptime(session['last_activity'], "%Y-%m-%dT%H:%M:%S")
            if (datetime.now() - last_active).total_seconds() > 3600:  # 1 hour timeout
                app.logger.warning(f"Session expired for officer {session['officer_id']}")
                session.clear()
                return jsonify({"error": "Session expired"}), 401
        
        # Update last activity time
        session['last_activity'] = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        
        # Return officer data
        return jsonify({
            "officer_id": session['officer_id'],
            "name": session['name'],
            "department": session['department'],
            "session_active": True
        }), 200
        
    except Exception as e:
        app.logger.error(f"Session check error: {str(e)}")
        return jsonify({
            "error": "Internal server error",
            "message": "Could not validate session"
        }), 500


# API Routes
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    officer_id = data.get('officer_id')
    password = data.get('password')
    
    officer = users_collection.find_one({"officer_id": officer_id, "password": password})
    if not officer:
        return jsonify({"error": "Invalid credentials"}), 401
    
    session['officer_id'] = officer_id
    session['department'] = officer['department']
    session['name'] = officer['name']
    session['last_activity'] = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    print("session is ",session)
    return jsonify({
        "message": "Login successful",
        "officer": {
            "name": officer['name'],
            "department": officer['department'],
            "email": officer['email']
        }
    }), 200

@app.route('/api/logout')
def logout():
    session.clear()
    return jsonify({"message": "Logged out successfully"}), 200

@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.get_json()
    
    # Basic department ID verification
    if not data.get('department_id', '').startswith('TN25'):
        return jsonify({"error": "Invalid department ID"}), 400
    
    # Check if officer already exists
    if users_collection.find_one({"officer_id": data['officer_id']}):
        return jsonify({"error": "Officer ID already exists"}), 400
    
    # Create new officer
    officer = {
        "officer_id": data['officer_id'],
        "password": data['password'],
        "name": data['name'],
        "email": data['email'],
        "department": data['department'],
        "created_at": datetime.now(),
        "verified": False  # Admin needs to verify
    }
    
    users_collection.insert_one(officer)
    return jsonify({"message": "Signup successful. Awaiting verification."}), 201













# Department to email mapping
DEPARTMENT_EMAILS = {
    "Transport": "tamilarasu.k369@gmail.com",
    "Water Supply": "tamilarasu.k369@gmail.com",
    "Electricity": "tamilarasu.k369@gmail.com",
    "Sanitation": "tamilarasu.k369@gmail.com",
    "Health": "tamilarasu.k369@gmail.com",
    "Education": "tamilarasu.k369@gmail.com",
    "Housing": "tamilarasu.k369@gmail.com",
    "Public Safety": "tamilarasu.k369@gmail.com",
    "Other": "tamilarasu.k369@gmail.com"
}

# Classification prompt template
# Classification prompt template
CLASSIFICATION_PROMPT = """
You are an AI assistant that processes citizen petitions and generates formal government responses. Perform these tasks:

1. Department Classification:
   - Transport
   - Water Supply
   - Electricity
   - Sanitation
   - Health
   - Education
   - Housing
   - Public Safety
   - Other

2. Urgency Assessment:
   - High (24hr response required)
   - Medium (3-5 day response)
   - Low (routine handling)

3. Generate Formal Letter with this structure:
   - Official letterhead
   - Reference number
   - Date
   - Citizen's details
   - Formal salutation
   - Acknowledgment of receipt
   - Department assignment notice
   - Expected timeline
   - Official closing

Input Email:
{email_text}

Respond ONLY with this JSON format:
{{
  "department": "[classified_department]",
  "urgency": "[high/medium/low]",
  "formal_letter": "[complete_letter_with_newlines]",
  "response_timeline": "[expected_days]"
}}
Example letter format:

Subject: Acknowledgement of Your Petition [REF-12345]

Dear [Citizen Name],

We acknowledge receipt of your petition regarding [brief summary]. 

This matter has been assigned to our [Department] for review. Based on the urgency assessment, we expect to respond within [timeline].

For urgent matters, you may contact [department email].

Sincerely,
[Officer Name]
[Department Name]
"""


def classify_petition(email_text, sender_email):
    """Classify the petition using Gemini API"""
    print("\nStarting petition classification...")
    try:
        prompt = CLASSIFICATION_PROMPT.format(email_text=email_text)
        api_response = call_gemini_api(prompt)
        
        if not api_response:
            print("API call failed")
            return None
            
        # Debug: Print full API response
        print("Full API response:", json.dumps(api_response, indent=2))
        
        # Handle potential errors in response
        if 'error' in api_response:
            print(f"API returned error: {api_response['error']}")
            return None
            
        # Safely extract the generated text
        if 'candidates' not in api_response or not api_response['candidates']:
            print("No candidates in response")
            return None
            
        candidate = api_response['candidates'][0]
        if 'content' not in candidate or 'parts' not in candidate['content']:
            print("Invalid content structure")
            return None
            
        parts = candidate['content']['parts']
        if not parts or 'text' not in parts[0]:
            print("No text in response parts")
            return None
            
        generated_text = parts[0]['text']
        print("Raw response text:", generated_text)
        
        # Parse the JSON response
        try:
            classification = json.loads(generated_text)
            if not all(key in classification for key in ['department', 'urgency']):
                print("Missing required classification fields")
                return None
                
            print("Classification successful:")
            print(f"Department: {classification['department']}")
            print(f"Urgency: {classification['urgency']}")
            return classification
            
        except json.JSONDecodeError as e:
            print(f"Failed to parse JSON: {e}")
            print("Response was:", generated_text)
            return None
            
    except Exception as e:
        print(f"Error in classification process: {e}")
        return None


# Helper functions
def generate_tracking_token(length=16):
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def call_gemini_api(prompt_text):
    headers = {'Content-Type': 'application/json'}
    params = {'key': GEMINI_API_KEY}
    payload = {
        "contents": [{"parts": [{"text": prompt_text}]}],
        "generationConfig": {"response_mime_type": "application/json"}
    }
    try:
        response = requests.post(GEMINI_API_URL, headers=headers, params=params, json=payload, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"API call failed: {e}")
        return None

def send_email(to_email, subject, body):
    try:
        msg = MIMEText(body, 'html')  # Instead of just MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = YOUR_EMAIL
        msg['To'] = to_email
        
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp_server:
            smtp_server.login(YOUR_EMAIL, YOUR_PASSWORD)
            smtp_server.send_message(msg)
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False



CONTENT_NORMALIZATION_PROMPT = """
You are a government document processing AI. Transform the following raw petition text into a structured, professional format:

1. Extract key components:
   - Citizen's primary concern
   - Supporting details
   - Specific requests/demands
   - Any referenced incidents/dates

2. Format as:
   [Main Concern]
   - Details: [Bullet points]
   - Request: [Clear action desired]
   - Supporting Info: [Relevant facts]

3. Maintain original meaning while improving:
   - Grammar
   - Clarity
   - Conciseness
   - Professional tone

Input Text:
{raw_text}

Output ONLY the structured version in this format:
{{
  "structured_content": "[formatted_text]",
  "key_details": {
    "primary_concern": "[1-2 sentence summary]",
    "requested_action": "[specific action]",
    "urgency_indicator": "[explicit/implicit]"
  }
}}
"""

def normalize_petition_content(raw_text):
    """Structure raw petition text for better readability"""
    try:
        prompt = CONTENT_NORMALIZATION_PROMPT.format(raw_text=raw_text)
        response = call_gemini_api.generate_content(prompt)
        
        if not response:
            return {
                "structured_content": raw_text,
                "key_details": {
                    "primary_concern": "Unable to parse",
                    "requested_action": "Review required",
                    "urgency_indicator": "unknown"
                }
            }
        
        # Extract JSON from response
        json_str = response.text.strip().replace('```json', '').replace('```', '').strip()
        normalized = json.loads(json_str)
        
        return normalized
        
    except Exception as e:
        print(f"Content normalization error: {e}")
        # Fallback to original text if parsing fails
        return {
            "structured_content": raw_text,
            "key_details": {
                "primary_concern": "Unstructured content",
                "requested_action": "Manual review needed",
                "urgency_indicator": "unknown"
            }
        }



def check_submission_cooldown(email):
    """Check if email has submitted a petition within last 5 minutes"""
    last_submission = petitions_collection.find_one(
        {"sender_email": email},
        sort=[("created_at", -1)]  # Get most recent submission
    )
    
    if last_submission:
        time_since_last = datetime.now() - last_submission["created_at"]
        if time_since_last.total_seconds() < 300:  # 300 seconds = 5 minutes
            return False, time_since_last
    return True, None

# API Routes
@app.route('/api/submit-petition', methods=['POST'])
def submit_petition():
    try:
        data = request.get_json()
        email_text = data.get('content', '')
        sender_email = data.get('sender_email', '')
        
        if not email_text or not sender_email:
            return jsonify({"error": "Missing required fields"}), 400
        
        # Check submission cooldown
        allowed, time_since = check_submission_cooldown(sender_email)
        if not allowed:
            remaining_time = 300 - time_since.total_seconds()
            return jsonify({
                "error": "Submission limit exceeded\n"+f"Please wait {int(remaining_time//60)} minutes and {int(remaining_time%60)} seconds before submitting again",
                "message": f"Please wait {int(remaining_time//60)} minutes and {int(remaining_time%60)} seconds before submitting again"
            }), 429  # 429 = Too Many Requests

        # Normalize content first
        normalized = normalize_petition_content(email_text)
        structured_content = normalized["structured_content"]
        classification = classify_petition(email_text, sender_email)
        if not classification:
            return jsonify({"error": "Failed to classify petition"}), 500
        


        # Create petition record
        token = generate_tracking_token()
        # Create petition document
        petition = {
            "sender_email": sender_email,
            "original_content": email_text,  # Keep original
            "content": structured_content,
            "key_details": normalized["key_details"],
            "department": classification["department"],
            "urgency": classification["urgency"],
            "formal_letter": classification["formal_letter"],
            "status": "received",
            "tracking_token": token,
            "created_at": datetime.now(),
            "updated_at": datetime.now(),
            "assigned_to": DEPARTMENT_EMAILS.get(classification["department"]),
            "verified": False
        }
        
        result = petitions_collection.insert_one(petition)
        
        # Send emails
        sender_subject = f"Petition Received (Token: {token})"
        sender_body = f"""
                <html>
                <head>
                    <style>
                        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                        .header {{ color: #0056b3; font-size: 20px; font-weight: bold; }}
                        .token {{ background: #f0f7ff; padding: 8px 12px; border-radius: 4px; 
                                font-family: monospace; font-size: 16px; }}
                        .footer {{ font-size: 12px; color: #666; margin-top: 20px; }}
                        .button {{ background: #0056b3; color: white; padding: 10px 15px; 
                                text-decoration: none; border-radius: 4px; display: inline-block; }}
                    </style>
                </head>
                <body>
                    <div class="header">Your Petition Has Been Received</div>
                    <p>Dear Citizen,</p>
                    
                    <p>We acknowledge receipt of your petition regarding <strong>{classification["department"]}</strong> 
                    with <strong>{classification["urgency"]} urgency</strong>.</p>
                    
                    <p>Your tracking token is: <span class="token">{token}</span></p>
                    
                    <p>You can track the status of your petition using this token on our portal.</p>
                    
                    <a href="https://petitiionsdesk.onrender.com/" class="button" style="background-color: #0056b3; 
                        color: white; 
                        padding: 10px 15px; 
                        text-decoration: none; 
                        border-radius: 4px; 
                        display: inline-block;
                        font-family: Arial, sans-serif;
                        font-size: 16px;
                        font-weight: bold;
                        text-align: center;
                        margin: 10px 0;">Track Your Petition
                    </a>
                    
                    <p>Here's what happens next:</p>
                    <ol>
                        <li>Your petition will be reviewed by our department</li>
                        <li>We may contact you for additional information if needed</li>
                        <li>You'll receive updates as we process your request</li>
                    </ol>
                    
                    <div class="footer">
                        <p>Thank you for participating in our democratic process.</p>
                        <p><strong>{classification["department"]} Department</strong><br>
                        Government Services</p>
                    </div>
                </body>
                </html>
                """  # Your email content
        send_email(sender_email, sender_subject, sender_body)
        
        dept_subject = f"New Petition - {classification['urgency']} urgency"
        dept_body = f"""
            <html>
            <head>
                <style>
                    body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                    .header {{ color: #d9534f; font-size: 20px; font-weight: bold; }}
                    .alert-box {{ background: #f8f9fa; border-left: 4px solid #d9534f; 
                                padding: 12px; margin: 10px 0; }}
                    .token {{ background: #f0f7ff; padding: 8px 12px; border-radius: 4px; 
                            font-family: monospace; font-size: 16px; }}
                    .button {{ background: #0056b3; color: white; padding: 10px 15px; 
                            text-decoration: none; border-radius: 4px; display: inline-block; }}
                    .urgency-high {{ color: #d9534f; font-weight: bold; }}
                    .urgency-medium {{ color: #f0ad4e; font-weight: bold; }}
                    .urgency-low {{ color: #5cb85c; font-weight: bold; }}
                </style>
            </head>
            <body>
                <div class="header">NEW PETITION REQUIRES ACTION</div>
                
                <div class="alert-box">
                    <strong>Urgency:</strong> 
                    <span class="urgency-{classification['urgency']}">
                        {classification['urgency'].upper()}
                    </span>
                </div>
                
                <p><strong>Department:</strong> {classification['department']}</p>
                <p><strong>Tracking Token:</strong> <span class="token">{token}</span></p>
                <p><strong>Received:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
                
                <h3>Petition Summary:</h3>
                <div style="background: #f8f9fa; padding: 12px; border-radius: 4px;">
                    {email_text[:500]}{'...' if len(email_text) > 500 else ''}
                </div>
                
                <p style="margin-top: 20px;">
                    <a href="https://petitiionsdesk.onrender.com/department.html" class="button" style="background-color: #0056b3; 
                        color: white; 
                        padding: 10px 15px; 
                        text-decoration: none; 
                        border-radius: 4px; 
                        display: inline-block;
                        font-family: Arial, sans-serif;
                        font-size: 16px;
                        font-weight: bold;
                        text-align: center;
                        margin: 10px 0;">
                        View Full Petition
                    </a>
                </p>
                
                <h3>Required Actions:</h3>
                <ol>
                    <li>Review petition details in the department portal</li>
                    <li>Verify information and assign to appropriate officer</li>
                    <li>Update status within { '24 hours' if classification['urgency'] == 'high' else '3 working days' }</li>
                </ol>
                
                <div style="margin-top: 30px; font-size: 12px; color: #666;">
                    <p>This is an automated notification. Please do not reply to this email.</p>
                    <p>Petition Management System | {datetime.now().strftime('%Y')} Government Services</p>
                </div>
            </body>
            </html>""" # Your department email content
        send_email(petition["assigned_to"], dept_subject, dept_body)
        
        return jsonify({"tracking_token": token, "formal_letter": petition["formal_letter"]}), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/track-petition', methods=['POST'])
def track_petition():
    try:
        data = request.get_json()
        tracking_token = data.get('tracking_token')
        
        if not tracking_token:
            return jsonify({"error": "Tracking token required"}), 400
        
        petition = petitions_collection.find_one({
            "tracking_token": tracking_token
        })
        
        if not petition:
            return jsonify({"error": "Petition not found"}), 404
        
        # Prepare response
        response = {
            "tracking_token": petition["tracking_token"],
            "sender_email": petition["sender_email"],
            "content": petition["content"],
            "department": petition["department"],
            "urgency": petition["urgency"],
            "status": petition["status"],
            "created_at": petition["created_at"].strftime("%Y-%m-%d %H:%M:%S")
        }
        
        if "updated_at" in petition:
            response["updated_at"] = petition["updated_at"].strftime("%Y-%m-%d %H:%M:%S")
        
        return jsonify(response), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/verify-petition', methods=['POST'])
@login_required
def verify_petition():
    try:
        data = request.get_json()
        tracking_token = data.get('tracking_token')
        print("This is TRACKING->>",tracking_token)
        
        if not tracking_token:
            return jsonify({"error": "Tracking token required"}), 400
        
        # Update petition status
        result = petitions_collection.update_one(
            {
                "tracking_token": tracking_token
                # "department": session.get('department')
            },
            {
                "$set": {
                    "status": "verified",
                    "verified": True,
                    "verified_by": session.get('officer_id'),
                    "verified_at": datetime.now(),
                    "updated_at": datetime.now()
                }
            }
        )
        
        if result.modified_count == 0:
            return jsonify({"error": "Petition not found or already verified"}), 404
        
        # Get petition to send email
        petition = petitions_collection.find_one({"tracking_token": tracking_token})
        
        # Send verification email
        send_email(
            to_email=petition["sender_email"],
            subject=f"Petition Verified: {petition['key_details']['primary_concern'][:50]}... (Ref: {tracking_token})",
            body=f"""
            <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto;">
                <div style="background-color: #f5f5f5; padding: 20px; border-radius: 5px;">
                    <h2 style="color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px;">
                        <img src="https://example.com/logo.png" alt="Government Logo" style="height: 40px; vertical-align: middle;">
                        Petition Verification Confirmation
                    </h2>
                    
                    <p>Dear Citizen,</p>
                    
                    <p>We're pleased to inform you that your petition has been <strong>officially verified</strong> and is now being processed:</p>
                    
                    <div style="background-color: #fff; border-left: 4px solid #3498db; padding: 15px; margin: 15px 0;">
                        <h3 style="margin-top: 0; color: #2c3e50;">{petition['key_details']['primary_concern']}</h3>
                        <p style="font-style: italic;">"{petition['content'][:200]}..."</p>
                    </div>
                    
                    <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
                        <tr>
                            <td style="padding: 8px; background-color: #f8f9fa; width: 120px;"><strong>Reference No:</strong></td>
                            <td style="padding: 8px; background-color: #f8f9fa;">{tracking_token}</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px;"><strong>Department:</strong></td>
                            <td style="padding: 8px;">{petition['department']}</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px; background-color: #f8f9fa;"><strong>Priority:</strong></td>
                            <td style="padding: 8px; background-color: #f8f9fa;">{petition['urgency'].capitalize()} urgency</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px;"><strong>Submitted On:</strong></td>
                            <td style="padding: 8px;">{petition['created_at'].strftime('%d %b %Y at %H:%M')}</td>
                        </tr>
                    </table>
                    
                    <div style="background-color: #e8f4fc; padding: 15px; border-radius: 5px; margin: 20px 0;">
                        <h4 style="margin-top: 0; color: #2c3e50;">Next Steps:</h4>
                        <ol>
                            <li>Your case has been assigned to {petition['department']} team</li>
                            <li>Expected response timeline: <strong>{'24 hours' if petition['urgency'] == 'high' else '3-5 working days'}</strong></li>
                            <li>You'll receive updates at this email address</li>
                        </ol>
                    </div>
                    
                    <p style="text-align: center; margin-top: 25px;">
                        <a href="https://petitiionsdesk.onrender.com/" 
                        style="background-color: #3498db; color: white; padding: 10px 20px; 
                                text-decoration: none; border-radius: 5px; display: inline-block;">
                        Track Your Petition Status
                        </a>
                    </p>
                    
                    <p style="font-size: 0.9em; color: #7f8c8d;">
                        For any urgent inquiries, please contact {petition['department']} at: 
                        <a href="mailto:{petition['assigned_to']}">{petition['assigned_to']}</a>
                    </p>
                    
                    <p>Sincerely,<br>
                    <strong>Public Services Team</strong><br>
                    Government of Tamil Nadu</p>
                </div>
                
                <p style="font-size: 0.8em; color: #95a5a6; text-align: center; margin-top: 20px;">
                    This is an automated message. Please do not reply directly to this email.
                </p>
            </body>
            </html>
            """
        )
        
        return jsonify({"message": "Petition verified successfully"}), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/send-reply', methods=['POST'])
@login_required
def send_reply():
    try:
        data = request.get_json()
        tracking_token = data.get('tracking_token')
        recipient = data.get('recipient')
        subject = data.get('subject')
        message = data.get('message')
        new_status = data.get('new_status', 'verified')  # Default to verified
        
        if not all([tracking_token, recipient, subject, message]):
            return jsonify({"error": "All fields are required"}), 400
        
        # Get petition to verify department
        petition = petitions_collection.find_one({
            "tracking_token": tracking_token
            # "department": session.get('department')
        })
        
        if not petition:
            return jsonify({"error": "Petition not found"}), 404
        
        # Get officer details from session
        officer_name = session.get('name', 'Government Officer')
        officer_dept = session.get('department', petition['department'])
        officer_email = session.get('email', petition['assigned_to'])

        # Create HTML email body
        html_body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto;">
            <div style="background-color: #f5f5f5; padding: 20px; border-radius: 5px;">
                <h2 style="color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px;">
                    <img src="https://unpkg.com/@dotlottie/player-component@2.7.12/dist/dotlottie-player.mjs" alt="Government Logo" style="height: 40px;">
                    Official Response to Your Petition
                </h2>
                
                <p>Dear Citizen,</p>
                
                <div style="background-color: #fff; border-left: 4px solid #3498db; padding: 15px; margin: 15px 0;">
                    <h3 style="margin-top: 0; color: #2c3e50;">Re: {subject}</h3>
                    <p>Reference No: <strong>{tracking_token}</strong></p>
                    <p>Original Petition: <em>"{petition['content'][:100]}..."</em></p>
                </div>
                
                <div style="background-color: #e8f4fc; padding: 15px; border-radius: 5px; margin: 20px 0;">
                    <h4 style="margin-top: 0; color: #2c3e50;">Official Response:</h4>
                    <div style="white-space: pre-line;">{message}</div>
                </div>
                
                <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
                    <tr>
                        <td style="padding: 8px; background-color: #f8f9fa; width: 120px;"><strong>Status Update:</strong></td>
                        <td style="padding: 8px; background-color: #f8f9fa;">
                            <span style="color: {'#27ae60' if new_status == 'completed' else '#3498db'}">
                                {new_status.capitalize()}
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 8px;"><strong>Responding Officer:</strong></td>
                        <td style="padding: 8px;">{officer_name}</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px; background-color: #f8f9fa;"><strong>Department:</strong></td>
                        <td style="padding: 8px; background-color: #f8f9fa;">{officer_dept}</td>
                    </tr>
                </table>
                
                <div style="text-align: center; margin: 25px 0;">
                    <a href="https://petitiionsdesk.onrender.com/" 
                       style="background-color: #3498db; color: white; padding: 10px 20px; 
                              text-decoration: none; border-radius: 5px; display: inline-block;">
                       View Full Petition Details
                    </a>
                </div>
                
                <p style="font-size: 0.9em; color: #7f8c8d;">
                    For further inquiries, please contact:
                    <a href="mailto:{officer_email}">{officer_email}</a>
                </p>
                
                <p>Sincerely,<br>
                <strong>{officer_name}</strong><br>
                {officer_dept} Department</p>
            </div>
            
            <p style="font-size: 0.8em; color: #95a5a6; text-align: center; margin-top: 20px;">
                This is an official communication from the Government Services.
            </p>
        </body>
        </html>
        """

        # Send email
        send_email(
            to_email=recipient,
            subject=f"Reg: {subject} (Ref: {tracking_token})",
            body=html_body
        )
        
        # Update petition with reply info and new status
        update_data = {
            "replied_at": datetime.now(),
            "replied_by": session.get('officer_id'),
            "reply_message": message,
            "updated_at": datetime.now(),
            "status": new_status
        }
        
        # If marking as completed, add completion timestamp
        if new_status == "completed":
            update_data["completed_at"] = datetime.now()
        
        petitions_collection.update_one(
            {"tracking_token": tracking_token},
            {"$set": update_data}
        )
        
        return jsonify({
            "message": "Reply sent and status updated successfully",
            "new_status": new_status
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500





@app.route('/api/department/petitions')
@login_required
def get_petitions():
    try:
        # Get filter parameters
        # department = session.get('department')
        department = request.args.get('department')
        status = request.args.get('status')
        urgency = request.args.get('urgency')
        date_from = request.args.get('date_from')
        date_to = request.args.get('date_to')
        search = request.args.get('search')
        page = int(request.args.get('page', 1))
        per_page = 10  # Items per page
        
        # Build query
        query = {"department": department}
        if department == "All Departments":
            query = {}
        if status:
            query["status"] = status
        if urgency and urgency!='ok':
            query["urgency"] = urgency
        if date_from and date_to:
            query["created_at"] = {
                "$gte": datetime.strptime(date_from, "%Y-%m-%d"),
                "$lte": datetime.strptime(date_to, "%Y-%m-%d")
            }
        elif date_from:
            query["created_at"] = {
                "$gte": datetime.strptime(date_from, "%Y-%m-%d")
            }
        elif date_to:
            query["created_at"] = {
                "$lte": datetime.strptime(date_to, "%Y-%m-%d")
            }
        if search:
            query["$or"] = [
                {"sender_email": {"$regex": search, "$options": "i"}},
                {"content": {"$regex": search, "$options": "i"}},
                {"tracking_token": {"$regex": search, "$options": "i"}}
            ]
        
        # Get total count for pagination
        total = petitions_collection.count_documents(query)
        total_pages = (total + per_page - 1) // per_page
        # Empty query returns all documents
        # Get paginated results
        petitions = list(petitions_collection.find(query)
            .sort("created_at", -1)
            .skip((page - 1) * per_page)
            .limit(per_page))
        print(petitions)
        # Convert ObjectId and datetime
        for petition in petitions:
            petition["_id"] = str(petition["_id"])
            petition["created_at"] = petition["created_at"].strftime("%Y-%m-%d %H:%M:%S")
            if "updated_at" in petition:
                petition["updated_at"] = petition["updated_at"].strftime("%Y-%m-%d %H:%M:%S")
        
        return jsonify({
            "petitions": petitions,
            "total_pages": total_pages,
            "current_page": page,
            "total_items": total
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500






# Static file serving
@app.route('/')
def serve_index():
    return send_from_directory(app.static_folder, 'form.html')

@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory(app.static_folder, path)



if __name__ == '__main__':
    print(f"\n🚀 Server running at: http://localhost:5000/")
    print("Press Ctrl+C to stop\n")
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)