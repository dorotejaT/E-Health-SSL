from flask import Flask, render_template, redirect, url_for, request, flash, session
from OpenSSL import crypto
import textwrap
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

def fix_cert_format(raw_cert):
    raw_cert = raw_cert.strip()
    raw_cert = raw_cert.replace("-----BEGIN CERTIFICATE-----", "")
    raw_cert = raw_cert.replace("-----END CERTIFICATE-----", "")
    raw_cert = raw_cert.replace(" ", "").replace("\n", "").replace("\r", "")
    wrapped = "\n".join(textwrap.wrap(raw_cert, 64))
    return f"-----BEGIN CERTIFICATE-----\n{wrapped}\n-----END CERTIFICATE-----"


# Initialize default patients in session if not exists
def init_patients():
    if 'patients' not in session:
        session['patients'] = [
            {'id': 1, 'name': 'Ивана Петрова', 'age': 34, 'medical_history': 'Алергија на полен, астма'},
            {'id': 2, 'name': 'Мартин Јованов', 'age': 45, 'medical_history': 'Дијабетес тип 2, висок крвен притисок'},
            {'id': 3, 'name': 'Елена Ристова', 'age': 29, 'medical_history': 'Нема значајна историја'},
            {'id': 4, 'name': 'Гоце Велков', 'age': 52, 'medical_history': 'Кардиоваскуларни проблеми, хипертензија'},
            {'id': 5, 'name': 'Снежана Димитрова', 'age': 61, 'medical_history': 'Остеопороза, алергија на пеницилин'}
        ]
        session['next_patient_id'] = 6


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login')
def login():
    cert_pem = (
            request.headers.get('X-SSL-Client-Cert') or
            request.environ.get('SSL_CLIENT_CERT') or
            request.headers.get('SSL_CLIENT_CERT')
    )

    print("=== SSL Environment Variables ===")
    for key, value in request.environ.items():
        if 'SSL' in key:
            print(f"{key}: {value}")

    print("=== HTTP Headers ===")
    for key, value in request.headers.items():
        if 'SSL' in key or 'CERT' in key:
            print(f"{key}: {value}")

    if not cert_pem:
        ssl_vars = {k: v for k, v in request.environ.items() if 'SSL' in k}
        return f"""
        <h2>Не е доставен клиентски сертификат</h2>
        <p>Мора да се најавите со сертификат.</p>
        <h3>Debug информации:</h3>
        <pre>SSL Environment Variables: {ssl_vars}</pre>
        <pre>All Headers: {dict(request.headers)}</pre>
        """

    try:
        cert_pem = fix_cert_format(cert_pem)
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)
        subject = dict(cert.get_subject().get_components())

        cn = None
        for key, value in subject.items():
            if key == b'CN':
                cn = value.decode('utf-8')
                break

        if not cn:
            return "<h2>Не може да се извлече Common Name од сертификатот.</h2>"

        print(f"User CN: {cn}")

        session['user'] = cn

        if "Doctor" in cn or "doctor" in cn.lower():
            return redirect(url_for('doctor_dashboard'))
        elif "Patient" in cn or "patient" in cn.lower():
            return redirect(url_for('patient_dashboard'))
        elif "Admin" in cn or "admin" in cn.lower():
            return redirect(url_for('admin_dashboard'))
        else:
            return f"<h2>Непознат тип на корисник: {cn}</h2>"

    except Exception as e:
        return f"""
        <h2>Грешка при читање сертификат</h2>
        <pre>{str(e)}</pre>
        <pre>Certificate data (truncated): {cert_pem[:200]}...</pre>
        """


@app.route('/doctor')
def doctor_dashboard():
    user = session.get('user', request.args.get('user', 'Doctor'))
    init_patients()  # Initialize patients if not exists
    patients = session.get('patients', [])
    return render_template('doctor_dashboard.html', user=user, patients=patients)


@app.route('/add_patient', methods=['GET', 'POST'])
def add_patient():
    if request.method == 'POST':
        # Get form data
        name = request.form.get('name')
        age = request.form.get('age')
        medical_history = request.form.get('medical_history', '')
        
        # Initialize patients if not exists
        init_patients()
        
        # Create new patient
        new_patient = {
            'id': session['next_patient_id'],
            'name': name,
            'age': int(age),
            'medical_history': medical_history
        }
        
        # Add to session
        session['patients'].append(new_patient)
        session['next_patient_id'] += 1
        session.modified = True  # Mark session as modified
        
        # Flash success message
        flash(f'Пациентот {name} е успешно додаден!', 'success')
        
        # Redirect back to doctor dashboard
        return redirect(url_for('doctor_dashboard'))
    
    # GET request - show the form
    return render_template('add_patient.html')


@app.route('/patient')
def patient_dashboard():
    user = session.get('user', request.args.get('user', 'Patient'))
    return render_template('patient_dashboard.html', user=user)


@app.route('/admin')
def admin_dashboard():
    user = session.get('user', request.args.get('user', 'Admin'))
    return render_template('admin_dashboard.html', user=user)


@app.route('/debug-ssl')
def debug_ssl():
    ssl_info = {k: v for k, v in request.environ.items() if 'SSL' in k}
    headers_info = dict(request.headers)

    return f"""
    <h2>SSL Debug Information</h2>
    <h3>Environment Variables:</h3>
    <pre>{ssl_info}</pre>
    <h3>HTTP Headers:</h3>
    <pre>{headers_info}</pre>
    """


@app.route('/manage_users')
def manage_users():
    return render_template('manage_users.html')


@app.route('/generate_reports')
def generate_reports():
    return render_template('generate_reports.html')


@app.route('/view_logs')
def view_logs():
    return render_template('view_logs.html')


@app.route('/logout')
def logout():
    session.clear()
    flash("Успешно се одјавивте.", "info")
    return redirect(url_for('login'))


if __name__ == '__main__':
    print("Starting Flask on http://127.0.0.1:5000")
    print("Access it through Apache at https://localhost")
    app.run(host='127.0.0.1', port=5000, debug=True)