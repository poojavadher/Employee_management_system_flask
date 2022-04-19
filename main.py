import os
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from flask import Flask, redirect, render_template, request, url_for, session, g
import psycopg2
import psycopg2.extras
import datetime
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

app = Flask("__name__")
load_dotenv()
app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]

DB_HOST = os.environ["DB_HOST"]
DB_USER = os.environ["DB_USER"]
DB_PASS = os.environ["DB_PASS"]

con = psycopg2.connect(user=DB_USER, password=DB_PASS, host=DB_HOST)


@app.before_request
def before_request():
    g.userloggedin = None
    g.loggedin = None

    if 'userloggedin' in session:
        g.userloggedin = session['userloggedin']

    if 'loggedin' in session:
        g.loggedin = session['loggedin']


@app.route("/")
def home():
    return redirect(url_for('user_login'))


@app.route("/user-login", methods=["GET", "POST"])
def user_login():
    if not g.userloggedin:
        cursor = con.cursor(cursor_factory=psycopg2.extras.DictCursor)
        # Check if "username" and "password" POST requests exist (user submitted form)
        if request.method == 'POST' and 'email' in request.form and 'password' in request.form:
            session.pop('userloggedin', None)
            session.pop('username', None)
            session.pop('uid', None)
            email = request.form['email']
            password = request.form['password']
            # Check if account exists using MySQL
            cursor.execute(
                f"SELECT * FROM user_login where email = '{email}'")
            # Fetch one record and return result
            account = cursor.fetchone()

            if account:
                password_rs = account['password']
                check = check_password_hash(password_rs, password)
                # If account exists in users table in out database
                if check:
                    # Create session data, we can access this data in other routes
                    session['userloggedin'] = True
                    session['username'] = account['user_name']
                    session['uid'] = account['id']
                    return redirect(url_for('user_panel'))
                else:
                    error = "Invalid credentials"
                    return render_template('User_login.html', error=error)

            else:
                error = "Account with is email doesn't exist..!!"
                return render_template('User_login.html', error=error)

        cursor.close()
        return render_template('User_login.html')
    else:
        return redirect(url_for('user_panel'))


@app.route('/user-dashboard')
def user_panel():
    if g.userloggedin:
        cursor = con.cursor(cursor_factory=psycopg2.extras.DictCursor)
        user_id = session['uid']
        cursor.execute(
            f"SELECT * FROM user_profile,user_login where user_login.id ='{user_id}' and user_profile.user_id='{user_id}'")
        user_account = cursor.fetchone()
        return render_template("user_dashboard.html", name=session['username'], account=user_account)
    else:
        return render_template("User_login.html")


@app.route("/edit-profile/<int:user_id>")
def fetch_edit_user(user_id):
    if g.userloggedin:
        cursor = con.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute(
            f"SELECT * FROM user_login,user_profile where user_login.id = '{user_id}' and user_profile.user_id = '{user_id}'")
        account = cursor.fetchone()
        cursor.close()
        return render_template("edit.html", account=account)
    else:
        return redirect(url_for('home'))


@app.route("/edit", methods=["GET", "POST"])
def edit():
    if g.userloggedin:
        if request.method == "POST":
            user_id = request.form.get("id")
            fname = request.form.get("fname")
            lname = request.form.get("lname")
            dob = request.form.get("dob")
            mobile = request.form.get("mobile")
            gender = request.form.get("gender")
            address = request.form.get("address")
            city = request.form.get("city")
            state = request.form.get("state")
            zipcode = request.form.get("zipcode")
            date_modified = datetime.date.today()
            cursor = con.cursor(cursor_factory=psycopg2.extras.DictCursor)
            sql_update_query = f"""Update user_profile set first_name='{fname}', last_name='{lname}', dob='{dob}',
                                    mobile_number='{mobile}', gender='{gender}', address='{address}', city='{city}',
                                    state='{state}', zipcode='{zipcode}', profile_update_dt='{date_modified}' where user_id='{user_id}'"""
            cursor.execute(sql_update_query)
            con.commit()
            cursor.close()
        return redirect(url_for('user_panel'))
    else:
        return redirect(url_for('home'))


@app.route("/admin-login", methods=["GET", "POST"])
def admin_login():
    if not g.loggedin:
        cursor = con.cursor(cursor_factory=psycopg2.extras.DictCursor)

        # Check if "username" and "password" POST requests exist (user submitted form)
        if request.method == 'POST' and 'email' in request.form and 'password' in request.form:
            session.pop('loggedin', None)
            email = request.form['email']
            password = request.form['password']

            # Check if account exists using MySQL
            cursor.execute(f"SELECT * FROM admin_login where email = '{email}'")
            # Fetch one record and return result
            account = cursor.fetchone()

            if account:
                password_rs = account['password']
                # If account exists in users table in out database
                if password == password_rs:
                    # Create session data, we can access this data in other routes
                    session['loggedin'] = True
                    # Redirect to home page
                    return redirect(url_for('admin_panel'))
                else:
                    error = "Incorrect username/password"
                    return render_template('Admin_login.html', error=error)

            else:
                error = "Incorrect username/password"
                return render_template("Admin_login.html", error=error)

        cursor.close()
        return render_template("Admin_login.html")
    else:
        return redirect(url_for('admin_panel'))


@app.route('/admin-dashboard', methods=["GET", "POST"])
def admin_panel():
    if g.loggedin:
        cursor = con.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute(
            "SELECT * FROM user_profile,user_login where user_login.id = user_profile.user_id order by user_login.id desc")
        account = cursor.fetchall()
        return render_template("admin_dashboard.html", account=account)
    else:
        return render_template("Admin_login.html")


@app.route('/add-user-form')
def add_user_form():
    if g.loggedin:
        return render_template("adduser.html")
    else:
        return redirect(url_for('admin_login'))


@app.route('/add-user', methods=["GET", "POST"])
def add_user():
    if g.loggedin:
        cursor = con.cursor(cursor_factory=psycopg2.extras.DictCursor)
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        conf_pwd = request.form.get("conf_pwd")
        # hash_password = crypt.hashpw(password, scrypt.gensalt())
        cursor.execute(f"select * from user_login where email='{email}'")
        user_exist = cursor.fetchone()
        cursor.close()
        if user_exist:
            message = "Account with this email aready exist, please try another email..!!"
            return render_template("adduser.html", error=message)
        elif request.method == 'POST':
            if password == conf_pwd:
                new_user()
                message = "User created successfully..!!"
                # fromaddr = 'poojavadher24@gmail.com'
                # toaddr = email

                # msg = MIMEMultipart()
                # msg['From'] = fromaddr
                # msg['To'] = toaddr
                # msg['Subject'] = "Verification Email"

                # html = """\n\n
                #                             <!doctype html>
                #                             <body>
                #                                     Dear """ + username + """,
                #                                     <div class="main_content">
                #                                     <p>Please verify your account with :<br>
                #                                             Username	-   """ + username + """<br>
                #                                             Email	-   """ + email + """<br>
                #                                             Password	-   """ + password + """<br>
                #                                     </p>
                #                                     <a href="http://127.0.0.1:5000/user-login">Click Here</a> to login to your account.
                #                                     </div>
                #                             </body>
                #                             </html>
                #                     """
                # part2 = MIMEText(html, 'html')
                # msg.attach(part2)

                # server = smtplib.SMTP('smtp.gmail.com', 587)
                # server.starttls()
                # server.login(os.environ["EMAIL"], os.environ["PASS"])
                # text = msg.as_string()
                # server.sendmail(fromaddr, toaddr, text)
                # server.quit()
                return render_template("adduser.html", success=message)
            else:
                message = "Password and confirm password doesn't match..!! "
                return render_template("adduser.html", denied=message)
    else:
        return redirect(url_for('admin_login'))
    return redirect(url_for('add_user_form'))


def new_user():
    cursor = con.cursor(cursor_factory=psycopg2.extras.DictCursor)
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    hash_pwd = generate_password_hash(password)
    cursor.execute(f"""INSERT INTO user_login (user_name,email,password)
                            VALUES('{username}','{email}','{hash_pwd}')
                        """)
    con.commit()
    cursor.execute("SELECT max(id) FROM user_login")
    new_id = cursor.fetchone()
    date_modified = datetime.date.today()
    cursor.execute(f"""INSERT INTO user_profile (user_id)
                            VALUES('{new_id[0]}')
                        """)
    con.commit()
    cursor.close()
    return redirect(url_for('admin_panel'))


@app.route("/update-user-profile/<int:user_id>")
def fetch_update_user(user_id):
    if g.loggedin:
        cursor = con.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute(
            f"SELECT * FROM user_login,user_profile where user_login.id = '{user_id}' and user_profile.user_id = '{user_id}'")
        account = cursor.fetchone()
        cursor.close()
        return render_template("update.html", account=account)
    else:
        return redirect(url_for('admin_login'))


@app.route("/update", methods=["GET", "POST"])
def update():
    if g.loggedin:
        if request.method == "POST":
            user_id = request.form.get("id")
            fname = request.form.get("fname")
            lname = request.form.get("lname")
            dob = request.form.get("dob")
            mobile = request.form.get("mobile")
            gender = request.form.get("gender")
            address = request.form.get("address")
            city = request.form.get("city")
            state = request.form.get("state")
            zipcode = request.form.get("zipcode")
            date_modified = datetime.date.today()
            cursor = con.cursor(cursor_factory=psycopg2.extras.DictCursor)
            sql_update_query = f"""Update user_profile set first_name='{fname}', last_name='{lname}', dob='{dob}',
                                    mobile_number='{mobile}', gender='{gender}', address='{address}', city='{city}',
                                    state='{state}', zipcode='{zipcode}', profile_update_dt='{date_modified}' where user_id='{user_id}'"""
            cursor.execute(sql_update_query)
            con.commit()
            cursor.close()
        return redirect(url_for('admin_panel'))
    else:
        return redirect(url_for('admin_login'))


@app.route("/delete/<int:user_id>")
def delete(user_id):
    cursor = con.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cursor.execute(f"DELETE FROM user_profile where user_id ='{user_id}'")
    cursor.execute(f"DELETE FROM user_login where id ='{user_id}'")
    con.commit()
    cursor.close()
    return redirect(url_for('admin_panel'))


@app.route("/logout-admin")
def logout_admin():
    session.pop('loggedin', None)
    return render_template("Admin_login.html")


@app.route("/logout")
def logout():
    session.pop('userloggedin', None)
    session.pop('username', None)
    session.pop('uid', None)
    return render_template("User_login.html")


if __name__ == "__main__":
    app.run(debug=True)
