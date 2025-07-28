import streamlit as st
import sqlite3
import pandas as pd
import requests
import re
import bcrypt
from streamlit_lottie import st_lottie

# -------------------- CONFIG --------------------
DB_PATH = "clinicdb_v3.sqlite"

# -------------------- UTILS --------------------
def get_db():
    """Open a connection to the SQLite database."""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    return conn

def loti(url: str):
    r = requests.get(url)
    return r.json() if r.status_code == 200 else None

# -------------------- DB SETUP --------------------
def init_db():
    db = get_db()
    cur = db.cursor()

    # users table
    cur.execute("""
      CREATE TABLE IF NOT EXISTS users (
        username      TEXT    PRIMARY KEY,
        password_hash BLOB    NOT NULL,
        role          TEXT    NOT NULL DEFAULT 'user'
      )
    """)

    # patients table
    cur.execute("""
      CREATE TABLE IF NOT EXISTS patients (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        name          TEXT    NOT NULL,
        age           INTEGER,
        contact       TEXT    UNIQUE,
        address       TEXT,
        date_added    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        email         TEXT,
        doctor_name   TEXT,
        disease       TEXT,
        fee           INTEGER,
        cnic          TEXT
      )
    """)

    # appointments table
    cur.execute("""
      CREATE TABLE IF NOT EXISTS appointments (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        patient_id       INTEGER,
        appointment_date DATE,
        appointment_time TIME,
        doctor_name      TEXT,
        notes            TEXT,
        FOREIGN KEY (patient_id) REFERENCES patients(id) ON DELETE CASCADE
      )
    """)

    db.commit()

    # seed an admin user if none exists
    cur.execute("SELECT 1 FROM users WHERE username='admin'")
    if cur.fetchone() is None:
        pw = b"admin123"
        h  = bcrypt.hashpw(pw, bcrypt.gensalt())
        cur.execute(
            "INSERT INTO users(username,password_hash,role) VALUES (?,?,?)",
            ("admin", h, "admin")
        )
        db.commit()

    cur.close()
    return db

# -------------------- AUTH --------------------
def login_form():
    st.sidebar.subheader("🔐 Login")
    with st.sidebar.form("login_form", clear_on_submit=False):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Log in")
    if submitted:
        db  = get_db()
        cur = db.cursor()
        cur.execute(
            "SELECT password_hash, role FROM users WHERE username=?",
            (username,)
        )
        row = cur.fetchone()
        cur.close()
        if row and bcrypt.checkpw(password.encode(), row[0]):
            st.session_state.authenticated = True
            st.session_state.user = username
            st.session_state.role = row[1]
        else:
            st.sidebar.error("❌ Invalid credentials")

# -------------------- VALIDATION --------------------
def valid_contact(c): return re.fullmatch(r"\d{10}", c)
def valid_cnic(x):    return re.fullmatch(r"\d{13}", x)
def valid_email(e):   return re.fullmatch(r"[^@]+@[^@]+\.[^@]+", e)

# -------------------- PATIENT CRUD --------------------
def insert_patient_record(db, name, age, contact, email, address, disease, fee, cnic):
    cur = db.cursor()
    cur.execute("""
      INSERT INTO patients
        (name, age, contact, email, address, disease, fee, cnic, doctor_name)
      VALUES (?,?,?,?,?,?,?,?,?)
    """, (name, age, contact, email, address, disease, fee, cnic, st.session_state.user))
    db.commit()
    cur.close()

def fetch_all_patients(db):
    cur = db.cursor()
    if st.session_state.role == "doctor":
        cur.execute(
            "SELECT * FROM patients WHERE doctor_name=?",
            (st.session_state.user,)
        )
    else:
        cur.execute("SELECT * FROM patients")
    rows = cur.fetchall()
    cur.close()
    return rows

def update_patient_record(db):
    option = st.selectbox("Search by", ["ID", "Contact", "CNIC"])
    value  = st.text_input("Enter value")
    if st.button("Search Patient"):
        fmap = {"ID":"id","Contact":"contact","CNIC":"cnic"}
        cur = db.cursor()
        cur.execute(
            f"SELECT * FROM patients WHERE {fmap[option]} = ?",
            (value,)
        )
        patient = cur.fetchone()
        cur.close()
        if patient:
            df = pd.DataFrame([patient], columns=[
                'ID','Name','Age','Contact','Address',
                'Date Added','Email','Doctor Name','Disease','Fee','CNIC'
            ])
            st.dataframe(df)
            st.session_state.edit_patient = patient
        else:
            st.warning("Not found")
    if 'edit_patient' in st.session_state:
        edit_patient(db)

def edit_patient(db):
    p = st.session_state.edit_patient
    new_name    = st.text_input("New Name",     p[1])
    new_age     = st.number_input("New Age",      p[2])
    new_contact = st.text_input("New Contact",  p[3])
    new_email   = st.text_input("New Email",    p[6])
    new_address = st.text_input("New Address",  p[4])
    if st.button("Update"):
        cur = db.cursor()
        cur.execute("""
          UPDATE patients SET
            name=?, age=?, contact=?, email=?, address=?
          WHERE id=?
        """, (new_name,new_age,new_contact,new_email,new_address,p[0]))
        db.commit()
        st.success("Updated")
        del st.session_state.edit_patient
        cur.close()

def delete_patient_record(db, field, value):
    fmap = {"ID":"id","Name":"name","Contact":"contact"}
    cur = db.cursor()
    cur.execute(
        f"DELETE FROM patients WHERE {fmap[field]} = ?",
        (value,)
    )
    db.commit()
    cur.close()

# -------------------- APPOINTMENTS --------------------
def insert_appointment_record(db, pid, date, time, doc, notes):
    cur = db.cursor()
    cur.execute("""
      INSERT INTO appointments
        (patient_id,appointment_date,appointment_time,doctor_name,notes)
      VALUES (?,?,?,?,?)
    """, (pid, date, time, doc, notes))
    db.commit()
    cur.close()

def fetch_all_appointments(db):
    cur = db.cursor()
    if st.session_state.role == "doctor":
        cur.execute("""
          SELECT id,patient_id,appointment_date,
            appointment_time,doctor_name,notes
          FROM appointments WHERE doctor_name=?
        """, (st.session_state.user,))
    else:
        cur.execute("""
          SELECT id,patient_id,appointment_date,
            appointment_time,doctor_name,notes
          FROM appointments
        """)
    rows = cur.fetchall()
    cur.close()
    return rows

def search_appointment(db):
    opt = st.selectbox("Search by", ["ID","Patient ID","Doctor Name"])
    val = st.text_input("Value")
    if st.button("Search"):
        fmap = {"ID":"id","Patient ID":"patient_id","Doctor Name":"doctor_name"}
        cur = db.cursor()
        cur.execute(f"""
          SELECT id,patient_id,appointment_date,
            appointment_time,doctor_name,notes
          FROM appointments WHERE {fmap[opt]} = ?
        """, (val,))
        row = cur.fetchone()
        cur.close()
        if row:
            st.dataframe(pd.DataFrame([row], columns=[
              'ID','Patient ID','Date','Time','Doctor','Notes'
            ]))
        else:
            st.warning("Not found")

# -------------------- MAIN --------------------
def main():
    st.set_page_config(page_title="Clinic PMS")

    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
        st.session_state.user = ""
        st.session_state.role = ""

    # ensure DB + tables exist
    init_db()

    if not st.session_state.authenticated:
        login_form()
        return

    st.sidebar.success(f"✔️ Logged in as {st.session_state.user} ({st.session_state.role})")
    if st.sidebar.button("🔓 Logout"):
        st.session_state.authenticated = False
        st.session_state.user = ""
        st.session_state.role = ""
        st.sidebar.info("✅ Logged out. Please refresh (F5) to return to login.")

    conn = get_db()
    l1   = loti("https://assets6.lottiefiles.com/packages/lf20_olluraqu.json")
    l2   = loti("https://assets6.lottiefiles.com/packages/lf20_vPnn3K.json")

    role = st.session_state.role
    menu = ["Home"]
    if role in ["admin", "receptionist"]:
        menu += [
            "Add Patient", "Show Patients", "Search/Edit Patient", "Delete Patient",
            "Add Appointment", "Show Appointments", "Search/Edit Appointment"
        ]
    else:
        menu += ["Show Patients", "Show Appointments"]
    if role == "admin":
        menu.append("Manage Users")

    choice = st.sidebar.radio("Select Option", menu)

    if choice == "Home":
        st.subheader("Welcome to the Hospital Management System")
        st_lottie(l1, height=300)

    elif choice == "Add Patient":
        st.subheader("Add Patient")
        st_lottie(l2, height=200)
        name    = st.text_input("Name")
        age     = st.number_input("Age", min_value=0)
        contact = st.text_input("Contact")
        cnic    = st.text_input("CNIC")
        email   = st.text_input("Email")
        address = st.text_input("Address")
        disease = st.text_input("Disease")
        fee     = st.number_input("Fee", min_value=0)
        if st.button("Add"):
            if not valid_contact(contact) or not valid_cnic(cnic) or not valid_email(email):
                st.warning("Enter valid contact/CNIC/email")
            else:
                insert_patient_record(conn, name, age, contact, email, address, disease, fee, cnic)
                st.success("Patient added")

    elif choice == "Show Patients":
        rows = fetch_all_patients(conn)
        if rows:
            df = pd.DataFrame(rows, columns=[
                'ID','Name','Age','Contact','Address',
                'Date Added','Email','Doctor Name','Disease','Fee','CNIC'
            ])
            st.dataframe(df)
        else:
            st.info("No patient records found.")

    elif choice == "Search/Edit Patient":
        update_patient_record(conn)

    elif choice == "Delete Patient":
        field = st.selectbox("Delete by", ["ID","Name","Contact"])
        val   = st.text_input("Value")
        if st.button("Delete"):
            delete_patient_record(conn, field, val)
            st.success("Deleted")

    elif choice == "Add Appointment":
        pid   = st.number_input("Patient ID", min_value=1)
        date  = st.date_input("Date")
        time  = st.time_input("Time")
        doc   = st.text_input("Doctor")
        notes = st.text_area("Notes")
        if st.button("Add Appointment"):
            insert_appointment_record(conn, pid, date, time, doc, notes)
            st.success("Added")

    elif choice == "Show Appointments":
        rows = fetch_all_appointments(conn)
        if rows:
            df = pd.DataFrame(rows, columns=[
                'ID','Patient ID','Date','Time','Doctor','Notes'
            ])
            st.dataframe(df)
        else:
            st.info("No appointments")

    elif choice == "Search/Edit Appointment":
        search_appointment(conn)

    elif choice == "Manage Users":
        st.subheader("Manage Users (Admin only)")
        new_u    = st.text_input("New Username")
        new_pw   = st.text_input("New Password", type="password")
        conf     = st.text_input("Confirm Pw",      type="password")
        new_role = st.selectbox("Select Role", ["admin", "doctor", "receptionist", "user"])
        if st.button("Create User"):
            if new_pw != conf:
                st.error("Passwords differ")
            else:
                cur = conn.cursor()
                cur.execute("SELECT 1 FROM users WHERE username=?", (new_u,))
                if cur.fetchone():
                    st.warning("User already exists")
                else:
                    h = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt())
                    cur.execute(
                      "INSERT INTO users(username,password_hash,role) VALUES (?,?,?)",
                      (new_u, h, new_role)
                    )
                    conn.commit()
                    st.success(f"User '{new_u}' with role '{new_role}' created ✅")
                cur.close()

    conn.close()

if __name__ == "__main__":
    main()
