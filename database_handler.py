import sqlite3

conn = sqlite3.connect('mypass.db')
c = conn.cursor()

def create_user(username, password, food_question, pet_question, city_question):
    c.execute('''
        INSERT INTO User (username, password, food_question, pet_question, city_question)
        VALUES (?, ?, ?, ?, ?)
    ''', (username, password, food_question, pet_question, city_question))
    conn.commit()

def check_user_credentials(username, password):
    c.execute('''
        SELECT id FROM User WHERE username = ? AND password = ?
    ''', (username, password))
    return c.fetchone()

def get_vault_data(user_id):
    c.execute('''
        SELECT * FROM Vault WHERE user_id = ?
    ''', (user_id,))
    return c.fetchall()

# Add a new vault entry
def add_vault_entry(user_id, passport_number=None, credit_card=None, license_number=None, ssn_number=None, identity=None, secure_notes=None):
    c.execute('''
        INSERT INTO Vault (user_id, passport_number, credit_card, license_number, ssn_number, identity, secure_notes)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (user_id, passport_number, credit_card, license_number, ssn_number, identity, secure_notes))
    conn.commit()

# Update an existing vault entry
def update_vault_entry(entry_id, user_id = None, passport_number=None, credit_card=None, license_number=None, ssn_number=None, identity=None, secure_notes=None):
    c.execute('''
        UPDATE Vault
        SET user_id = ?, passport_number = ?, credit_card = ?, license_number = ?, ssn_number = ?, identity = ?, secure_notes = ?
        WHERE entry_id = ?
    ''', (user_id, passport_number, credit_card, license_number, ssn_number, identity, secure_notes, entry_id))
    conn.commit()

# Delete an existing vault entry
def delete_vault_entry(entry_id):
    c.execute('''
        DELETE FROM Vault
        WHERE entry_id = ?
    ''', (entry_id,))
    conn.commit()

def close_connection():
    conn.close()

