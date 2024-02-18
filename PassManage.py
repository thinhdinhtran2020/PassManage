import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3
from database_handler import create_user, check_user_credentials, delete_vault_entry, get_vault_data, add_vault_entry, update_vault_entry, delete_vault_entry, close_connection, c
import random
import string
from datetime import datetime, timedelta

# Singleton pattern for user session management
class UserSession:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(UserSession, cls).__new__(cls)
            cls._instance.username = None
            cls._instance.master_password = None
            cls._instance.logged_in = False
            cls._instance.user_id = 1
        return cls._instance

# Mediator pattern for UI components communication
class UIMediator:
    def __init__(self, root):
        self.observers = []
        self.root = root

    def add_observer(self, observer):
        self.observers.append(observer)

    def notify_observers(self, password):
        for observer in self.observers:
            observer.update(password)

    def display_message(self, message):
        messagebox.showinfo("Message", message)
        
# Observer pattern for password strength notifications
class PasswordStrengthObserver:
    def __init__(self, ui_mediator):
        self.ui_mediator = ui_mediator

    def update(self, password):
        # Check password strength and notify user
        strength_message = self.check_password_strength(password)
        self.ui_mediator.display_message(strength_message)

    def check_password_strength(self, password):
        # Password logic
        length_ok = len(password) >= 8
        uppercase_ok = any(char.isupper() for char in password)
        lowercase_ok = any(char.islower() for char in password)
        digit_ok = any(char.isdigit() for char in password)
        special_char_ok = any(char in string.punctuation for char in password)

        if length_ok and uppercase_ok and lowercase_ok and digit_ok and special_char_ok:
            return 'Password is strong'
        else:
            return 'Password is weak. Please include at least 8 characters, one uppercase letter, one lowercase letter, one digit, and one special character.'

# Builder pattern for password generation
class PasswordBuilder:
    def __init__(self):
        self.password = None

    def set_length(self, length):
        # Set the length of the password
        self.password_length = length
        return self

    def include_uppercase(self):
        # Include uppercase letters in the password
        self.include_upper = True
        return self

    def include_lowercase(self):
        # Include lowercase letters in the password
        self.include_lower = True
        return self

    def include_digits(self):
        # Include digits in the password
        self.include_digits = True
        return self

    def include_special_characters(self):
        # Include special characters in the password
        self.include_special = True
        return self

    def generate_password(self):
        # Generate the password based on the specified criteria
        if not hasattr(self, 'password_length'):
            raise ValueError("Password length not set")

        characters = ""
        if getattr(self, 'include_upper', False):
            characters += string.ascii_uppercase
        if getattr(self, 'include_lower', False):
            characters += string.ascii_lowercase
        if getattr(self, 'include_digits', False):
            characters += string.digits
        if getattr(self, 'include_special', False):
            characters += string.punctuation

        if not characters:
            raise ValueError("No character set specified")

        self.password = ''.join(random.choice(characters) for _ in range(self.password_length))
        
        return self.password
    
# Proxy pattern for data masking and unmasking
class DataProxy:
    def __init__(self, real_subject):
        self._real_subject = real_subject
        self._masked_data = None

    def mask_data(self, data):
        self._masked_data = "*" * len(data)
        return self._masked_data

    def unmask_data(self):
        return self._real_subject

# Chain of Responsibility pattern for master password recovery
class SecurityQuestionHandler:
    def __init__(self, user_id=None, successor=None):
        self.user_id = user_id
        self.successor = successor

    def handle_request(self, security_question, answer):
        if self.successor:
            self.successor.handle_request(security_question, answer)
             
# Concrete handlers for each security question
class SecurityQuestionHandlerFood(SecurityQuestionHandler):
    def handle_request(self, security_question, answer):
        if security_question == "Food":
            # Query the database to get the correct answer for the food security question
            c.execute('''
                SELECT food_question FROM User WHERE id = ?
            ''', (self.user_id,))
            correct_answer = c.fetchone()[0]

            # Check if the provided answer matches the correct answer
            if answer.lower() == correct_answer.lower():
                print("Food security question answered correctly.")
            elif self.successor:
                # If the answer is incorrect and there's a successor, propagate the request to the successor
                self.successor.handle_request(security_question, answer)
            else:
                print("No handler available for the security question")
        elif self.successor:
            # If the security question doesn't match and there's a successor, propagate the request to the successor
            self.successor.handle_request(security_question, answer)
        else:
            print("No handler available for the security question")

class SecurityQuestionHandlerPet(SecurityQuestionHandler):
    def handle_request(self, security_question, answer):
        if security_question == "Pet":
            # Query the database to get the correct answer for the pet security question
            c.execute('''
                SELECT pet_question FROM User WHERE id = ?
            ''', (self.user_id,))
            correct_answer = c.fetchone()[0]

            # Check if the provided answer matches the correct answer
            if answer.lower() == correct_answer.lower():
                print("Pet security question answered correctly.")
            elif self.successor:
                # If the answer is incorrect and there's a successor, propagate the request to the successor
                self.successor.handle_request(security_question, answer)
            else:
                print("No handler available for the security question")
        elif self.successor:
            # If the security question doesn't match and there's a successor, propagate the request to the successor
            self.successor.handle_request(security_question, answer)
        else:
            print("No handler available for the security question")

class SecurityQuestionHandlerCity(SecurityQuestionHandler):
    def handle_request(self, security_question, answer):
        if security_question == "City":
            # Query the database to get the correct answer for the city security question
            c.execute('''
                SELECT city_question FROM User WHERE id = ?
            ''', (self.user_id,))
            correct_answer = c.fetchone()[0]

            # Check if the provided answer matches the correct answer
            if answer.lower() == correct_answer.lower():
                print("City security question answered correctly.")
            elif self.successor:
                # If the answer is incorrect and there's a successor, propagate the request to the successor
                self.successor.handle_request(security_question, answer)
            else:
                print("No handler available for the security question")
        elif self.successor:
            # If the security question doesn't match and there's a successor, propagate the request to the successor
            self.successor.handle_request(security_question, answer)
        else:
            print("No handler available for the security question")

# UI implementation using Tkinter
class MyPassUI(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("MyPass Password Manager")

        self.session = UserSession()
        self.user_id = 1
        self.mediator = UIMediator(self)
        self.generator = PasswordBuilder
        
        # Add components to the mediator
        password_observer = PasswordStrengthObserver(self.mediator)
        self.mediator.add_observer(password_observer)


        # Create a notebook (tabs)
        self.notebook = ttk.Notebook(self)
        self.notebook.grid(row=0, column=0, sticky="nsew")

        # Create tabs
        self.login_tab = UserLoginTab(self.notebook, self)
        self.registration_tab = UserRegistrationTab(self.notebook, self)
        self.vault_tab = VaultTab(self.notebook, self)
        self.recovery_tab = PasswordRecoveryTab(self.notebook, self)


        # Add tabs to the notebook
        self.notebook.add(self.login_tab, text="Login")
        self.notebook.add(self.registration_tab, text="Register")
        self.notebook.add(self.vault_tab, text="Vault")
        self.notebook.add(self.recovery_tab, text="Password Recovery")
   
class UserLoginTab(tk.Frame):
    def __init__(self, parent, main_app):
        super().__init__(parent)

        self.main_app = main_app

        # Create a text box for username input
        tk.Label(self, text="Username:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.username_entry = tk.Entry(self)
        self.username_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")

        # Create a text box for master password input
        tk.Label(self, text="Master Password:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.master_password_entry = tk.Entry(self, show="*")
        self.master_password_entry.grid(row=1, column=1, padx=5, pady=5, sticky="w")

        # Create a button for user login
        login_button = tk.Button(self, text="Login", command=self.authenticate_user)
        login_button.grid(row=2, column=0, columnspan=2, pady=10)
        
        # Create a button to open the password recovery window
        tk.Button(self, text="Forgot Password?", command=self.switch_to_recovery_tab).grid(row=3, column=0, columnspan=2, pady=10)
        
    def authenticate_user(self):
        username = self.username_entry.get()
        master_password = self.master_password_entry.get()

        if username and master_password:
            user_id = check_user_credentials(username, master_password)
            if user_id:
                self.main_app.user_id = user_id[0]
                self.main_app.session.user_id = user_id[0]
                self.main_app.logged_in = True
                messagebox.showinfo("Success", "Login successful!")
            else:
                messagebox.showerror("Error", "Invalid username or password")
        else:
            messagebox.showerror("Error", "Please fill in all fields.")
            
        if user_id:
            self.main_app.user_id = user_id[0]
            self.main_app.session.user_id = user_id[0]
            self.main_app.logged_in = True

            # Switch to the vault tab
            self.main_app.notebook.select(self.main_app.vault_tab)
            
            
    def switch_to_recovery_tab(self):
        # Switch to the "Password Recovery" tab
        self.main_app.notebook.select(self.main_app.recovery_tab)
            
class VaultTab(tk.Frame):
    def __init__(self, parent, main_app):
        super().__init__(parent)

        self.main_app = main_app

        # Create a notebook for vault actions
        self.vault_actions_notebook = ttk.Notebook(self)
        self.vault_actions_notebook.grid(row=0, column=0, sticky="nsew")

        # Create tabs for vault actions
        self.add_tab = AddEntryTab(self.vault_actions_notebook, self)
        self.modify_tab = ModifyEntryTab(self.vault_actions_notebook, self)
        self.delete_tab = DeleteEntryTab(self.vault_actions_notebook, self)
        self.display_tab = DisplayTab(self.vault_actions_notebook, self)  

        # Add tabs to the notebook
        self.vault_actions_notebook.add(self.add_tab, text="Add Entry")
        self.vault_actions_notebook.add(self.modify_tab, text="Modify Entry")
        self.vault_actions_notebook.add(self.delete_tab, text="Delete Entry")
        self.vault_actions_notebook.add(self.display_tab, text="Display")
        
class AddEntryTab(tk.Frame):
    def __init__(self, parent, vault_tab):
        super().__init__(parent)

        self.vault_tab = vault_tab

        tk.Label(self, text="Passport Number:").grid(row=4, column=0, padx=5, pady=5, sticky="e")
        self.passport_number_entry = tk.Entry(self)
        self.passport_number_entry.grid(row=4, column=1, padx=5, pady=5, sticky="w")

        tk.Label(self, text="Credit Card:").grid(row=5, column=0, padx=5, pady=5, sticky="e")
        self.credit_card_entry = tk.Entry(self)
        self.credit_card_entry.grid(row=5, column=1, padx=5, pady=5, sticky="w")

        tk.Label(self, text="License Number:").grid(row=6, column=0, padx=5, pady=5, sticky="e")
        self.license_number_entry = tk.Entry(self)
        self.license_number_entry.grid(row=6, column=1, padx=5, pady=5, sticky="w")

        tk.Label(self, text="SSN Number:").grid(row=7, column=0, padx=5, pady=5, sticky="e")
        self.ssn_number_entry = tk.Entry(self)
        self.ssn_number_entry.grid(row=7, column=1, padx=5, pady=5, sticky="w")

        tk.Label(self, text="Identity:").grid(row=8, column=0, padx=5, pady=5, sticky="e")
        self.identity_entry = tk.Entry(self)
        self.identity_entry.grid(row=8, column=1, padx=5, pady=5, sticky="w")

        tk.Label(self, text="Secure Notes:").grid(row=9, column=0, padx=5, pady=5, sticky="e")
        self.secure_notes_entry = tk.Entry(self)
        self.secure_notes_entry.grid(row=9, column=1, padx=5, pady=5, sticky="w")

        # Create a button to add the entry
        add_button = tk.Button(self, text="Add Entry", command=self.add_entry)
        add_button.grid(row=10, column=0, columnspan=2, pady=10)

    def add_entry(self):

        passport_number = self.passport_number_entry.get()
        credit_card = self.credit_card_entry.get()
        license_number = self.license_number_entry.get()
        ssn_number = self.ssn_number_entry.get()
        identity = self.identity_entry.get()
        secure_notes = self.secure_notes_entry.get()

        # Add the new entry to the database
        add_vault_entry(
            self.vault_tab.main_app.user_id,
            passport_number,
            credit_card,
            license_number,
            ssn_number,
            identity,
            secure_notes
        )

class ModifyEntryTab(tk.Frame):
    def __init__(self, parent, vault_tab):
        super().__init__(parent)

        self.vault_tab = vault_tab

        # Create entry fields for modifying an entry
        tk.Label(self, text="Entry ID to Modify:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.entry_id_entry = tk.Entry(self)
        self.entry_id_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")

        tk.Label(self, text="New User ID:").grid(row=4, column=0, padx=5, pady=5, sticky="e")
        self.new_user_id_entry = tk.Entry(self)
        self.new_user_id_entry.grid(row=4, column=1, padx=5, pady=5, sticky="w")

        tk.Label(self, text="New Passport Number:").grid(row=5, column=0, padx=5, pady=5, sticky="e")
        self.new_passport_number_entry = tk.Entry(self)
        self.new_passport_number_entry.grid(row=5, column=1, padx=5, pady=5, sticky="w")

        tk.Label(self, text="New Credit Card:").grid(row=6, column=0, padx=5, pady=5, sticky="e")
        self.new_credit_card_entry = tk.Entry(self)
        self.new_credit_card_entry.grid(row=6, column=1, padx=5, pady=5, sticky="w")

        tk.Label(self, text="New License Number:").grid(row=7, column=0, padx=5, pady=5, sticky="e")
        self.new_license_number_entry = tk.Entry(self)
        self.new_license_number_entry.grid(row=7, column=1, padx=5, pady=5, sticky="w")

        tk.Label(self, text="New SSN Number:").grid(row=8, column=0, padx=5, pady=5, sticky="e")
        self.new_ssn_number_entry = tk.Entry(self)
        self.new_ssn_number_entry.grid(row=8, column=1, padx=5, pady=5, sticky="w")

        tk.Label(self, text="New Identity:").grid(row=9, column=0, padx=5, pady=5, sticky="e")
        self.new_identity_entry = tk.Entry(self)
        self.new_identity_entry.grid(row=9, column=1, padx=5, pady=5, sticky="w")

        tk.Label(self, text="New Secure Notes:").grid(row=10, column=0, padx=5, pady=5, sticky="e")
        self.new_secure_notes_entry = tk.Entry(self)
        self.new_secure_notes_entry.grid(row=10, column=1, padx=5, pady=5, sticky="w")

        # Create a button to modify the entry
        modify_button = tk.Button(self, text="Modify Entry", command=self.modify_entry)
        modify_button.grid(row=11, column=0, columnspan=2, pady=10)

    def modify_entry(self):
        # Get user input from entry fields
        entry_id = self.entry_id_entry.get()
        new_user_id = self.new_user_id_entry.get()
        new_passport_number = self.new_passport_number_entry.get()
        new_credit_card = self.new_credit_card_entry.get()
        new_license_number = self.new_license_number_entry.get()
        new_ssn_number = self.new_ssn_number_entry.get()
        new_identity = self.new_identity_entry.get()
        new_secure_notes = self.new_secure_notes_entry.get()

        # Update the entry in the database
        update_vault_entry(
            entry_id,
            new_user_id,
            new_passport_number,
            new_credit_card,
            new_license_number,
            new_ssn_number,
            new_identity,
            new_secure_notes
        )
   
class DeleteEntryTab(tk.Frame):
    def __init__(self, parent, vault_tab):
        super().__init__(parent)

        self.vault_tab = vault_tab

        # Create entry fields for deleting an entry
        tk.Label(self, text="Entry ID to Delete:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.delete_entry_id_entry = tk.Entry(self)
        self.delete_entry_id_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")

        # Create a button to delete the entry
        delete_button = tk.Button(self, text="Delete Entry", command=self.delete_entry)
        delete_button.grid(row=1, column=0, columnspan=2, pady=10)

    def delete_entry(self):
        # Get user input from entry field
        entry_id_to_delete = self.delete_entry_id_entry.get()

        # Delete the entry from the database
        delete_vault_entry(entry_id_to_delete)
        
class DisplayTab(tk.Frame):
    def __init__(self, parent, vault_tab):
        super().__init__(parent)

        self.vault_tab = vault_tab

        # Create a text widget for displaying vault data
        self.vault_display = tk.Text(self, wrap="word", height=10, width=40)
        self.vault_display.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

        # Create a button to refresh and show vault data
        refresh_button = tk.Button(self, text="Refresh Vault", command=self.refresh_vault)
        refresh_button.grid(row=1, column=0, pady=10)

        # Create a button to unmask data
        unmask_button = tk.Button(self, text="Unmask", command=self.unmask_data)
        unmask_button.grid(row=2, column=0, pady=10)

    def refresh_vault(self):
        # Retrieve and display vault data
        vault_data = get_vault_data(self.vault_tab.main_app.user_id)

        # Create a DataProxy for masking and unmasking sensitive information
        data_proxy = DataProxy(vault_data)

        # Mask sensitive information before displaying
        masked_data = data_proxy.mask_data(vault_data)

        # Display masked data
        self.vault_display.delete(1.0, tk.END)
        self.vault_display.insert(tk.END, masked_data)
        
        # Schedule the refresh function to be called again after 15 seconds
        self.schedule_refresh()

    def unmask_data(self):
        # Retrieve and display vault data
        vault_data = get_vault_data(self.vault_tab.main_app.user_id)

        # Create a DataProxy for masking and unmasking sensitive information
        data_proxy = DataProxy(vault_data)

        # Unmask data and display it
        self.vault_display.delete(1.0, tk.END)
        self.vault_display.insert(tk.END, data_proxy.unmask_data())
        
    def schedule_refresh(self):
        # Schedule the refresh function to be called after 15 seconds
        self.after(15000, self.refresh_vault)
        
class PasswordRecoveryTab(tk.Frame):
    def __init__(self, parent, main_app):
        super().__init__(parent)

        self.main_app = main_app

        tk.Label(self, text="Username:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.username_entry = tk.Entry(self)
        self.username_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")

        tk.Label(self, text="Security Question 1:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.security_question1_entry = tk.Entry(self)
        self.security_question1_entry.grid(row=1, column=1, padx=5, pady=5, sticky="w")

        tk.Label(self, text="Security Question 2:").grid(row=2, column=0, padx=5, pady=5, sticky="e")
        self.security_question2_entry = tk.Entry(self)
        self.security_question2_entry.grid(row=2, column=1, padx=5, pady=5, sticky="w")

        tk.Label(self, text="Security Question 3:").grid(row=3, column=0, padx=5, pady=5, sticky="e")
        self.security_question3_entry = tk.Entry(self)
        self.security_question3_entry.grid(row=3, column=1, padx=5, pady=5, sticky="w")

        tk.Button(self, text="Initiate Recovery", command=self.initiate_recovery).grid(row=4, column=0, columnspan=2, pady=10)

    # Creating the chain of responsibility
    def initiate_recovery(self):
        username = self.username_entry.get()
        food_answer = self.security_question1_entry.get()
        pet_answer = self.security_question2_entry.get()
        city_answer = self.security_question3_entry.get()

        c.execute('''
            SELECT * FROM User WHERE username = ?
        ''', (username,))
        user_data = c.fetchone()

        if user_data:
            user_id = user_data[0]

            if (
                food_answer.lower() == user_data[3].lower() and
                pet_answer.lower() == user_data[4].lower() and
                city_answer.lower() == user_data[5].lower()
            ):
                messagebox.showinfo('Recovered Password', 'Your password is: ' + user_data[2])
            else:
                messagebox.showinfo('Failed Recovery', 'Failed to recover the password.')
        else:
            messagebox.showinfo('User Not Found', 'No user found with the provided username.')

class UserRegistrationTab(tk.Frame):
    def __init__(self, parent, main_app):
        super().__init__(parent)
        self.main_app = main_app
        self.mediator = UIMediator(self)

        # Create a text box for username input
        tk.Label(self, text="Username:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.username_entry = tk.Entry(self)
        self.username_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")

        # Create a text box for password input
        tk.Label(self, text="Password:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.master_password_entry = tk.Entry(self, show="*")
        self.master_password_entry.grid(row=1, column=1, padx=5, pady=5, sticky="w")

        # Create text boxes for security questions
        tk.Label(self, text="Security Question 1:").grid(row=2, column=0, padx=5, pady=5, sticky="e")
        self.security_question1_entry = tk.Entry(self)
        self.security_question1_entry.grid(row=2, column=1, padx=5, pady=5, sticky="w")

        tk.Label(self, text="Security Question 2:").grid(row=3, column=0, padx=5, pady=5, sticky="e")
        self.security_question2_entry = tk.Entry(self)
        self.security_question2_entry.grid(row=3, column=1, padx=5, pady=5, sticky="w")

        tk.Label(self, text="Security Question 3:").grid(row=4, column=0, padx=5, pady=5, sticky="e")
        self.security_question3_entry = tk.Entry(self)
        self.security_question3_entry.grid(row=4, column=1, padx=5, pady=5, sticky="w")

        # Create a button for user registration
        register_button = tk.Button(self, text="Register", command=self.register_user)
        register_button.grid(row=5, column=0, columnspan=2, pady=10)

        # Create a button to suggest a generated password
        suggest_password_button = tk.Button(self, text="Suggest Password", command=self.suggest_password)
        suggest_password_button.grid(row=6, column=0, columnspan=2, pady=10)
        
        # Create a button to check password
        check_password_button = tk.Button(self, text="Check Password", command=self.check_password)
        check_password_button.grid(row=7, column=0, columnspan=2, pady=10)
        
        # Add password strength observer
        password_observer = PasswordStrengthObserver(self.mediator)
        self.mediator.add_observer(password_observer)
        
    def register_user(self):
        username = self.username_entry.get()
        master_password = self.master_password_entry.get()
        security_question1 = self.security_question1_entry.get()
        security_question2 = self.security_question2_entry.get()
        security_question3 = self.security_question3_entry.get()

        if username and master_password and security_question1 and security_question2 and security_question3:
            create_user(username, master_password, security_question1, security_question2, security_question3)
            messagebox.showinfo("Success", "User registered successfully!")
        else:
            messagebox.showerror("Error", "Please fill in all fields.")

        
    def check_password(self):
        # Notify observers to check password strength
        password = self.master_password_entry.get()
        self.mediator.notify_observers(password)
        
    def suggest_password(self):
        # Use the PasswordBuilder to generate a suggested password
        suggested_password = self.main_app.generator().set_length(12).include_uppercase().include_lowercase().include_digits().include_special_characters().generate_password()

        # Display the suggested password in the password entry field
        self.master_password_entry.delete(0, tk.END)
        self.master_password_entry.insert(0, suggested_password)
        messagebox.showinfo("Message", suggested_password)

if __name__ == "__main__":
    user_id = 1
    app = MyPassUI()
    app.mainloop()
