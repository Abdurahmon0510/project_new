import bcrypt
from db import hash_password_bcrypt

def match_password_bcrypt(raw_password, hashed_password, salt):
    hashed_password_stored = bcrypt.hashpw(raw_password.encode(), salt.encode())
    return hashed_password_stored == hashed_password.encode()

def register_user_bcrypt(username, password, role, status, login_try_count, cursor, conn):
    hashed_password, salt = hash_password_bcrypt(password)
    insert_user_query = """
        INSERT INTO users(username, password, "role", status, login_try_count)
        VALUES (%s, %s, %s, %s, %s);
    """
    user_data = (username, hashed_password, role, status, login_try_count)
    cursor.execute(insert_user_query, user_data)
    conn.commit()
