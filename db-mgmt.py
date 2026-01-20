#!/usr/bin/env python3
import argparse
import os
import sys
import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv
from passlib.context import CryptContext

pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")

USERS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS users (
 id SERIAL PRIMARY KEY,
 email TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL,
 role TEXT NOT NULL DEFAULT 'viewer',
 created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
"""

DROP_USERS_TABLE_SQL = "DROP TABLE IF EXISTS users CASCADE;"

def load_env(env_file: str | None):
   if env_file:
       load_dotenv(dotenv_path=env_file)
   else:
       # fallback: try common names
       load_dotenv(dotenv_path=".env.local", override=False)

def get_db_conn():
   dbname = os.getenv("POSTGRES_DB")
   user = os.getenv("POSTGRES_USER")
   password = os.getenv("POSTGRES_PASSWORD")
   host = os.getenv("POSTGRES_HOST", "db")
   port = os.getenv("POSTGRES_PORT", "5432")

   missing = [k for k, v in {
       "POSTGRES_DB": dbname,
       "POSTGRES_USER": user,
       "POSTGRES_PASSWORD": password,
   }.items() if not v]
   if missing:
       raise SystemExit(f"Missing env vars: {', '.join(missing)}")

   return psycopg2.connect(
       dbname=dbname,
       user=user,
       password=password,
       host=host,
       port=port,
   )

def init_db(drop_users: bool = False):
   with get_db_conn() as conn:
       with conn.cursor() as cur:
           if drop_users:
               cur.execute(DROP_USERS_TABLE_SQL)
           cur.execute(USERS_TABLE_SQL)
       conn.commit()

def normalize_email(username: str) -> str:
   return username.strip().lower()

def add_user(username: str, password: str, role: str):
   role = role.strip().lower()
   if role not in ("admin", "viewer"):
       raise SystemExit("role must be 'admin' or 'viewer'")

   email = normalize_email(username)
   pw_hash = pwd.hash(password)

   with get_db_conn() as conn:
       with conn.cursor() as cur:
           cur.execute(
               """
               INSERT INTO users (email, password_hash, role)
               VALUES (%s, %s, %s)
               ON CONFLICT (email) DO NOTHING
               """,
               (email, pw_hash, role),
           )
       conn.commit()

def delete_user(username: str):
   email = normalize_email(username)
   with get_db_conn() as conn:
       with conn.cursor() as cur:
           cur.execute("DELETE FROM users WHERE email = %s", (email,))
           deleted = cur.rowcount
       conn.commit()
   return deleted

def set_role(username: str, role: str):
   role = role.strip().lower()
   if role not in ("admin", "viewer"):
       raise SystemExit("role must be 'admin' or 'viewer'")

   email = normalize_email(username)
   with get_db_conn() as conn:
       with conn.cursor() as cur:
           cur.execute("UPDATE users SET role = %s WHERE email = %s", (role, email))
           updated = cur.rowcount
       conn.commit()
   return updated

def set_password(username: str, password: str):
   email = normalize_email(username)
   pw_hash = pwd.hash(password)
   with get_db_conn() as conn:
       with conn.cursor() as cur:
           cur.execute(
               "UPDATE users SET password_hash = %s WHERE email = %s",
               (pw_hash, email),
           )
           updated = cur.rowcount
       conn.commit()
   return updated

def list_users():
   with get_db_conn() as conn:
       with conn.cursor(cursor_factory=RealDictCursor) as cur:
           cur.execute("SELECT id, email, role, created_at FROM users ORDER BY id ASC")
           return cur.fetchall()

def parse_args():
   p = argparse.ArgumentParser(
       prog="retro_hunter_db_admin.py",
       description="Retro Hunter DB setup + user admin (admin/viewer).",
   )
   p.add_argument("--env-file", help="Path to env file (e.g. .env or .env.local)")

   sub = p.add_subparsers(dest="cmd", required=True)

   s_init = sub.add_parser("init", help="Create required tables (users).")
   s_init.add_argument("--drop-users", action="store_true", help="Drop users table before creating it.")

   s_add = sub.add_parser("add-user", help="Create a user.")
   s_add.add_argument("--username", required=True, help="Email/username")
   s_add.add_argument("--password", required=True, help="Plain password (will be hashed)")
   s_add.add_argument("--role", default="viewer", help="admin|viewer (default: viewer)")

   s_del = sub.add_parser("del-user", help="Delete a user.")
   s_del.add_argument("--username", required=True)

   s_role = sub.add_parser("set-role", help="Change user role.")
   s_role.add_argument("--username", required=True)
   s_role.add_argument("--role", required=True, help="admin|viewer")

   s_pw = sub.add_parser("set-password", help="Change user password.")
   s_pw.add_argument("--username", required=True)
   s_pw.add_argument("--password", required=True)

   sub.add_parser("list-users", help="List users.")

   return p.parse_args()

def main():
   args = parse_args()
   load_env(args.env_file)

   try:
       if args.cmd == "init":
           init_db(drop_users=args.drop_users)
           print("OK: users table ready")

       elif args.cmd == "add-user":
           init_db(drop_users=False)  # ensure table exists
           add_user(args.username, args.password, args.role)
           print("OK: user added (or already existed)")

       elif args.cmd == "del-user":
           deleted = delete_user(args.username)
           print(f"OK: deleted={deleted}")

       elif args.cmd == "set-role":
           updated = set_role(args.username, args.role)
           print(f"OK: updated={updated}")

       elif args.cmd == "set-password":
           updated = set_password(args.username, args.password)
           print(f"OK: updated={updated}")

       elif args.cmd == "list-users":
           init_db(drop_users=False)  # ensure table exists
           rows = list_users()
           if not rows:
               print("(no users)")
           else:
               for r in rows:
                   print(f'{r["id"]:>3}  {r["email"]:<35}  {r["role"]:<6}  {r["created_at"]}')
       else:
           raise SystemExit("Unknown command")

   except psycopg2.Error as e:
       print(f"DB error: {e}", file=sys.stderr)
       sys.exit(2)

if __name__ == "__main__":
   main()
