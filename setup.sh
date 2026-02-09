#!/bin/bash
set -e

echo "🛠️ Retro Hunter – Automated Setup"

# ARGUMENT CHECK
if [ $# -lt 2 ]; then
 echo "ℹ️ Usage: ./setup.sh <malwarebazaar.csv> <install_directory>"
 exit 1
fi

MALWARE_CSV="$1"
INSTALL_DIR="$2"

# VERIFY CSV
if [ ! -f "$MALWARE_CSV" ]; then
 echo "❌ malwarebazaar.csv not found: $MALWARE_CSV"
 exit 1
fi

# CLONE REPO
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

if [ -d ".git" ]; then
 echo "❌ Target directory already contains a git repo. Aborting."
 exit 1
fi

echo "🌐 Cloning Retro Hunter repository..."
git clone https://github.com/yetanothermightytool/retro-hunter.git .
echo "✅ Repository cloned"

# COPY CSV
cp "$MALWARE_CSV" malwarebazaar.csv

# ENV FILES
read -p "🧑 PostgreSQL user: " PG_USER
read -s -p "🔐 PostgreSQL password: " PG_PASS
echo ""

cat > .env <<EOF
POSTGRES_USER=$PG_USER
POSTGRES_PASSWORD=$PG_PASS
POSTGRES_DB=retro-hunter
POSTGRES_HOST=db
POSTGRES_PORT=5432
EOF

cat > .env.local <<EOF
POSTGRES_USER=$PG_USER
POSTGRES_PASSWORD=$PG_PASS
POSTGRES_DB=retro-hunter
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
EOF

chmod 600 .env .env.local
echo "✅ Environment files created"

# START DATABASE
echo "🐘 Starting PostgreSQL container..."
sudo docker compose up -d db

echo "⏳ Waiting for PostgreSQL to become available..."
until sudo docker exec retro-hunter-db pg_isready -U "$PG_USER" >/dev/null 2>&1; do
 sleep 1
done
echo "✅ PostgreSQL is running."

sudo apt install python3-psycopg2 python3-dotenv python3-passlib -y

REPO_DIR="$(pwd)"  
cd "$REPO_DIR"
ENV_FILE="$REPO_DIR/.env.local"

# DATABASE INITIALIZATION
echo "🧱 Initializing database for user management..."
python3 "$REPO_DIR/db-mgmt.py" --env-file "$ENV_FILE" init

echo "👤 Creating default admin user for website..."
python3 "$REPO_DIR/db-mgmt.py" --env-file "$ENV_FILE" add-user --username retro-admin --password 'ChangeMe1234!' --role admin

# IMPORT DATA
echo "🦠 Importing MalwareBazaar and LOLBAS data..."
python3 import_lolbas.py || { echo "❌ LOLBAS import failed"; exit 1; }
python3 import_malwarebazaar.py || { echo "❌ MalwareBazaar import failed"; exit 1; }

# Ask for VBR Server Config
read -p "🌐 Enter VBR Server: " VBR_SERVER
read -p "👤 Enter Veeam REST API username: " REST_USER

if [ -z "$VBR_SERVER" ] || [ -z "$REST_USER" ]; then
 echo "❌ VBR Server and REST API User are required."
 exit 1
fi

sed -i "s|__REPLACE_VBR_SERVER__|$VBR_SERVER|g" retro-hunter.py
sed -i "s|__REPLACE_REST_API_USER__|$REST_USER|g" retro-hunter.py
echo "✅ Patched retro-hunter.py"

sed -i "s|__REPLACE_VBR_SERVER__|$VBR_SERVER|g" nas-scanner.py
sed -i "s|__REPLACE_REST_API_USER__|$REST_USER|g" nas-scanner.py
echo "✅ Patched nas-scanner.py"

# Make retro-hunter.py and the other tools executable
chmod +x retro-hunter.py
chmod +x registry-analyzer.py
chmod +x import_malwarebazaar.py
chmod +x db-cleaner.py
chmod +x get-malware-csv.py
chmod +x nas-scanner.py
chmod +x db-mgmt.py
echo "🎸 retro-hunter.py & the other mighty tools are ready to rock!"

# CREATE FERNET FILES
echo "🔐 Generating Fernet key files..."
cp fernet/create-fernet-files.py . || { echo "❌ Missing create-fernet-files.py"; exit 1; }
python3 create-fernet-files.py || { echo "❌ Fernet key generation failed"; exit 1; }
rm -rf fernet/
echo "✅ Fernet files generated."

# CREATE CERTIFICATES
CERT_DIR="nginx/certs"
CERT_FILE="$CERT_DIR/server.crt"
KEY_FILE="$CERT_DIR/server.key"

mkdir -p "$CERT_DIR"

if [ -f "$CERT_FILE" ] && [ -f "$KEY_FILE" ]; then
   echo "⚠️  SSL certificate already exists – skipping generation."
else
   openssl req -x509 -nodes -days 825 -newkey rsa:2048 -keyout "$KEY_FILE" -out "$CERT_FILE" -subj "/CN=localhost"  > /dev/null 2>&1

   echo "✅ Self-signed certificate created at $CERT_DIR/"
   echo "⚠️  This is not secure for production use!"
fi


# Node/NPM check
echo "🧰 Checking Node.js / npm..."
if ! command -v npm >/dev/null 2>&1; then
 echo "❌ npm not found. Installing Node.js + npm..."
 sudo apt-get update
 sudo apt-get install -y nodejs npm
else
 echo "✅ npm found: $(npm -v)"
fi

# FRONTEND SETUP
echo "📦 Installing frontend dependencies..."
cd frontend
npm install
cd ..

# BACKEND BUILD (optional but recommended)
echo "🚀 Backend containers build..."
sudo docker compose build api

# START FULL STACK
read -p "🚀 Start Retro Hunter stack now? [y/N]: " CONFIRM
if [[ "$CONFIRM" =~ ^[Yy]$ ]]; then
 sudo docker compose up -d
 echo ""
 echo "✅ Retro Hunter is running"
 echo "🌐 Frontend: https://<server_name>"
 echo "🔐 Login: retro-admin / ChangeMe1234!"
else
 echo "ℹ️ Setup completed."
fi

# CLEANUP
echo "🧹 Cleaning up temporary import files..."
rm -f import_lolbas.py lolbin.csv malwarebazaar.csv create-fernet-files.py
rm -rf Images
echo "🎉 Setup complete!"
