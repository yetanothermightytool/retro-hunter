#!/bin/bash
set -e

echo "🛠️ Retro Hunter – Automated Setup"

# CLEANUP FUNCTION FOR ERRORS
cleanup_on_error() {
   echo ""
   echo "❌ An error occurred. Cleaning up..."
   if [ -n "$INSTALL_DIR" ] && [ -d "$INSTALL_DIR/.git" ]; then
       read -p "🗑️  Remove incomplete installation in $INSTALL_DIR? [y/N]: " REMOVE
       if [[ "$REMOVE" =~ ^[Yy]$ ]]; then
           cd /
           rm -rf "$INSTALL_DIR"
           echo "✅ Cleanup completed"
       fi
   fi
   exit 1
}

trap cleanup_on_error ERR

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

# CHECK DOCKER
if ! command -v docker >/dev/null 2>&1; then
   echo "❌ Docker not found. Please install Docker first."
   exit 1
fi

# CHECK DOCKER COMPOSE
if ! docker compose version >/dev/null 2>&1; then
   echo "❌ Docker Compose not found. Please install Docker Compose first."
   exit 1
fi

# CHECK DOCKER PERMISSIONS
if ! docker ps >/dev/null 2>&1; then
   echo "⚠️  Docker requires sudo. You may need to add your user to the docker group:"
   echo "   sudo usermod -aG docker $USER"
   echo "   Then log out and back in."
   echo ""
   read -p "Continue with sudo? [y/N]: " USE_SUDO
   if [[ ! "$USE_SUDO" =~ ^[Yy]$ ]]; then
       exit 1
   fi
   DOCKER_CMD="sudo docker"
   DOCKER_COMPOSE_CMD="sudo docker compose"
else
   DOCKER_CMD="docker"
   DOCKER_COMPOSE_CMD="docker compose"
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

# Password with confirmation
while true; do
   read -s -p "🔐 PostgreSQL password: " PG_PASS
   echo ""
   read -s -p "🔐 Confirm password: " PG_PASS_CONFIRM
   echo ""
   if [ "$PG_PASS" = "$PG_PASS_CONFIRM" ]; then
       break
   else
       echo "❌ Passwords do not match. Please try again."
   fi
done

# VBR Server Configuration
read -p "🌐 Enter VBR Server hostname or IP: " VBR_SERVER_INPUT
if [ -z "$VBR_SERVER_INPUT" ]; then
   echo "❌ VBR Server is required."
   exit 1
fi

# Format VBR_SERVER with https:// and port if not already included
if [[ ! "$VBR_SERVER_INPUT" =~ ^https?:// ]]; then
   VBR_SERVER="https://${VBR_SERVER_INPUT}"
else
   VBR_SERVER="$VBR_SERVER_INPUT"
fi

# Add port if not present
if [[ ! "$VBR_SERVER" =~ :[0-9]+$ ]]; then
   VBR_SERVER="${VBR_SERVER}:9419"
fi

echo "ℹ️  Using VBR Server: $VBR_SERVER"

read -p "👤 Enter Veeam REST API username: " REST_USER
if [ -z "$REST_USER" ]; then
   echo "❌ REST API User is required."
   exit 1
fi

# Create .env file
cat > .env <<EOF
POSTGRES_USER=$PG_USER
POSTGRES_PASSWORD=$PG_PASS
POSTGRES_DB=retro-hunter
POSTGRES_HOST=db
POSTGRES_PORT=5432
EOF

# Create .env.local file with VBR_SERVER
cat > .env.local <<EOF
POSTGRES_USER=$PG_USER
POSTGRES_PASSWORD=$PG_PASS
POSTGRES_DB=retro-hunter
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
VEEAM_API_URL=$VBR_SERVER
EOF

chmod 600 .env .env.local
echo "✅ Environment files created"

# START DATABASE
echo "🐘 Starting PostgreSQL container..."
$DOCKER_COMPOSE_CMD up -d db

echo "⏳ Waiting for PostgreSQL to become available..."
TIMEOUT=60
ELAPSED=0
until $DOCKER_CMD exec retro-hunter-db pg_isready -U "$PG_USER" >/dev/null 2>&1; do
   sleep 1
   ELAPSED=$((ELAPSED + 1))
   if [ $ELAPSED -ge $TIMEOUT ]; then
       echo "❌ PostgreSQL failed to start within ${TIMEOUT}s"
       exit 1
   fi
done
echo "✅ PostgreSQL is running."

# Install Python dependencies
echo "📦 Installing Python dependencies..."
sudo apt-get update
sudo apt-get install -y python3-psycopg2 python3-dotenv python3-passlib

REPO_DIR="$(pwd)"
ENV_FILE="$REPO_DIR/.env.local"

# DATABASE INITIALIZATION
echo "🧱 Initializing database for user management..."
python3 "$REPO_DIR/db-mgmt.py" --env-file "$ENV_FILE" init

# Create admin user with custom password
echo "👤 Creating admin user for website..."
while true; do
   read -s -p "🔐 Set admin password (min 8 chars): " ADMIN_PASS
   echo ""
   read -s -p "🔐 Confirm admin password: " ADMIN_PASS_CONFIRM
   echo ""
   
   if [ "$ADMIN_PASS" != "$ADMIN_PASS_CONFIRM" ]; then
       echo "❌ Passwords do not match. Please try again."
       continue
   fi
   
   if [ ${#ADMIN_PASS} -lt 8 ]; then
       echo "❌ Password must be at least 8 characters."
       continue
   fi
   
   break
done

python3 "$REPO_DIR/db-mgmt.py" --env-file "$ENV_FILE" add-user --username retro-admin --password "$ADMIN_PASS" --role admin
echo "✅ Admin user 'retro-admin' created"

# IMPORT DATA
echo "🦠 Importing MalwareBazaar and LOLBAS data..."
if [ ! -f "import_lolbas.py" ]; then
   echo "❌ import_lolbas.py not found"
   exit 1
fi
python3 import_lolbas.py || { echo "❌ LOLBAS import failed"; exit 1; }

if [ ! -f "import_malwarebazaar.py" ]; then
   echo "❌ import_malwarebazaar.py not found"
   exit 1
fi
python3 import_malwarebazaar.py || { echo "❌ MalwareBazaar import failed"; exit 1; }

# PATCH PYTHON SCRIPTS
echo "🔧 Patching Python scripts with VBR configuration..."

for script in retro-hunter.py nas-scanner.py; do
   if [ ! -f "$script" ]; then
       echo "⚠️  $script not found - skipping"
       continue
   fi
   
   if grep -q "__REPLACE_VBR_SERVER__" "$script"; then
       sed -i "s|__REPLACE_VBR_SERVER__|$VBR_SERVER|g" "$script"
       echo "✅ Patched $script (VBR_SERVER)"
   else
       echo "⚠️  Placeholder __REPLACE_VBR_SERVER__ not found in $script"
   fi
   
   if grep -q "__REPLACE_REST_API_USER__" "$script"; then
       sed -i "s|__REPLACE_REST_API_USER__|$REST_USER|g" "$script"
       echo "✅ Patched $script (REST_API_USER)"
   else
       echo "⚠️  Placeholder __REPLACE_REST_API_USER__ not found in $script"
   fi
done

# Make scripts executable
echo "🔨 Making scripts executable..."
for script in retro-hunter.py registry-analyzer.py import_malwarebazaar.py db-cleaner.py get-malware-csv.py nas-scanner.py db-mgmt.py; do
   if [ -f "$script" ]; then
       chmod +x "$script"
   fi
done
echo "✅ Scripts are ready to rock!"

# CREATE FERNET FILES
echo "🔐 Generating Fernet key files..."
if [ ! -f "fernet/create-fernet-files.py" ]; then
   echo "❌ Missing fernet/create-fernet-files.py"
   exit 1
fi

cp fernet/create-fernet-files.py . || { echo "❌ Failed to copy create-fernet-files.py"; exit 1; }
python3 create-fernet-files.py || { echo "❌ Fernet key generation failed"; exit 1; }
rm -rf fernet/

# Secure the Fernet key files
FERNET_DIR="certs"
if [ -d "$FERNET_DIR" ]; then
   echo "🔒 Securing Fernet key directory and files..."
   
   # Set directory permissions (only owner can read/write/execute)
   chmod 700 "$FERNET_DIR"
   
   # Set file permissions for all key files (only owner can read/write)
   find "$FERNET_DIR" -type f -name "*.key" -exec chmod 600 {} \;
   
   echo "✅ Fernet keys secured (chmod 700 for dir, 600 for *.key files)"
else
   echo "⚠️  Warning: certs directory not found - Fernet keys may not be secured!"
fi

echo "✅ Fernet files generated and secured."

# CREATE SSL CERTIFICATES
CERT_DIR="nginx/certs"
CERT_FILE="$CERT_DIR/server.crt"
KEY_FILE="$CERT_DIR/server.key"

mkdir -p "$CERT_DIR"

if [ -f "$CERT_FILE" ] && [ -f "$KEY_FILE" ]; then
   echo "⚠️  SSL certificate already exists – skipping generation."
else
   echo "🔐 Generating self-signed SSL certificate..."
   openssl req -x509 -nodes -days 825 -newkey rsa:2048 -keyout "$KEY_FILE" -out "$CERT_FILE" -subj "/CN=localhost" > /dev/null 2>&1
   
   # Secure SSL certificates
   chmod 700 "$CERT_DIR"
   chmod 600 "$KEY_FILE"
   chmod 644 "$CERT_FILE"  # Certificate can be world-readable, key must not
   
   echo "✅ Self-signed certificate created and secured at $CERT_DIR/"
   echo "⚠️  This is not secure for production use!"
fi

# Node/NPM check
echo "🧰 Checking Node.js / npm..."

NODE_REQUIRED_MAJOR=20

if ! command -v node >/dev/null 2>&1; then
   echo "❌ Node.js not found. Installing Node.js LTS..."
   
   # Install Node.js via NodeSource repository
   curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash -
   sudo apt-get install -y nodejs
   
   echo "✅ Node.js installed: $(node -v)"
else
   # Check Node.js version
   NODE_VERSION=$(node -v | sed 's/v//')
   NODE_MAJOR=$(echo "$NODE_VERSION" | cut -d. -f1)
   
   echo "ℹ️  Found Node.js: v$NODE_VERSION"
   
   if [ "$NODE_MAJOR" -lt "$NODE_REQUIRED_MAJOR" ]; then
       echo "⚠️  Node.js version $NODE_VERSION is too old (required: >= v${NODE_REQUIRED_MAJOR}.x)"
       read -p "Upgrade Node.js to latest LTS? [Y/n]: " UPGRADE_NODE
       
       if [[ ! "$UPGRADE_NODE" =~ ^[Nn]$ ]]; then
           echo "📥 Upgrading Node.js..."
           
           # Remove old Node.js
           sudo apt-get remove -y nodejs npm
           
           # Install latest LTS via NodeSource
           curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash -
           sudo apt-get install -y nodejs
           
           echo "✅ Node.js upgraded to: $(node -v)"
       else
           echo "⚠️  Continuing with old Node.js version - this may cause issues!"
       fi
   else
       echo "✅ Node.js version is sufficient (v${NODE_MAJOR}.x >= v${NODE_REQUIRED_MAJOR}.x)"
   fi
fi

# Verify npm
if ! command -v npm >/dev/null 2>&1; then
   echo "❌ npm not found. Installing..."
   sudo apt-get install -y npm
fi

echo "✅ npm version: $(npm -v)"

# FRONTEND SETUP
echo "📦 Installing frontend dependencies..."
if [ ! -d "frontend" ]; then
   echo "❌ frontend directory not found"
   exit 1
fi

cd frontend

# Install dependencies
echo "ℹ️  This may take a few minutes..."
npm install --legacy-peer-deps || { 
   echo "❌ npm install failed"
   cd ..
   exit 1
}

# Check for vulnerabilities
echo "🔍 Checking for security vulnerabilities..."
if npm audit --production 2>/dev/null | grep -q "found 0 vulnerabilities"; then
   echo "✅ No vulnerabilities found"
else
   echo "⚠️  Vulnerabilities detected"
   read -p "Attempt automatic fix? [Y/n]: " FIX_VULNS
   
   if [[ ! "$FIX_VULNS" =~ ^[Nn]$ ]]; then
       echo "🔧 Running npm audit fix..."
       npm audit fix --legacy-peer-deps 2>/dev/null || echo "⚠️  Manual review recommended: npm audit"
   fi
fi

cd ..
echo "✅ Frontend dependencies installed"

# BACKEND BUILD
echo "🚀 Building backend containers..."
$DOCKER_COMPOSE_CMD build api

# START FULL STACK
echo ""
read -p "🚀 Start Retro Hunter stack now? [y/N]: " CONFIRM
if [[ "$CONFIRM" =~ ^[Yy]$ ]]; then
   $DOCKER_COMPOSE_CMD up -d
   echo ""
   echo "✅ Retro Hunter is running"
   echo "🌐 Frontend: https://localhost (or your server's hostname)"
   echo "🔐 Login: retro-admin / <your password>"
   echo ""
   echo "ℹ️  Important: Change the admin password after first login!"
else
   echo "ℹ️  Setup completed. Start the stack later with:"
   echo "   cd $INSTALL_DIR"
   echo "   $DOCKER_COMPOSE_CMD up -d"
fi

# CLEANUP
echo ""
read -p "🧹 Clean up temporary import files? [Y/n]: " CLEANUP_CONFIRM
if [[ ! "$CLEANUP_CONFIRM" =~ ^[Nn]$ ]]; then
   echo "🧹 Cleaning up..."
   rm -f import_lolbas.py lolbin.csv malwarebazaar.csv create-fernet-files.py
   rm -rf Images
   echo "✅ Cleanup complete!"
else
   echo "ℹ️  Temporary files kept in $INSTALL_DIR"
fi

echo ""
echo "🎉 Setup complete!"
echo ""
echo "📝 Next steps:"
echo "   1. Access the web interface at https://<your-server>"
echo "   2. Login with username 'retro-admin'"
echo "   3. Change your password immediately"
echo "   4. Review the configuration in .env.local"
echo ""
echo "🔒 Security notes:"
echo "   - Fernet keys: $FERNET_DIR (chmod 700/600)"
echo "   - SSL keys: $CERT_DIR (chmod 700/600)"
echo "   - Environment files: .env, .env.local (chmod 600)"
