#!/bin/bash
set -e

echo -e "\n\033[1;35m=================================================\033[0m"
echo -e "🕵️‍♀️  \033[1;33mRetro Hunter Setup Tool – Let the hunt begin!\033[0m"
echo -e "\033[1;35m=================================================\033[0m\n"

echo "🚀 Starting Retro Hunter setup..."
# === Arguments & Pre-Check(s) ===
if [ $# -lt 2 ]; then
   echo "ℹ️ Usage: ./setup.sh <path_to_malwarebazaar.csv> <project_directory>"
   exit 1
fi

# === PYTHON MODULE CHECK ===
echo "🐍 Checking required Python modules..."
# Nur nicht-standardmäßige Module prüfen
REQUIRED_MODULES=(colorama requests keyring dateutil Evtx magic pefile)
MISSING_MODULES=()
for module in "${REQUIRED_MODULES[@]}"; do
   python3 -c "import $module" 2>/dev/null || MISSING_MODULES+=("$module")
done
python3 -c "import yara" 2>/dev/null || MISSING_MODULES+=("yara-python")
if [ ${#MISSING_MODULES[@]} -ne 0 ]; then
   echo "❌ Missing required Python modules:"
   for m in "${MISSING_MODULES[@]}"; do echo "   - $m"; done
   echo ""
   echo "💡 You can install them with:"
   echo "   pip3 install ${MISSING_MODULES[*]}"
   echo ""
   exit 1
else
   echo "✅ All required Python modules are available."
fi

# === Get parameters ===
MALWARE_CSV_SOURCE="$1"
PROJECT_DIR="$2"

# === Validate malwarebazaar.csv ===
if [ ! -f "$MALWARE_CSV_SOURCE" ]; then
   echo "❌ Provided malwarebazaar.csv path is invalid: $MALWARE_CSV_SOURCE"
   exit 1
fi
echo "📄 Found malwarebazaar.csv: $MALWARE_CSV_SOURCE"

# === Create or use project directory ===
if [ ! -d "$PROJECT_DIR" ]; then
   echo "📁 Creating project directory: $PROJECT_DIR"
   mkdir "$PROJECT_DIR"
else
   echo "📂 Using existing project directory: $PROJECT_DIR"
fi

cd "$PROJECT_DIR"

# === Clone GitHub repo ===
if [ ! -d ".git" ]; then
   echo "🌐 Cloning YAMT Retro Hunter Repository from GitHub..."
   git clone -q https://github.com/yetanothermightytool/retro-hunter.git . || {
       echo "❌ Git clone failed. Please check internet connection."
       exit 1
   }
else
   echo "🔄 Repository already present. Aborting setup."
   exit 1
fi

# === Copy malwarebazaar.csv into project directory ===
echo "📦 Copying malwarebazaar.csv to project directory..."
cp "$MALWARE_CSV_SOURCE" malwarebazaar.csv

# === Check required local files ===
echo "🔍 Checking required files..."
REQUIRED=(import_lolbas.py lolbin.csv)
for f in "${REQUIRED[@]}"; do
   if [ ! -f "$f" ]; then
       echo "❌ Missing required file: $f"
       exit 1
   fi
done

# === Import to badfiles.db ===
echo "🛠️ Creating badfiles.db and importing LOLBAS..."
python3 import_lolbas.py || {
   echo "❌ Failed to import LOLBAS"
   exit 1
}

# === Import malwarebazaar.csv ===
if [ -f "malwarebazaar.csv" ]; then
   echo "🦠 Importing malware hashes from malwarebazaar.csv..."
   python3 import_malwarebazaar.py || {
       echo "❌ MalwareBazaar import failed"
       exit 1
   }
else
   echo "⚠️ malwarebazaar.csv not found in project directory."
   exit 1
fi

# === Quick DB check ===
echo "🧪 Verifying database content..."
if [ -f "badfiles.db" ]; then
   LOL_COUNT=$(sqlite3 badfiles.db "SELECT COUNT(*) FROM lolbas;")
   echo "   ✅ LOLBAS entries: $LOL_COUNT"
   if sqlite3 badfiles.db "SELECT name FROM sqlite_master WHERE type='table' AND name='malwarebazaar';" | grep -q 'malwarebazaar'; then
       MW_COUNT=$(sqlite3 badfiles.db "SELECT COUNT(*) FROM malwarebazaar;")
       echo "   ✅ MalwareBazaar entries: $MW_COUNT"
   fi
else
   echo "❌ badfiles.db not found!"
   exit 1
fi

# === Ensure file_index.db exists for Docker mount ===
if [ ! -f file_index.db ]; then
   echo "📄 Creating empty file_index.db for Docker mount..."
   sqlite3 file_index.db "VACUUM;" || {
       echo "❌ Failed to create file_index.db"
       exit 1
   }
else
   echo "📂 file_index.db already exists – skipping creation."
fi

# === Configure retro-hunter.py with user-provided values ===
echo "🛠️  Customizing retro-hunter.py..."
read -p "👉 VBR Server? " VBR_SERVER
read -p "👉 Veeam REST API USER? " REST_API_USER
if [ -z "$VBR_SERVER" ] || [ -z "$REST_API_USER" ]; then
   echo "❌ Both VBR Server and REST API User must be provided."
   exit 1
fi
# Replace placeholders in retro-hunter.py
sed -i "s|__REPLACE_VBR_SERVER__|$VBR_SERVER|g" retro-hunter.py
sed -i "s|__REPLACE_REST_API_USER__|$REST_API_USER|g" retro-hunter.py
echo "✅ retro-hunter.py configured successfully."

# Make retro-hunter.py executable
chmod +x retro-hunter.py
echo "🎸 retro-hunter.py ready to rock!"

# === Execute create-fernet-files.py ===
echo "🔐 Preparing Fernet key files..."
# Copy script to current directory
cp fernet/create-fernet-files.py . || {
   echo "❌ Failed to copy create-fernet-files.py"
   exit 1
}
python3 create-fernet-files.py || {
   echo "❌ Failed to execute create-fernet-files.py"
   exit 1
}
# Delete fernet/ directory
rm -rf fernet/
echo "🧹 Removed fernet/ directory after Fernet key generation."

# === DOCKER UI SETUP ===
echo "📦 The Retro Hunter Streamlit Dashboard can be started in a Docker container."
read -p "❓ Do you want to install and launch the Streamlit UI now? [y/N]: " CONFIRM
if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
   echo ""
   echo "🧹 Cleaning up import files..."
   rm -f import_lolbas.py lolbin.csv import_malwarebazaar.py malwarebazaar.csv setup.sh create-fernet-files.py
   rm -rf Images
   echo "🚫 Streamlit UI setup was skipped by user choice."
   echo "🛡️ You can still run Retro Hunter manually via: sudo ./retro-hunter.py"
   echo "🏁 Setup complete without Docker."
   exit 0
fi


# === Generate self-signed SSL certificate for Streamlit ===
echo "🔐 Generating self-signed SSL certificate for Streamlit..."

CERT_DIR="docker/certs"
CERT_FILE="$CERT_DIR/cert.pem"
KEY_FILE="$CERT_DIR/key.pem"

mkdir -p "$CERT_DIR"

if [ -f "$CERT_FILE" ] && [ -f "$KEY_FILE" ]; then
   echo "⚠️  SSL certificate already exists – skipping generation."
else
   openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
       -keyout "$KEY_FILE" \
       -out "$CERT_FILE" \
       -subj "/CN=localhost" > /dev/null 2>&1

   echo "✅ Self-signed certificate created at $CERT_DIR/"
   echo "⚠️  This is not secure for production use!"
fi

# === Update docker-compose.yml with absolute paths ===
echo "🛠️  Updating docker-compose.yml volume paths..."
COMPOSE_FILE="docker/docker-compose.yml"
ABS_PATH="$(pwd)"
[ ! -f "$COMPOSE_FILE.bak" ] && cp "$COMPOSE_FILE" "$COMPOSE_FILE.bak"
sed -i "s|  - ./app.py:/app/app.py|  - $ABS_PATH/app.py:/app/app.py|g" "$COMPOSE_FILE"
sed -i "s|  - ./file_index.db:/app/file_index.db|  - $ABS_PATH/file_index.db:/app/file_index.db|g" "$COMPOSE_FILE"
sed -i "s|  - ./badfiles.db:/app/badfiles.db|  - $ABS_PATH/badfiles.db:/app/badfiles.db|g" "$COMPOSE_FILE"
sed -i "s|  - ./certs:/app/certs|  - $ABS_PATH/docker/certs:/app/certs|g" "$COMPOSE_FILE"
echo "✅ docker-compose.yml updated."

# === Start Docker container ===
echo "🐳 Building and starting Retro Hunter UI container, powered by Streamlit..."
if docker compose -f docker/docker-compose.yml up -d > /dev/null 2>&1; then
   echo "✅ Docker container is running at https://localhost:8501"
else
   echo "❌ Failed to build or start Docker container."
   echo "💡 Run 'docker compose -f docker/docker-compose.yml up' manually to see details."
   exit 1
fi

# === END. Cleanup ===
echo "🧹 Cleaning up files..."
echo "🧹 Cleaning up import files..."
rm -f import_lolbas.py lolbin.csv import_malwarebazaar.py malwarebazaar.csv setup.sh create-fernet-files.py
rm -rf Images
echo ""
echo "+------------------------------------------+"
echo "|  🎉 SETUP COMPLETE – RETRO HUNTER READY  |"
echo "|  🔎 UI: https://localhost:8501           |"
echo "|  💀 Happy hunting, detective! 🕵️‍♀️         |"
echo "+------------------------------------------+"
echo ""
echo "👉 To start your first scan, run:"
echo ""
echo "   cd \"$PROJECT_DIR\""
echo "   sudo ./retro-hunter.py +documented parameters"
echo ""
