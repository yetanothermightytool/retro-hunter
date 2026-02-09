#!/bin/bash
echo "🛠️ Retro Hunter Environment Update"

# ARGUMENT CHECK
if [ $# -lt 2 ]; then
 echo "ℹ️ Usage: ./setup.sh <malwarebazaar.csv> <project_directory>"
 exit 1
fi

MALWARE_CSV="$1"
PROJECT_DIR="$2"

# VERIFY CSV FILE
if [ ! -f "$MALWARE_CSV" ]; then
 echo "❌ File not found: $MALWARE_CSV"
 exit 1
fi
echo "📄 Found malwarebazaar.csv"

# CREATE PROJECT DIRECTORY
if [ ! -d "$PROJECT_DIR" ]; then
 echo "❌ Directory $PROJECT_DIR does not exist!"
 exit
else
 echo "📂 Using existing project directory: $PROJECT_DIR"
fi
cd "$PROJECT_DIR" || exit 1

# UPDATE REPO
 echo "🌐 Cloning Retro Hunter GitHub repository..."
 git pull https://github.com/yetanothermightytool/retro-hunter.git main

# COPY CSV
echo "📦 Copying malwarebazaar.csv..."
cp "$MALWARE_CSV" malwarebazaar.csv

# CHECK LOCAL FILES
echo "🔍 Checking required local import script..."
REQUIRED=(import_malwarebazaar.py)
for f in "${REQUIRED[@]}"; do
 [ ! -f "$f" ] && echo "❌ Missing: $f" && exit 1
done

echo "🦠 Update MalwareBazaar..."
python3 import_malwarebazaar.py || { echo "❌ MalwareBazaar import failed"; exit 1; }

echo "✅ Setup complete! Thanks for flying with Yet Another Mighty Tool!"
