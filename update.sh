#!/bin/bash
set -e

echo "🛠️ Retro Hunter Environment Update"

# Variables
SKIP_DB_UPDATE=false
MALWARE_CSV=""
PROJECT_DIR=""

# Parse arguments
while [[ $# -gt 0 ]]; do
   case $1 in
       --nodbupdate)
           SKIP_DB_UPDATE=true
           shift
           ;;
       *)
           if [ -z "$PROJECT_DIR" ]; then
               # First non-flag argument is project directory
               PROJECT_DIR="$1"
           elif [ -z "$MALWARE_CSV" ]; then
               # Second non-flag argument is CSV file
               MALWARE_CSV="$1"
           else
               echo "❌ Unknown argument: $1"
               exit 1
           fi
           shift
           ;;
   esac
done

# Argument Checker 
if [ -z "$PROJECT_DIR" ]; then
   echo "Usage: ./update.sh [--nodbupdate] <project_directory> [malwarebazaar.csv]"
   echo ""
   echo "Options:"
   echo "  --nodbupdate    Skip database update (only pull from GitHub)"
   echo ""
   echo "Examples:"
   echo "  ./update.sh /opt/retro-hunter malware.csv          # Full update"
   echo "  ./update.sh --nodbupdate /opt/retro-hunter         # GitHub only"
   echo "  ./update.sh /opt/retro-hunter                      # GitHub only (no CSV provided)"
   exit 1
fi

# Verifiy project directory
if [ ! -d "$PROJECT_DIR" ]; then
   echo "❌ Directory $PROJECT_DIR does not exist!"
   exit 1
fi

if [ ! -d "$PROJECT_DIR/.git" ]; then
   echo "❌ $PROJECT_DIR is not a git repository!"
   exit 1
fi

echo "📂 Using project directory: $PROJECT_DIR"
cd "$PROJECT_DIR" || exit 1

# Check if DB needs to be updated
if [ "$SKIP_DB_UPDATE" = false ] && [ -z "$MALWARE_CSV" ]; then
   echo "ℹ️  No CSV file provided - skipping database update"
   SKIP_DB_UPDATE=true
fi

# Verify CSV file
if [ "$SKIP_DB_UPDATE" = false ]; then
   if [ ! -f "$MALWARE_CSV" ]; then
       echo "❌ File not found: $MALWARE_CSV"
       exit 1
   fi
   echo "Found malwarebazaar.csv"
fi

# Extract the local config values
echo "Extracting local configuration..."

# Extract REST API username from retro-hunter.py
REST_USER=""
if [ -f "retro-hunter.py" ]; then
   REST_USER=$(grep -m 1 '^\s*username\s*=\s*"' retro-hunter.py | \
               grep -oP '"\K[^"]+' | \
               head -n 1)

   # Check if we got a valid username (not the placeholder)
   if [ -n "$REST_USER" ] && [ "$REST_USER" != "__REPLACE_REST_API_USER__" ]; then
       echo "  ✓ Found REST API username: $REST_USER"
   else
       echo "  ⚠️  No configured REST API username found (still using placeholder. Do you use the script?)"
       REST_USER=""
   fi
fi

# Backup important files
echo "Creating backup of important files..."
BACKUP_DIR="backup_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

# List of files that should NEVER be overwritten by git (local-only)
LOCAL_ONLY_FILES=(
   ".env"
   ".env.local"
)

# Backup local-only configuration files
for file in "${LOCAL_ONLY_FILES[@]}"; do
   if [ -f "$file" ]; then
       cp "$file" "$BACKUP_DIR/"
       echo "  ✓ Backed up $file"
   fi
done

# Backup Fernet keys
if [ -d "certs" ]; then
   cp -r certs "$BACKUP_DIR/"
   echo "  ✓ Backed up certs/"
fi

# Backup nginx certs
if [ -d "nginx/certs" ]; then
   mkdir -p "$BACKUP_DIR/nginx"
   cp -r nginx/certs "$BACKUP_DIR/nginx/"
   echo "  ✓ Backed up nginx/certs/"
fi

echo "✅ Backup created in $BACKUP_DIR"

# CHECK FOR LOCAL CHANGES
echo ""
echo "🔍 Checking repository status..."

# Check for actual content changes (not just permission changes)
if ! git diff --quiet HEAD -- 2>/dev/null; then
   echo "⚠️  Local file modifications detected:"
   git diff --stat HEAD
   echo ""
   echo "These content changes will be discarded to apply the update."
   echo "Your configuration (.env, certs) is safely backed up."
   read -p "Continue? [Y/n]: " CONTINUE
   if [[ "$CONTINUE" =~ ^[Nn]$ ]]; then
       echo "❌ Update cancelled"
       exit 1
   fi
   
   # Reset all local changes to tracked files
   echo "🔄 Resetting local changes..."
   git reset --hard HEAD
elif ! git diff-index --quiet HEAD -- 2>/dev/null; then
   # Only permission changes (like +x flag)
   echo "ℹ️  Detected executable flag changes (will be reset and reapplied after update)"
   git reset --hard HEAD
else
   echo "✅ No local changes detected"
fi

# Update Repo
echo "Pulling latest changes from GitHub..."
git fetch origin main

# Show what will be updated
CURRENT_COMMIT=$(git rev-parse HEAD)
REMOTE_COMMIT=$(git rev-parse origin/main)

if [ "$CURRENT_COMMIT" = "$REMOTE_COMMIT" ]; then
   echo "✅ Already up to date (commit: ${CURRENT_COMMIT:0:7})"
   REPO_UPDATED=false
else
   echo ""
   echo "📊 Changes to be applied:"
   # Show compact summary of changes
   echo ""
   git log --oneline HEAD..origin/main | head -n 10
   echo ""
   echo "📁 Files that will be updated:"
   git diff --name-status HEAD..origin/main | head -n 20
   echo ""
   
   read -p "Apply these updates? [Y/n]: " APPLY
   if [[ "$APPLY" =~ ^[Nn]$ ]]; then
       echo "❌ Update cancelled"
       exit 1
   fi
   
   # Pull changes
   git pull origin main
   echo "✅ Repository updated to commit: $(git rev-parse --short HEAD)"
   REPO_UPDATED=true
fi

# Restore local-only files
echo ""
echo "🔄 Restoring local configuration..."

# Restore local-only config files
for file in "${LOCAL_ONLY_FILES[@]}"; do
   if [ -f "$BACKUP_DIR/$file" ]; then
       cp "$BACKUP_DIR/$file" "$file"
       echo "  ✓ Restored $file"
   fi
done

# Restore Fernet keys
if [ -d "$BACKUP_DIR/certs" ]; then
   rm -rf certs 2>/dev/null || true
   cp -r "$BACKUP_DIR/certs" .
   chmod 700 certs
   find certs -type f -name "*.key" -exec chmod 600 {} \;
   echo "  ✓ Restored and secured certs/"
fi

# Restore nginx certs
if [ -d "$BACKUP_DIR/nginx/certs" ]; then
   mkdir -p nginx
   rm -rf nginx/certs 2>/dev/null || true
   cp -r "$BACKUP_DIR/nginx/certs" nginx/
   chmod 700 nginx/certs
   chmod 600 nginx/certs/server.key 2>/dev/null || true
   chmod 644 nginx/certs/server.crt 2>/dev/null || true
   echo "  ✓ Restored and secured nginx/certs/"
fi

# Patch local files
if [ -n "$REST_USER" ]; then
   echo ""
   echo "🔧 Applying local configuration to scripts..."
   
   for script in retro-hunter.py; do
       if [ -f "$script" ]; then
           if grep -q "__REPLACE_REST_API_USER__" "$script"; then
               sed -i "s|__REPLACE_REST_API_USER__|$REST_USER|g" "$script"
               echo "  ✓ Patched $script with REST_USER"
           else
               # Script was already patched or format changed
               if [ "$REPO_UPDATED" = true ]; then
                   echo "  ⚠️  No placeholder found in $script (may need manual update)"
               fi
           fi
       fi
   done
else
   if [ "$REPO_UPDATED" = true ]; then
       echo ""
       echo "⚠️  No REST_USER found - scripts may need manual configuration"
   fi
fi

# Make the scripts executable again
echo ""
echo "🔨 Setting executable permissions..."
SCRIPT_FILES=(
   "retro-hunter.py"
   "registry-analyzer.py"
   "import_malwarebazaar.py"
   "db-cleaner.py"
   "get-malware-csv.py"
   "nas-scanner.py"
   "db-mgmt.py"
)

MADE_EXECUTABLE=0
for script in "${SCRIPT_FILES[@]}"; do
   if [ -f "$script" ]; then
       if [ ! -x "$script" ]; then
           chmod +x "$script"
           MADE_EXECUTABLE=$((MADE_EXECUTABLE + 1))
       fi
   fi
done

if [ $MADE_EXECUTABLE -gt 0 ]; then
   echo "  ✓ Made $MADE_EXECUTABLE script(s) executable"
else
   echo "  ✓ All scripts already executable"
fi

# DB update
if [ "$SKIP_DB_UPDATE" = false ]; then
   echo ""
   echo "Updating MalwareBazaar data..."
   
   # Copy new CSV
   cp "$MALWARE_CSV" malwarebazaar.csv
   echo "  ✓ Copied new malwarebazaar.csv"
   
   # Check if import script exists
   if [ ! -f "import_malwarebazaar.py" ]; then
       echo "❌ import_malwarebazaar.py not found"
       exit 1
   fi
   
   # Check if database is running
   if command -v docker >/dev/null 2>&1; then
       if docker ps | grep -q retro-hunter-db; then
           echo "  ✓ Database container is running"
       else
           echo "⚠️  Database container not running"
           read -p "Start database now? [Y/n]: " START_DB
           if [[ ! "$START_DB" =~ ^[Nn]$ ]]; then
               docker compose up -d db
               echo "⏳ Waiting for database..."
               sleep 5
           else
               echo "❌ Database update cancelled"
               exit 1
           fi
       fi
   fi
   
   # Run import
   python3 import_malwarebazaar.py || { echo "❌ MalwareBazaar import failed"; exit 1; }
   echo "✅ MalwareBazaar data updated"
else
   echo ""
   echo "ℹ️  Skipping database update"
fi

# Check if containers need to be restarted
echo ""
read -p "🔄 Restart Docker containers to apply updates? [Y/n]: " RESTART
if [[ ! "$RESTART" =~ ^[Nn]$ ]]; then
   if command -v docker >/dev/null 2>&1; then
       echo "Rebuilding and restarting containers..."
       docker compose build
       docker compose up -d
       echo "✅ Containers restarted"
   else
       echo "⚠️  Docker not found, skipping container restart"
   fi
else
   echo "ℹ️  Remember to restart containers manually:"
   echo "   cd $PROJECT_DIR"
   echo "   docker compose build"
   echo "   docker compose up -d"
fi

# CLEANUP OLD BACKUPS
echo ""
echo "Checking for old backups..."
BACKUP_COUNT=$(find . -maxdepth 1 -type d -name "backup_*" | wc -l)
if [ "$BACKUP_COUNT" -gt 3 ]; then
   echo "⚠️  Found $BACKUP_COUNT backup directories"
   read -p "Keep only the 3 most recent backups? [Y/n]: " CLEANUP_BACKUPS
   if [[ ! "$CLEANUP_BACKUPS" =~ ^[Nn]$ ]]; then
       ls -dt backup_* | tail -n +4 | xargs rm -rf
       echo "✅ Old backups cleaned up"
   fi
fi

echo ""
echo "🎉 Update complete!"
echo ""
echo "Summary:"
echo "   - Git repository: Updated"
if [ "$SKIP_DB_UPDATE" = false ]; then
   echo "   - Database: Updated"
else
   echo "   - Database: Skipped"
fi
echo "   - Local configuration: Preserved"
echo "   - Scripts: Re-patched and made executable"
echo "   - Backup location: $BACKUP_DIR"
echo ""
echo "Thanks for flying with Yet Another Mighty Tool!"
