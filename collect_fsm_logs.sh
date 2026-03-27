#!/bin/bash
# =============================================================================
# FortiSIEM Log Collection Script
# Based on: Fortinet Technical Tip - Article ID 192568
# Usage: ./collect_fsm_logs.sh <ticket_number> <number_of_days>
# Example: ./collect_fsm_logs.sh 1234567 3
# Must be run as root on the FortiSIEM Supervisor/Worker/Collector
# =============================================================================

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Colour

# ── Helper functions ──────────────────────────────────────────────────────────
log()    { echo -e "${CYAN}[$(date '+%H:%M:%S')]${NC} $1"; }
ok()     { echo -e "${GREEN}[$(date '+%H:%M:%S')] ✔ $1${NC}"; }
warn()   { echo -e "${YELLOW}[$(date '+%H:%M:%S')] ⚠ $1${NC}"; }
err()    { echo -e "${RED}[$(date '+%H:%M:%S')] ✘ $1${NC}"; }

# ── Banner ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}============================================================${NC}"
echo -e "${CYAN}   FortiSIEM Log Collection Script (Fortinet KB 192568)    ${NC}"
echo -e "${CYAN}============================================================${NC}"
echo ""

# ── Input validation ──────────────────────────────────────────────────────────
if [[ $# -ne 2 ]]; then
    err "Invalid arguments."
    echo ""
    echo "  Usage  : $0 <ticket_number> <number_of_days>"
    echo "  Example: $0 1234567 3"
    echo ""
    exit 1
fi

TICKET="$1"
DAYS="$2"

# Validate ticket number (numeric only)
if ! [[ "$TICKET" =~ ^[0-9]+$ ]]; then
    err "Ticket number must be numeric. Got: '$TICKET'"
    exit 1
fi

# Validate days (numeric, between 1-30)
if ! [[ "$DAYS" =~ ^[0-9]+$ ]] || [[ "$DAYS" -lt 1 ]] || [[ "$DAYS" -gt 30 ]]; then
    err "Number of days must be a number between 1 and 30. Got: '$DAYS'"
    exit 1
fi

# ── Root check ────────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    err "This script must be run as root."
    exit 1
fi

# ── Setup ─────────────────────────────────────────────────────────────────────
WORKDIR="/tmp/${TICKET}"
DATE_STAMP=$(date '+%Y%m%d_%H%M%S')
HOSTNAME=$(hostname -s)
FINAL_NAME="FortiSIEMLogs-${TICKET}-${HOSTNAME}-${DATE_STAMP}.tar"

echo -e "  Ticket Number  : ${YELLOW}${TICKET}${NC}"
echo -e "  Days to Collect: ${YELLOW}${DAYS}${NC}"
echo -e "  Output Dir     : ${YELLOW}${WORKDIR}${NC}"
echo -e "  Final Archive  : ${YELLOW}${WORKDIR}/${FINAL_NAME}${NC}"
echo -e "  Host           : ${YELLOW}${HOSTNAME}${NC}"
echo ""

# ── Create working directory ──────────────────────────────────────────────────
log "Creating working directory: ${WORKDIR}"
mkdir -p "${WORKDIR}"
ok "Directory ready."
echo ""

# ── Step 1: Collect supplementary files ───────────────────────────────────────
echo -e "${CYAN}── Step 1: Collecting supplementary diagnostic files ──${NC}"
echo ""

# 1a. FSM health
log "Running get-fsm-health.py..."
if command -v get-fsm-health.py &>/dev/null; then
    get-fsm-health.py --local -o /tmp/fsm-health.log 2>/dev/null \
        && ok "fsm-health.log collected." \
        || warn "get-fsm-health.py ran but may have had errors."
else
    warn "get-fsm-health.py not found — skipping."
    echo "get-fsm-health.py not found on this node" > /tmp/fsm-health.log
fi

# 1b. journalctl kernel log
log "Collecting kernel journal (journalctl -k)..."
journalctl -k --no-pager > /tmp/journlctl.log 2>/dev/null \
    && ok "journlctl.log collected." \
    || warn "journalctl failed — skipping."

# 1c. Interrupts
log "Collecting /proc/interrupts..."
cat /proc/interrupts > /tmp/interrupts.txt 2>/dev/null \
    && ok "interrupts.txt collected." \
    || warn "Could not read /proc/interrupts."

# 1d. Hosts file
log "Collecting /etc/hosts..."
cat /etc/hosts > /tmp/hosts.txt 2>/dev/null \
    && ok "hosts.txt collected." \
    || warn "Could not read /etc/hosts."

# 1e. Root environment
log "Collecting root environment..."
env > /tmp/root_env 2>/dev/null \
    && ok "root_env collected." \
    || warn "Could not collect root env."

# 1f. Admin environment
log "Collecting admin user environment..."
su admin -c env > /tmp/admin_env 2>/dev/null \
    && ok "admin_env collected." \
    || warn "Could not collect admin env (admin user may not exist on this node)."

# 1g. PostgreSQL activity
log "Collecting PostgreSQL pg_stat_activity..."
if command -v psql &>/dev/null; then
    psql -U phoenix -d phoenixdb -c "select * from pg_stat_activity" \
        > /tmp/pg_stat_activity.out 2>/dev/null \
        && ok "pg_stat_activity.out collected." \
        || warn "psql query failed — DB may not be local on this node."
else
    warn "psql not found — skipping (not a Supervisor with DB)."
    echo "psql not available on this node" > /tmp/pg_stat_activity.out
fi

# 1h. ClickHouseKeeper app logs
log "Collecting ClickHouseKeeper application logs..."
if ls /data-clickhouse-*/clickhouse-keeper/app_logs 2>/dev/null | head -1 | grep -q .; then
    tar -czvf /tmp/keeper_logs.tar.gz \
        /data-clickhouse-*/clickhouse-keeper/app_logs > /dev/null 2>&1 \
        && ok "keeper_logs.tar.gz collected." \
        || warn "Failed to archive keeper app logs."
else
    warn "ClickHouseKeeper app_logs directory not found — skipping."
    touch /tmp/keeper_logs.tar.gz
fi

# 1i. ClickHouseKeeper config
log "Collecting ClickHouseKeeper config..."
if ls /data-clickhouse-*/clickhouse-keeper/conf 2>/dev/null | head -1 | grep -q .; then
    tar -czvf /tmp/keeper_conf.tar.gz \
        /data-clickhouse-*/clickhouse-keeper/conf > /dev/null 2>&1 \
        && ok "keeper_conf.tar.gz collected." \
        || warn "Failed to archive keeper config."
else
    warn "ClickHouseKeeper conf directory not found — skipping."
    touch /tmp/keeper_conf.tar.gz
fi

echo ""

# ── Step 2: Run phziplogs ──────────────────────────────────────────────────────
echo -e "${CYAN}── Step 2: Running phziplogs ──${NC}"
echo ""
log "Running: phziplogs /tmp/${TICKET} ${DAYS}"
log "This may take several minutes depending on log volume..."
echo ""

if command -v phziplogs &>/dev/null; then
    phziplogs "/tmp/${TICKET}" "${DAYS}"
    PHZIP_EXIT=$?
    if [[ $PHZIP_EXIT -eq 0 ]]; then
        ok "phziplogs completed successfully."
    else
        warn "phziplogs exited with code ${PHZIP_EXIT} — archive may be incomplete."
    fi
else
    err "phziplogs not found. Is this a FortiSIEM node? Check PATH."
    err "PATH: $PATH"
    exit 1
fi

echo ""

# ── Step 3: Append supplementary files to AOLogs.tar ─────────────────────────
echo -e "${CYAN}── Step 3: Appending supplementary files to AOLogs.tar ──${NC}"
echo ""

AOLOGS_TAR="${WORKDIR}/AOLogs.tar"

if [[ ! -f "${AOLOGS_TAR}" ]]; then
    err "AOLogs.tar not found in ${WORKDIR}. phziplogs may have failed."
    err "Contents of ${WORKDIR}:"
    ls -lh "${WORKDIR}"
    exit 1
fi

SUPPLEMENTARY_FILES=(
    /tmp/fsm-health.log
    /tmp/journlctl.log
    /tmp/interrupts.txt
    /tmp/hosts.txt
    /tmp/root_env
    /tmp/admin_env
    /tmp/pg_stat_activity.out
    /tmp/keeper_logs.tar.gz
    /tmp/keeper_conf.tar.gz
)

for FILE in "${SUPPLEMENTARY_FILES[@]}"; do
    if [[ -f "$FILE" ]]; then
        log "Appending: $(basename $FILE)..."
        tar --append --file="${AOLOGS_TAR}" "$FILE" 2>/dev/null \
            && ok "$(basename $FILE) appended." \
            || warn "Failed to append $(basename $FILE)."
    else
        warn "File not found, skipping: $FILE"
    fi
done

echo ""

# ── Step 4: Rename archive ────────────────────────────────────────────────────
echo -e "${CYAN}── Step 4: Renaming archive ──${NC}"
echo ""

log "Renaming AOLogs.tar to ${FINAL_NAME}..."
mv "${AOLOGS_TAR}" "${WORKDIR}/${FINAL_NAME}" 2>/dev/null \
    && ok "Archive renamed successfully." \
    || warn "Could not rename — file may already be named differently."

echo ""

# ── Step 5: Summary ───────────────────────────────────────────────────────────
echo -e "${CYAN}── Step 5: Summary ──${NC}"
echo ""

ARCHIVE_PATH="${WORKDIR}/${FINAL_NAME}"
if [[ -f "${ARCHIVE_PATH}" ]]; then
    ARCHIVE_SIZE=$(du -sh "${ARCHIVE_PATH}" | cut -f1)
    ok "Log collection complete!"
    echo ""
    echo -e "  Archive Location : ${GREEN}${ARCHIVE_PATH}${NC}"
    echo -e "  Archive Size     : ${GREEN}${ARCHIVE_SIZE}${NC}"
    echo ""
    echo -e "${CYAN}── Next Steps ──────────────────────────────────────────────${NC}"
    echo ""
    echo "  1. Copy archive to your local machine:"
    echo ""
    echo -e "     ${YELLOW}# From your local Linux/Mac terminal:${NC}"
    echo "     scp root@$(hostname -I | awk '{print $1}'):${ARCHIVE_PATH} ."
    echo ""
    echo -e "     ${YELLOW}# Windows: Use WinSCP to pull from:${NC}"
    echo "     Host: $(hostname -I | awk '{print $1}')"
    echo "     Path: ${ARCHIVE_PATH}"
    echo ""
    echo "  2. Upload to Fortinet Support ticket #${TICKET} at:"
    echo "     https://support.fortinet.com"
    echo ""
    echo "  NOTE: Max upload size is 500MB per attachment."
    echo ""
else
    err "Archive not found at expected path: ${ARCHIVE_PATH}"
    log "Contents of ${WORKDIR}:"
    ls -lh "${WORKDIR}"
fi

# ── Cleanup temp files ────────────────────────────────────────────────────────
log "Cleaning up temporary files..."
rm -f /tmp/fsm-health.log /tmp/journlctl.log /tmp/interrupts.txt \
       /tmp/hosts.txt /tmp/root_env /tmp/admin_env \
       /tmp/pg_stat_activity.out /tmp/keeper_logs.tar.gz /tmp/keeper_conf.tar.gz
ok "Temp files cleaned up."
echo ""
