================================================================================
  AD-AUDIT.SH v3.0 — README
  Sr.Robot Labs | Antonio José Romero Fdez.-Giro
  USO EXCLUSIVO EN ENTORNOS CON AUTORIZACIÓN ESCRITA
================================================================================


¿QUÉ ES ESTE SCRIPT?
────────────────────
ad_audit.sh es una herramienta de auditoría de seguridad para entornos
Active Directory (AD), escrita en Bash. Permite a un auditor o pentester
analizar de forma ordenada un dominio Windows, desde la recopilación
inicial de información hasta el análisis avanzado de rutas de ataque.

Pensada para:
  - Laboratorios de práctica (HackTheBox, TryHackMe, laboratorio propio)
  - Auditorías de seguridad con autorización escrita del cliente
  - Entornos de formación en ciberseguridad ofensiva (DAW / ASIR / CEH)


REQUISITOS DEL SISTEMA
──────────────────────
  - Sistema operativo: Linux (Kali, Parrot, Ubuntu, Debian...)
  - Intérprete:        bash 4.0 o superior (NO funciona con sh/dash)
  - Permisos:          usuario normal (algunos módulos pueden requerir sudo)

  IMPORTANTE: ejecuta siempre con 'bash', no con 'sh':
    bash ad_audit.sh          correcto
    sh   ad_audit.sh          incorrecto — dará error en línea 52


MODOS DE USO
────────────
  1. Menú interactivo (recomendado para uso manual):

       chmod +x ad_audit.sh
       bash ad_audit.sh

  2. Modo automático (ejecuta todos los módulos en secuencia):

       bash ad_audit.sh --auto

  3. Verificar herramientas instaladas (sin tocar ningún objetivo):

       bash ad_audit.sh --check

  4. Ayuda rápida:

       bash ad_audit.sh --help


MÓDULOS DISPONIBLES
───────────────────

  [0] Configuración del objetivo
  ─────────────────────────────────────────────────────────────────────
  Introduce la IP del Domain Controller, el nombre de dominio, el
  directorio de salida y las credenciales: usuario/contraseña o hash
  NTLM para pass-the-hash. Puedes indicar rutas a wordlists propias.


  [c] Verificación de herramientas
  ─────────────────────────────────────────────────────────────────────
  Tabla con el estado de cada herramienta. Si alguna falta, muestra
  el comando exacto para instalarla. También comprueba wordlists.


  [1] Enumeración anónima
  ─────────────────────────────────────────────────────────────────────
  Recopila información del dominio SIN credenciales. Comprueba si el
  servidor expone datos a cualquier usuario de la red.

  Herramientas: netexec, rpcclient, smbmap, smbclient, ldapsearch
  Detecta: nombre de dominio, usuarios, grupos, recursos SMB


  [2] Enumeración autenticada + LDAP profundo
  ─────────────────────────────────────────────────────────────────────
  Con credenciales válidas extrae información detallada del directorio.

  Herramientas: netexec, smbmap, rpcclient, ldapsearch
  Detecta: usuarios/grupos, política de contraseñas, permisos SMB,
           cuentas privilegiadas, SPNs, delegaciones RBCD,
           contraseñas almacenadas en campos de descripción

  Incluye: Password Spraying — prueba una contraseña contra todos
           los usuarios (avisa del riesgo de bloqueo de cuentas)


  [3] Kerberoasting / AS-REP Roasting
  ─────────────────────────────────────────────────────────────────────
  Explota debilidades del protocolo Kerberos para capturar hashes de
  contraseñas que se crackean offline.

  Herramientas: impacket (GetNPUsers, GetUserSPNs), kerbrute
  AS-REP Roasting: cuentas sin pre-autenticación Kerberos
  Kerberoasting:   tickets TGS de cuentas con SPN configurado
  Kerbrute:        enumeración de usuarios válidos + spray Kerberos


  [4] Cracking de hashes
  ─────────────────────────────────────────────────────────────────────
  Recupera la contraseña en texto claro a partir de los hashes
  capturados en otros módulos.

  Herramientas: hashcat (GPU), john the ripper (CPU, fallback)
  Soporta:      NTLM, NTLMv2, AS-REP (krb5asrep), Kerberoast (TGS)
  Método:       diccionario + reglas best64; john si hashcat no crackea

  También puede usarse de forma independiente con cualquier fichero
  de hashes externo.


  [5] Movimiento lateral
  ─────────────────────────────────────────────────────────────────────
  Comprueba hasta dónde se puede llegar con las credenciales obtenidas.

  Herramientas: netexec, impacket-secretsdump, evil-winrm
  Detecta:  acceso administrador local ("Pwn3d!")
  Extrae:   hashes SAM, LSA secrets, base de datos NTDS
  Técnica:  pass-the-hash (sin necesitar la contraseña en texto claro)
  Acceso:   sesión remota interactiva vía WinRM (evil-winrm)


  [6] BloodHound / Rutas de ataque
  ─────────────────────────────────────────────────────────────────────
  Recoge datos completos del dominio y los prepara para BloodHound,
  que muestra gráficamente las rutas para llegar a Domain Admin.

  Herramientas: bloodhound-python, neo4j
  Genera:   ZIP listo para importar en la GUI de BloodHound
  Incluye:  instrucciones paso a paso para arrancar neo4j y BloodHound
  Consultas sugeridas: Shortest Path to DA, Kerberoastable to DA,
            Find Computers where Domain Users are Local Admin


  [7] Modo automático
  ─────────────────────────────────────────────────────────────────────
  Ejecuta los módulos 1-6 en secuencia. Pide confirmación explícita
  antes de comenzar.


  [8] Generar informe final
  ─────────────────────────────────────────────────────────────────────
  Consolida todos los resultados en REPORT.md con tabla de resumen,
  duración total y listado de todos los artefactos generados.


ESTRUCTURA DE RESULTADOS
─────────────────────────
Al configurar el objetivo se crea un directorio con esta estructura:

  ad_audit_YYYYMMDD_HHMM/
  ├── audit.log        → log completo con timestamps de toda la sesión
  ├── REPORT.md        → informe consolidado en Markdown
  ├── enum/            → usuarios, grupos, política de contraseñas, LDAP
  ├── smb/             → recursos compartidos y accesos SMB
  ├── kerberos/        → hashes AS-REP y Kerberoast capturados
  ├── lateral/         → dumps SAM, LSA, NTDS, secretsdump
  ├── cracking/        → contraseñas crackeadas (hashcat / john)
  └── bloodhound/      → datos para BloodHound (.zip)


HERRAMIENTAS NECESARIAS
───────────────────────
El script detecta qué herramientas están disponibles y salta los
módulos que no pueden ejecutarse. Usa --check para ver el estado.

  Herramienta           Instalación
  ────────────────────  ─────────────────────────────────────────────
  rpcclient             apt install samba-common-bin
  smbclient             apt install smbclient
  smbmap                apt install smbmap
  ldapsearch            apt install ldap-utils
  netexec               pip install netexec
  impacket              pip install impacket
  bloodhound-python     pip install bloodhound
  hashcat               apt install hashcat
  john                  apt install john
  evil-winrm            gem install evil-winrm
  kerbrute              https://github.com/ropnop/kerbrute/releases
  neo4j                 apt install neo4j

  Wordlists recomendadas:
    /usr/share/wordlists/rockyou.txt    →  apt install wordlists
    /usr/share/seclists/Usernames/...   →  apt install seclists


AUTENTICACIÓN SOPORTADA
───────────────────────
  · Sin credenciales          → módulo 1 únicamente
  · Usuario + contraseña      → todos los módulos
  · Hash NTLM (formato NT)    → pass-the-hash en todos los módulos


CAMBIOS EN v3 RESPECTO A v2
────────────────────────────
  - Bug corregido: error en línea 52 al ejecutar con sh/dash
      Causa:    declare -A (arrays asociativos) no soportado por sh
      Solución: reemplazado por función get_install_hint() con case/esac

  - Guard al inicio: si se usa sh en vez de bash, el script aborta
    con un mensaje de error claro indicando cómo ejecutarlo bien

  - Variables globales mejoradas con := para no sobreescribirse
    al hacer source del script desde otro entorno

  - Validado con 33 tests automatizados: sintaxis, shellcheck,
    guard sh/dash, todas las ramas de get_install_hint, detección
    de variantes impacket, y ejecución real de todos los módulos


AVISO LEGAL
───────────
Esta herramienta realiza técnicas de auditoría ofensiva. Su uso sin
autorización expresa y por escrito del propietario del sistema objetivo
es ilegal según el Código Penal español (art. 197 bis y 264) y la
normativa equivalente en otros países.

  - Úsala SOLO en entornos que controles o para los que tengas permiso.
  - HackTheBox, TryHackMe y redes propias son entornos seguros y válidos.
  - El autor no se hace responsable del uso indebido de esta herramienta.

================================================================================
  ad_audit.sh v3.0 — Sr.Robot Labs
  Antonio José Romero Fdez.-Giro
================================================================================
