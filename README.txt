================================================================================
  AD-AUDIT.SH v2.0 — README
  Sr.Robot Labs | Antonio José Romero Fdez.-Giro
  USO EXCLUSIVO EN ENTORNOS CON AUTORIZACIÓN ESCRITA
================================================================================


¿QUÉ ES ESTE SCRIPT?
────────────────────
ad_audit.sh es una herramienta de auditoría de seguridad para entornos
Active Directory (AD), escrita en Bash. Permite a un auditor o pentester
analizar de forma ordenada un dominio Windows, desde la recopilación
inicial de información hasta el análisis de rutas de ataque avanzadas.

Está pensada para usarse en:
  - Laboratorios de práctica (HTB, TryHackMe, laboratorio propio)
  - Auditorías de seguridad con autorización escrita del cliente
  - Entornos de formación en ciberseguridad ofensiva


¿PARA QUÉ SIRVE?
────────────────
En un entorno corporativo basado en Windows, Active Directory es el
servicio central que gestiona usuarios, contraseñas, permisos y accesos.
Esta herramienta automatiza las comprobaciones más habituales que realiza
un auditor para detectar configuraciones inseguras, cuentas vulnerables
y posibles vías de escalada de privilegios.

En pocas palabras: ayuda a responder la pregunta "¿podría un atacante
comprometer este dominio, y por dónde?"


MÓDULOS DISPONIBLES
───────────────────
El script está dividido en 6 módulos independientes. Puedes ejecutarlos
por separado o todos en secuencia (modo automático).

  MÓDULO 1 — Enumeración anónima
  ┌─────────────────────────────────────────────────────────────────────┐
  │ Recopila información del dominio SIN necesitar credenciales.        │
  │ Prueba si el servidor expone datos a cualquier usuario de la red.   │
  │                                                                     │
  │ Herramientas: rpcclient, smbmap, smbclient, ldapsearch, netexec    │
  │ Detecta: nombre de dominio, usuarios, grupos, recursos compartidos  │
  └─────────────────────────────────────────────────────────────────────┘

  MÓDULO 2 — Enumeración con credenciales + LDAP profundo
  ┌─────────────────────────────────────────────────────────────────────┐
  │ Con un usuario válido, extrae información detallada del directorio. │
  │                                                                     │
  │ Herramientas: netexec, smbmap, rpcclient, ldapsearch               │
  │ Detecta: lista completa de usuarios y grupos, políticas de          │
  │          contraseñas, permisos en carpetas compartidas, cuentas     │
  │          con privilegios especiales, delegaciones de control,       │
  │          y contraseñas almacenadas en campos de descripción.        │
  │                                                                     │
  │ También incluye: Password Spraying (prueba una contraseña común     │
  │ contra todos los usuarios para encontrar accesos válidos).          │
  └─────────────────────────────────────────────────────────────────────┘

  MÓDULO 3 — Kerberoasting y AS-REP Roasting
  ┌─────────────────────────────────────────────────────────────────────┐
  │ Explota debilidades en el protocolo de autenticación Kerberos       │
  │ para obtener hashes de contraseñas que luego se pueden crackear.   │
  │                                                                     │
  │ Herramientas: impacket (GetNPUsers, GetUserSPNs), kerbrute          │
  │                                                                     │
  │ AS-REP Roasting: ataca cuentas que no requieren pre-autenticación. │
  │ Kerberoasting:   solicita tickets de servicio (TGS) de cuentas     │
  │                  con SPN configurado.                               │
  │ Kerbrute:        enumera usuarios válidos del dominio y realiza     │
  │                  ataques de spray a nivel Kerberos.                 │
  └─────────────────────────────────────────────────────────────────────┘

  MÓDULO 4 — Cracking de hashes
  ┌─────────────────────────────────────────────────────────────────────┐
  │ Intenta recuperar contraseñas en texto claro a partir de los        │
  │ hashes obtenidos en otros módulos.                                  │
  │                                                                     │
  │ Herramientas: hashcat (GPU), john the ripper (CPU)                 │
  │                                                                     │
  │ Soporta: NTLM, NTLMv2, AS-REP ($krb5asrep), Kerberoast ($krb5tgs) │
  │ Método: diccionario + reglas (best64) con fallback automático       │
  │         de hashcat a john si no hay resultados.                     │
  └─────────────────────────────────────────────────────────────────────┘

  MÓDULO 5 — Movimiento lateral
  ┌─────────────────────────────────────────────────────────────────────┐
  │ Comprueba hasta dónde se puede llegar con las credenciales          │
  │ obtenidas, e intenta acceder a sistemas del dominio.               │
  │                                                                     │
  │ Herramientas: netexec, impacket-secretsdump, evil-winrm            │
  │                                                                     │
  │ Detecta: acceso de administrador local ("Pwn3d!")                  │
  │ Extrae: hashes del SAM, LSA secrets, NTDS (base de datos de AD)   │
  │ Acceso: sesión remota interactiva via WinRM (evil-winrm)           │
  │ Técnica: pass-the-hash (usar hash NTLM sin conocer la contraseña)  │
  └─────────────────────────────────────────────────────────────────────┘

  MÓDULO 6 — BloodHound / Análisis de rutas de ataque
  ┌─────────────────────────────────────────────────────────────────────┐
  │ Recoge datos completos del dominio y los prepara para su            │
  │ visualización en BloodHound, una herramienta gráfica que muestra   │
  │ las rutas más cortas para llegar a ser Domain Admin.               │
  │                                                                     │
  │ Herramientas: bloodhound-python, neo4j                             │
  │ Genera: fichero ZIP listo para importar en la GUI de BloodHound    │
  │ Incluye instrucciones detalladas para arrancar neo4j y BloodHound  │
  └─────────────────────────────────────────────────────────────────────┘


MODOS DE USO
────────────

  1. Menú interactivo (recomendado)
     Ejecuta el script sin argumentos y navega por el menú:

       chmod +x ad_audit.sh
       ./ad_audit.sh

     Opciones del menú:
       [0]  Configurar IP, dominio y credenciales del objetivo
       [c]  Ver qué herramientas están instaladas (y cómo instalar las que falten)
       [1]  Enumeración anónima
       [2]  Enumeración con credenciales + LDAP profundo
       [3]  Kerberoasting / AS-REP Roasting
       [4]  Cracking de hashes
       [5]  Movimiento lateral
       [6]  BloodHound
       [7]  Modo automático (ejecuta todo en orden)
       [8]  Generar informe final en Markdown
       [q]  Salir


  2. Modo automático
     Ejecuta todos los módulos en secuencia sin intervención manual:

       ./ad_audit.sh --auto


  3. Solo verificar herramientas instaladas
     Muestra qué herramientas están disponibles y cuáles faltan,
     con el comando exacto para instalar cada una:

       ./ad_audit.sh --check


RESULTADOS Y FICHEROS GENERADOS
────────────────────────────────
Al configurar el objetivo, el script crea un directorio de salida con
la siguiente estructura:

  ad_audit_YYYYMMDD_HHMM/
  ├── audit.log               → log completo con timestamps
  ├── REPORT.md               → informe consolidado en Markdown
  ├── enum/                   → resultados de enumeración (usuarios, grupos, LDAP...)
  ├── smb/                    → shares y accesos SMB
  ├── kerberos/               → hashes AS-REP y Kerberoast
  ├── lateral/                → dumps SAM, LSA, NTDS, secretsdump
  ├── cracking/               → contraseñas crackeadas (hashcat/john)
  └── bloodhound/             → datos para BloodHound (.zip)


HERRAMIENTAS NECESARIAS
───────────────────────
El script funciona con las herramientas que estén instaladas y salta
automáticamente los módulos que no pueden ejecutarse. Usa la opción
[c] del menú o ./ad_audit.sh --check para ver el estado de cada una.

  Herramienta           Instalación
  ────────────────────  ──────────────────────────────────────────
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
    /usr/share/wordlists/rockyou.txt       (apt install wordlists)
    /usr/share/seclists/Usernames/...      (apt install seclists)


AUTENTICACIÓN SOPORTADA
───────────────────────
El script acepta tres modos de autenticación:

  · Sin credenciales       → solo módulo de enumeración anónima
  · Usuario + contraseña   → todos los módulos
  · Hash NTLM (LM:NT)      → pass-the-hash en todos los módulos


AVISO LEGAL
───────────
Este script es una herramienta de seguridad ofensiva. Su uso sin
autorización expresa y por escrito del propietario del sistema objetivo
es ilegal en la mayoría de jurisdicciones.

  - Úsalo SOLO en entornos que controles o para los que tengas permiso.
  - Laboratorios CTF (HackTheBox, TryHackMe) y redes propias son seguros.
  - El autor no se hace responsable del uso indebido de esta herramienta.

================================================================================
  ad_audit.sh v2.0 — Sr.Robot Labs
  Antonio José Romero Fdez.-Giro
================================================================================
