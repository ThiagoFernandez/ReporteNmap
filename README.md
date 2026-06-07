# Reporte de Seguridad de Red con Nmap

Herramienta de línea de comandos en Python que escanea hosts, subredes o dominios usando el motor de Nmap y genera reportes de seguridad estructurados en **Markdown** y **JSON**. Detecta puertos abiertos, servicios y versiones, sistema operativo, y enriquece los resultados con vulnerabilidades conocidas (CVEs) consultadas en la NVD API.

Proyecto de la Fase 2 de mi roadmap de ciberseguridad / redes.

## Características

- Escaneo de IP, hostname o subred CIDR, o múltiples targets desde un archivo `.txt`
- Menú interactivo para elegir el tipo de scan (SYN, TCP connect, UDP, version detection, OS detection, aggressive, banner grabbing, top-ports, etc.)
- Detección de servicios y versiones (`-sV`) y de sistema operativo (`-O`)
- Reporte en Markdown con tabla de puertos, info de host, OS y uptime
- Sección de **servicios destacados**: riesgos de seguridad por servicio expuesto (FTP, SSH, Telnet, HTTP, RDP, SMB, MySQL...)
- Sección de **recomendaciones** accionables
- Lookup de **CVEs conocidos** vía NVD API 2.0, con caché y rate limiting
- Exportación dual: Markdown (`.md`) y JSON (`.json`)
- Salida en consola con colores

## Requisitos

- Python 3.10 o superior
- **Nmap** instalado en el sistema (el paquete de Python es solo un wrapper, no incluye el binario)
  - Linux: `sudo apt install nmap`
  - Windows: instalar [Nmap](https://nmap.org/download.html) + [Npcap](https://npcap.com/)
- Dependencias de Python:

```bash
pip install python-nmap tabulate colorama requests
```

## Instalación
```bash
git clone https://github.com/ThiagoFernandez/ReporteNmap.git
cd <repo>
pip install -r requirements.txt
```

## Uso

```bash
python main.py <target> [rango_de_puertos]
```

Ejemplos:

```bash
python main.py scanme.nmap.org 1-1024
python main.py 192.168.1.1
python main.py 192.168.1.0/24 1-100
python main.py targets.txt 1-1024
```

Al ejecutar, un menú interactivo permite elegir los flags de Nmap. El reporte se guarda como `reporte_<target>_<timestamp>.md` y `reporte_<target>_<timestamp>.json` en el directorio actual.

### Archivo de targets

Un target por línea. Las líneas vacías y las que empiezan con `#` se ignoran:

```
# Servidores del lab
192.168.1.1
scanme.nmap.org
10.0.0.0/24
```

El rango de puertos y los flags elegidos en el menú se aplican a todos los targets del archivo. Si un target falla (DNS, host caído), el resto del lote continúa.

### API key de NVD (opcional)

El lookup de CVEs funciona sin API key, pero el rate limit es lento (~6 s por servicio único). Con una API key gratuita baja a ~0.6 s:

```bash
# Linux / Mac
export NVD_API_KEY="tu_key"

# Windows PowerShell
$env:NVD_API_KEY="tu_key"
```

Se solicita gratis en https://nvd.nist.gov/developers/request-an-api-key

## Estructura del proyecto

```
ReporteNmap/
├── main.py        # punto de entrada
├── scanner.py     # scan, parseo del resultado, renderers (md/json/consola), lookup de CVEs
└── auxiliar.py    # validación de argumentos, carga de targets, escritura de archivos
```

El flujo interno separa las responsabilidades en capas:

```
nmap → parseo (dict normalizado) → enriquecimiento (CVEs) → renderers (md / json / consola) → writer
```

## Notas

- La detección de OS (`-O`) y el SYN scan (`-sS`) requieren privilegios de administrador / root (usan raw sockets). En Windows, ejecutar la terminal **como Administrador**.
- El lookup de CVEs solo se ejecuta si se eligió `-sV` o `-A`: sin detección de versiones no hay CPE para consultar.
- El reporte se genera incluso si el host está caído o no responde (queda registrado como tal).

## Aviso legal

Esta herramienta es para uso educativo y para escanear **únicamente** sistemas propios o sobre los que se cuente con autorización explícita. Escanear redes o hosts ajenos sin permiso puede ser ilegal según la jurisdicción. El autor no se responsabiliza por el uso indebido.
