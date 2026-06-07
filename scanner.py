import os
import time
from datetime import datetime

import nmap
import requests
from colorama import Fore, Style, init
from nmap.nmap import PortScannerError
from tabulate import tabulate

import auxiliar

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.environ.get("NVD_API_KEY")  # None si no está seteada
_cache_cve = {}  # cache por CPE: no repetir consultas


def cpe22_a_23(cpe) -> str | None:
    """nmap emite CPE 2.2 URI; NVD 2.0 quiere CPE 2.3 formatted string."""
    if isinstance(cpe, list):  # nmap a veces devuelve lista
        cpe = cpe[0] if cpe else None
    if not cpe or not cpe.startswith("cpe:/"):
        return None
    partes = cpe[len("cpe:/") :].split(":")  # ["a","openbsd","openssh","8.9"]
    partes += ["*"] * (11 - len(partes))  # rellenar a 11 campos
    return "cpe:2.3:" + ":".join(partes[:11])


def parsear_cve(v: dict) -> dict:
    cve = v["cve"]
    desc = next(
        (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
        "sin descripcion",
    )
    score = "N/A"
    metrics = cve.get("metrics", {})
    for clave in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):  # nuevo -> viejo
        if metrics.get(clave):
            score = metrics[clave][0]["cvssData"]["baseScore"]
            break
    return {"id": cve["id"], "score": score, "desc": desc[:120]}


def consultar_cves(cpe23: str) -> list[dict]:
    if cpe23 in _cache_cve:  # cache hit: instant, sin sleep
        return _cache_cve[cpe23]

    params = {"cpeName": cpe23, "resultsPerPage": 20}
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}

    try:
        r = requests.get(NVD_URL, params=params, headers=headers, timeout=15)
        r.raise_for_status()
        cves = [parsear_cve(v) for v in r.json().get("vulnerabilities", [])]
    except requests.RequestException as e:
        print(f"{Fore.RED}NVD fallo para {cpe23}: {e}{Style.RESET_ALL}")
        cves = []  # degradar con gracia

    _cache_cve[cpe23] = cves
    time.sleep(0.6 if NVD_API_KEY else 6)  # respetar rate limit
    return cves


def enriquecer_con_cves(reporte: dict) -> None:
    for host in reporte["hosts"]:
        for p in host["puertos"]:
            if p["state"] != "open":
                continue
            cpe23 = cpe22_a_23(p.get("cpe"))
            if cpe23:
                p["cves"] = consultar_cves(cpe23)


init()
SERVICIOS_CRITICOS = {
    21: {
        "nombre": "FTP",
        "riesgo": "Protocolo sin cifrado; credenciales y datos viajan en texto plano",
        "recomendacion": "Migrar a SFTP o FTPS; deshabilitar si no se usa",
    },
    22: {
        "nombre": "SSH",
        "riesgo": "Acceso remoto activo; objetivo frecuente de fuerza bruta",
        "recomendacion": "Deshabilitar login por password (solo claves); considerar cambiar el puerto default",
    },
    23: {
        "nombre": "Telnet",
        "riesgo": "Sin cifrado; toda la sesion es visible para cualquiera en la red",
        "recomendacion": "Reemplazar por SSH y cerrar el puerto 23",
    },
    80: {
        "nombre": "HTTP",
        "riesgo": "Trafico sin cifrar; posible panel de administracion expuesto",
        "recomendacion": "Implementar HTTPS (443) y redirigir 80 a 443",
    },
    3306: {
        "nombre": "MySQL",
        "riesgo": "Base de datos accesible; exposicion de datos sensibles",
        "recomendacion": "Restringir a red interna o localhost; nunca exponer a internet",
    },
    3389: {
        "nombre": "RDP",
        "riesgo": "Escritorio remoto; blanco frecuente de ransomware y fuerza bruta",
        "recomendacion": "Restringir por VPN/firewall, habilitar NLA y MFA",
    },
    445: {
        "nombre": "SMB",
        "riesgo": "File sharing Windows; historico de exploits (EternalBlue)",
        "recomendacion": "Aplicar parches, deshabilitar SMBv1, no exponer a internet",
    },
}


def format_uptime(host):
    segundos = int(host["uptime"]["seconds"])
    dias, resto = divmod(segundos, 86400)
    horas, _ = divmod(resto, 3600)
    return f"{dias}d {horas}h ({segundos}s)"


def generar_markdown(reporte: dict) -> str:
    lineas = []
    lineas.append(f"# Reporte de Seguridad de Red\n")
    lineas.append(f"**Timestamp:** {reporte['timestamp']}  ")
    lineas.append("**Scan info:**")
    for proto, info in reporte["scaninfo"].items():
        if isinstance(info, dict):
            lineas.append(
                f"- `{proto}`: método `{info.get('method', '?')}`, rango `{info.get('services', '?')}`"
            )
        else:
            lineas.append(f"- `{proto}`: {info}")
    lineas.append(f"**Demoro:** {reporte['scanstats']['elapsed']}s  ")
    lineas.append(f"**Target:** {reporte['target_original']}  ")
    lineas.append(f"**Comando:** `{reporte['comando']}`  ")
    lineas.append(f"**TotalHosts:** {reporte['scanstats']['totalhosts']}  ")
    lineas.append(
        f"**UpHosts:** {reporte['scanstats']['uphosts']}/{reporte['scanstats']['totalhosts']}"
    )
    lineas.append(
        f"**DownHosts:** {reporte['scanstats']['downhosts']}/{reporte['scanstats']['totalhosts']}\n"
    )

    lineas.append(f"---\n")
    if not reporte["hosts"]:
        lineas.append("\n*No se encontraron hosts activos para este target.*\n")
        return "\n".join(lineas)

    for host in reporte["hosts"]:
        lineas.append(f"\n## {host['ip']}")
        if host["hostname"]:
            lineas.append(f"**Hostname:** {host['hostname']}")
        nombres = ", ".join(
            h["name"] for h in host["hostnames"]
        )  # lo desempaqueto porque sino queda muy vegano
        lineas.append(f"**Hostnames:** {nombres}")
        lineas.append(f"**Estado:** {host['state']}")
        lineas.append(f"**Protocolos:** {', '.join(host['protocols'])}\n")

        if "os" in host:
            lineas.append(f"\n### Seccion OS\n")
            lineas.append(f"**nombre:** {host['os']['name']}")
            lineas.append(f"**Confianza:** {host['os']['accuracy']}")
            for osc in host["os"]["osclass"]:
                lineas.append(  # lo desempaqueto porque sino queda muy vegano
                    f"- {osc.get('vendor', '?')} {osc.get('osfamily', '?')} "
                    f"(gen: {osc.get('osgen', '?')}, accuracy: {osc.get('accuracy', '?')}%)"
                )

        if "uptime" in host:
            lineas.append(f"\n### Seccion UPTIME\n")
            lineas.append(f"**Uptime:** {format_uptime(host)}")
            lineas.append(f"**Ultimo reinicio(boot):** {host['uptime']['lastboot']}\n")

        # podria hacer un list(host["puertos"].keys()) y listo
        data = []
        if host["puertos"]:
            encabezados = [
                "Puerto",
                "Protocolo",
                "Razon",
                "Estado",
                "Nombre",
                "Producto",
                "Version",
                "Banner",
                "ExtraInfo",
                "CPE",
                "CONF",
            ]
            data = []
            criticos = []  # antes "destacados": ahora alimenta DOS secciones
            for p in host["puertos"]:
                if p["state"] == "open" and p["port"] in SERVICIOS_CRITICOS:
                    criticos.append(p)
                data.append(
                    [
                        p["port"],
                        p["protocol"],
                        p.get("reason") or "desconocido/unknown",
                        p["state"],
                        p["name"] or "?",
                        p.get("product") or "desconocido/unknown",
                        p.get("version") or "desconocido/unknown",
                        p.get("banner") or "desconocido/unknown",
                        p.get("extrainfo") or "desconocido/unknown",
                        p.get("cpe") or "desconocido/unknown",
                        p.get("conf") or "desconocido/unknown",
                    ]
                )

            lineas.append(tabulate(data, headers=encabezados, tablefmt="github"))

            if criticos:
                # Servicios destacados --> el RIESGO
                lineas.append("\n### Servicios destacados\n")
                for p in criticos:
                    info = SERVICIOS_CRITICOS[p["port"]]
                    lineas.append(
                        f"- **{info['nombre']} ({p['port']}):** {info['riesgo']}"
                    )

                # Recomendaciones → la ACCIÓN (qué hacer)
                lineas.append("\n### Recomendaciones\n")
                for p in criticos:
                    info = SERVICIOS_CRITICOS[p["port"]]
                    lineas.append(
                        f"- **{info['nombre']} ({p['port']}):** {info['recomendacion']}"
                    )

                # Vulnerabilidades conocidas (NVD)
                con_cves = [p for p in host["puertos"] if p.get("cves")]
                if con_cves:
                    lineas.append("\n### Vulnerabilidades conocidas (NVD)\n")
                    for p in con_cves:
                        lineas.append(
                            f"\n**{p['port']}/{p['protocol']} — {p.get('name') or '?'}** "
                            f"({len(p['cves'])} CVEs)"
                        )
                        for cve in p["cves"]:
                            lineas.append(
                                f"- `{cve['id']}` (score {cve['score']}): {cve['desc']}"
                            )

        else:
            lineas.append("\n*Sin puertos detectados*\n")

    return "\n".join(lineas)


def show_reporte(reporte):
    # ── Header del scan ──
    print(f"{Fore.CYAN}{'═' * 60}{Style.RESET_ALL}")
    print(f"{Fore.BLUE}REPORTE DE SCAN{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'═' * 60}{Style.RESET_ALL}")
    print(f"Target:    {reporte['target_original']}")
    print(f"Puertos:   {reporte['ports_solicitados']}")
    print(f"Comando:   {reporte['comando']}")
    print(f"Timestamp: {reporte['timestamp']}")

    stats = reporte["scanstats"]
    print(f"Duración:  {stats.get('elapsed', '?')}s")
    print(f"Hosts up:  {stats.get('uphosts', '?')}/{stats.get('totalhosts', '?')}")

    # ── Hosts ──
    if not reporte["hosts"]:
        print(f"\n{Fore.YELLOW}No se encontraron hosts.{Style.RESET_ALL}")
        return

    for host in reporte["hosts"]:
        print(f"\n{Fore.GREEN}─── {host['ip']} ───{Style.RESET_ALL}")
        print(f"Estado: {host['state']}")

        if host["hostname"]:
            print(f"Hostname: {host['hostname']}")

        if "os" in host:
            os_info = host["os"]
            print(f"OS: {os_info['name']} ({os_info['accuracy']}% confianza)")

        if "uptime" in host:
            print(
                f"Uptime: {format_uptime(host)} (ultimo boot: {host['uptime']['lastboot']})"
            )

        # Puertos
        if not host["puertos"]:
            print(f"{Fore.YELLOW}Sin puertos detectados.{Style.RESET_ALL}")
            continue

        print(f"\nPuertos ({len(host['puertos'])}):")
        for p in host["puertos"]:
            color = Fore.GREEN if p["state"] == "open" else Fore.YELLOW
            servicio = p.get("name") or "?"
            producto = p.get("product") or ""
            version = p.get("version") or ""
            extra = f" {producto} {version}".rstrip() if (producto or version) else ""

            print(
                f"  {color}{p['port']:>5}/{p['protocol']:<3}{Style.RESET_ALL} "
                f"{p['state']:<10} {servicio}{extra}"
            )

            if p.get("extrainfo"):
                print(f"         extrainfo: {p['extrainfo']}")
            if p.get("banner"):
                print(f"         banner:    {p['banner']}")


def filter_args(opt):  # podria ser una tupla y listo
    if "100" in opt:
        idx = opt.index("1")
        return opt[: idx + 3]
    idx = opt.index(" ")
    return opt[:idx]


def choose_arguments(mode):

    options = [
        "-sS SYN SCAN",
        "-sT TCP CONNECT",
        "-sU UDP SCAN",
        "-sV VERSION DETECTION",
        "-O OS DETECTION",
        "-A AGGRESSIVE: OS+VERSION+SCRIPTS",
        "-T4 AGGRESSIVE TIMING",
        "--script=banner BANNER GRABBING",
    ]
    if mode == "":
        options += [
            "--top-ports 100 TOP 100 PORTS",
            "-p- ALL THE 65535 PORTS",
            "--open ONLY OPEN PORTS",
        ]
    argmnts = ""
    while True:
        auxiliar.show_options(options)
        rt = auxiliar.validate_number(options)
        if rt == -1:
            break
        elif (
            "p" in options[rt - 1]
            and options[rt - 1] != "--script=banner BANNER GRABBING"
        ):
            result = options[rt - 1]
            options.remove("--top-ports 100 TOP 100 PORTS")
            options.remove("-p- ALL THE 65535 PORTS")
            options.remove("--open ONLY OPEN PORTS")
            argmnts += filter_args(result) + " "
        else:
            argmnts += filter_args(options[rt - 1]) + " "
            options.pop(rt - 1)

    if argmnts == "":
        return "-sS"
    return argmnts


def generar_reporte(target, nm, ports):
    reporte = {
        # ─── Nivel scan ───
        "target_original": target,  # consola
        "ports_solicitados": ports,  # rango solicitado
        "comando": nm.command_line(),  # nmap real, incluye target y flag
        "timestamp": datetime.now().isoformat(),
        "scanstats": nm.scanstats(),  # dict: elapsed, uphosts, downhosts, totalhosts, timestr
        "scaninfo": nm.scaninfo(),  # dict: por protocolo, método y rango de puertos
        # ─── Lista de hosts (1 para target unico, N para subred) ───
        "hosts": [],
    }

    for ip in nm.all_hosts():
        # Campos obligatorios (siempre presentes)
        host_info = {
            "ip": ip,
            "hostname": nm[ip].hostname(),
            "hostnames": nm[ip].hostnames(),
            "state": nm[ip].state(),
            "protocols": nm[ip].all_protocols(),
            "puertos": [],
        }

        # OS: solo si nmap matcheo algo (independiente de que flag mando el user)
        if nm[ip].get("osmatch"):
            mejor = nm[ip]["osmatch"][0]  # el de mayor accuracy
            host_info["os"] = {
                "name": mejor["name"],
                "accuracy": mejor["accuracy"],
                "osclass": mejor.get("osclass"),
            }

        # Uptime: solo si nmap lo devolvió
        if nm[ip].get("uptime"):
            host_info["uptime"] = {
                "seconds": nm[ip]["uptime"].get("seconds"),
                "lastboot": nm[ip]["uptime"].get("lastboot"),
            }

        # Puertos: iterar protocolos efectivos, despues puertos de cada uno
        for proto in nm[ip].all_protocols():
            for port in nm[ip][proto].keys():
                datos = nm[ip][proto][port]  # var para no repetir la cad 8 veces
                host_info["puertos"].append(
                    {
                        "port": port,
                        "protocol": proto,
                        "state": datos.get("state"),
                        "reason": datos.get("reason"),
                        "name": datos.get("name"),
                        "banner": datos.get("script", {}).get("banner"),
                        "product": datos.get("product"),
                        "version": datos.get("version"),
                        "extrainfo": datos.get("extrainfo"),
                        "cpe": datos.get("cpe"),
                        "conf": datos.get("conf"),
                    }
                )

        reporte["hosts"].append(host_info)

    return reporte


def nmap_scan():
    nm = nmap.PortScanner()
    targets, ports = auxiliar.validat_args()
    if targets == -1:
        return

    args = choose_arguments(ports)

    for target in targets:
        print(f"{Fore.CYAN}Escaneando {target} con {args}{Style.RESET_ALL}")
        print(
            f"{Fore.YELLOW}Esto puede tardar varios minutos segun el tamaño del target...{Style.RESET_ALL}"
        )
        try:
            nm.scan(str(target), str(ports), arguments=args)
        except PortScannerError as p:
            print(f"{Fore.RED}Error de nmap: {p}{Style.RESET_ALL}")
            continue
        except KeyboardInterrupt as k:
            print(f"{Fore.YELLOW}Scan cancelado: {k}{Style.RESET_ALL}")
            return

        print(f"{Fore.GREEN}Scan completo.{Style.RESET_ALL}")

        reporte = generar_reporte(target, nm, ports)
        if "-sV" in args or "-A" in args:  # ← gating inteligente
            print(
                f"{Fore.CYAN}Consultando NVD para CVEs (puede tardar)...{Style.RESET_ALL}"
            )
            enriquecer_con_cves(reporte)
        show_reporte(reporte)
        auxiliar.guardar_reporte(generar_markdown(reporte), target, "md")
        auxiliar.guardar_reporte(auxiliar.generar_json(reporte), target, "json")
