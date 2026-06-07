from datetime import datetime

import nmap
from colorama import Fore, Style, init
from nmap.nmap import PortScannerError
from tabulate import tabulate

import auxiliar

init()
SERVICIOS_CRITICOS = {  # cada uno pone lo q quiera aca
    21: ("FTP", "Sin cifrado, credenciales en texto plano"),
    22: ("SSH", "Verificar autenticación por clave, no por contraseña"),
    23: ("Telnet", "Inseguro, reemplazar por SSH"),
    80: ("HTTP", "Sin cifrar, verificar paneles admin expuestos"),
    3306: ("MySQL", "BD expuesta, no debería ser accesible desde internet"),
    3389: ("RDP", "Blanco frecuente, restringir acceso"),
    445: ("SMB", "Verificar patches de EternalBlue"),
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
        lineas.append(
            f"- `{proto}`: método `{info['method']}`, rango `{info['services']}`"
        )
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
            ]  # podria hacer un list(host["puertos"].keys()) y listo
            data = []
            destacados = []
            for p in host["puertos"]:
                if p["state"] == "open" and p["port"] in SERVICIOS_CRITICOS:
                    destacados.append(p)
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

            tabla = tabulate(data, headers=encabezados, tablefmt="github")
            lineas.append(tabla)

            if destacados:
                lineas.append("\n### Servicios destacados\n")
                for p in destacados:
                    nombre, nota = SERVICIOS_CRITICOS[p["port"]]
                    lineas.append(f"- **{nombre} ({p['port']}):** {nota}")

        else:
            lineas.append(f"\n*Sin puertos detectados*\n")

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


def nmap_scan():
    target, ports = auxiliar.validat_args()
    if target == -1:
        return

    args = choose_arguments(ports)

    try:
        nm = nmap.PortScanner()
        nm.scan(target, str(ports), arguments=args)
    except PortScannerError as p:
        print(f"{Fore.RED}Error de nmap: {p}{Style.RESET_ALL}")
        return
    except KeyboardInterrupt as k:
        print(f"{Fore.YELLOW}Scan cancelado: {k}{Style.RESET_ALL}")
        return

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

    show_reporte(reporte)
    markdown = generar_markdown(reporte)
    auxiliar.guardar_reporte(markdown, target, "md")
    auxiliar.guardar_reporte(markdown, target, "json")
