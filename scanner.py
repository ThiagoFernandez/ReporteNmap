import socket
from ast import arg
from datetime import datetime

import nmap
from colorama import Fore, Style, init
from nmap.nmap import PortScannerError

import auxiliar


def show_reporte(reporte):
    for key, value in reporte.items():
        if key == "ports":
            for p in value:
                print(f"port:{p[0]} - version: {p[1]}")
        else:
            print(f"{key} - {value}")


def filter_args(opt):  # podria ser una tupla y listo
    if "100" in opt:
        idx = opt.index("1")
        return opt[: idx + 3]
    idx = opt.index(" ")
    return opt[:idx]


def choose_arguments():
    options = [
        "-sS SYN SCAN",
        "-sT TCP CONNECT",
        "-sU UDP SCAN",
        "-sV VERSION DETECTION",
        "-O OS DETECTION",
        "-A AGGRESSIVE: OS+VERSION+SCRIPTS",
        "-T4 AGGRESSIVE TIMING",
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
        elif "p" in options[rt - 1]:
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

    args = choose_arguments()

    try:
        nm = nmap.PortScanner()
        nm.scan(target, str(ports), arguments=args)
    except PortScannerError as p:
        print(f"{Fore.RED}No se encontro nmap: {p}{Style.RESET_ALL}")
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
        # Por cada IP que respondió, agregás esto a reporte["hosts"]:
        host_info = {
            "ip": ip,  # de nm.all_hosts()
            "hostname": nm[ip].hostname(),  # str, puede ser ""
            "hostnames": nm[ip].hostnames(),  # list[dict] — PTRs completos
            "state": nm[ip].state(),  # "up" | "down" | ...
            "protocols": nm[ip].all_protocols(),  # ["tcp", "udp", ...]
            # Opcionales — solo si nmap los devuelve
            "os": {
                "name": nm[ip]["osmatch"]["name"],
                "accuracy": f"{nm[ip]['osmatch']['accuracy']}%",
            }
            if "-O" in args
            else None,  # solo si pediste -O y matcheó algo
            "uptime": {
                "days": nm[host]["osclass"][0]["uptime"]["days"],
                "lastBoot": nm[host]["osclass"][0]["uptime"]["last_boot"],
            }
            if "-O" in args and "uptime" in nm[ip]['osclass']
            else None,  # solo si -O lo detectó
            "puertos": [],  # lista de dicts (ver abajo)
        }
        reporte["hosts"].append(host_info)

    # Si nmap detectó OS, llenás "os":
    if nm[ip].get("osmatch"):
        mejor = nm[ip]["osmatch"][0]  # el de mayor accuracy
        host_info["os"] = {
            "name": mejor["name"],  # ej: "Linux 4.15 - 5.6"
            "accuracy": mejor["accuracy"],  # str: "92"
            "osclass": mejor.get("osclass"),  # lista con vendor/family/generation
        }

    # Si nmap devolvió uptime:
    if nm[ip].get("uptime"):
        host_info["uptime"] = {
            "seconds": nm[ip]["uptime"].get("seconds"),
            "lastboot": nm[ip]["uptime"].get("lastboot"),
        }

    # Por cada puerto en cada protocolo, agregás esto a host_info["puertos"]:
    puerto_info = {
        "port": port,  # int
        "protocol": proto,  # "tcp" | "udp"
        "state": nm[ip][proto][port].get("state"),
        "reason": nm[ip][proto][port].get("reason"),  # "syn-ack", "conn-refused", etc.
        "name": nm[ip][proto][port].get("name"),  # "ssh", "http", ...
        "product": nm[ip][proto][port].get("product"),  # "OpenSSH", "Apache httpd"
        "version": nm[ip][proto][port].get("version"),  # "8.9p1"
        "extrainfo": nm[ip][proto][port].get(
            "extrainfo"
        ),  # "Ubuntu Linux; protocol 2.0"
        "cpe": nm[ip][proto][port].get("cpe"),  # útil si después agregás CVE lookup
        "conf": nm[ip][proto][port].get("conf"),  # confianza (1-10)
    }

    show_reporte(reporte)
    auxiliar.save_file(reporte)
