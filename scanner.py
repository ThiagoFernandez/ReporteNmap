import socket

import nmap
from colorama import Fore, Style, init

import auxiliar


def show_reporte(reporte):
    for key, value in reporte.items():
        if key == "ports":
            for p in value:
                print(f"port:{p[0]} - version: {p[1]}")
        else:
            print(f"{key} - {value}")


def filter_args(opt):
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

    try:
        host = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"{Fore.RED}Host inválido: {target}{Style.RESET_ALL}")
        return

    nm = nmap.PortScanner()

    resultado = nm.scan(host, str(ports), arguments=choose_arguments())
    print(resultado)

    reporte = {
        "host": host,
        "ports": None,
    }  # host, estado, puertos abiertos con servicio y versión
    host_state = nm[host].state()
    if host_state == "up":
        open_ports = []
        for port in nm[host]["tcp"].keys():
            port_state = nm[host]["tcp"][port]["state"]
            if port_state == "open":
                name = nm[host]["tcp"][port].get("name", "desconocido/unknown")
                version = nm[host]["tcp"][port].get("version", "desconocida/unknown")

                open_ports.append([name, version])

        reporte["ports"] = open_ports

    show_reporte(reporte)
    auxiliar.save_file(reporte)
