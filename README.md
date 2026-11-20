# Metasploitscapy

Monitor pasivo de red para ayudar a detectar posibles escaneos de puertos en una red propia o autorizada. Examina metadatos de paquetes IPv4 TCP/UDP y alerta cuando una misma dirección de origen contacta muchos puertos destino distintos en el mismo host durante una ventana de tiempo.

No envía paquetes, ejecuta exploits ni guarda capturas o cargas útiles. Scapy recibe los paquetes temporalmente; el programa solo procesa direcciones IP y puertos, y muestra alertas en la terminal.

## Requisitos

- Python 3.10 o posterior.
- Scapy y permisos del sistema para capturar tráfico en la interfaz elegida (en Linux, normalmente se requiere `sudo`).

Instala la dependencia:

```sh
python3 -m pip install -r requirements.txt
```

## Uso

Indica explícitamente la interfaz de la red que tienes autorización para supervisar:

```sh
sudo python3 -m metasploitscapy --interface eth0
```

El umbral predeterminado es 20 puertos destino distintos dentro de 60 segundos. Puedes ajustarlo:

```sh
sudo python3 -m metasploitscapy --interface eth0 --threshold 10 --window 30
```

Pulsa `Ctrl+C` para detener la supervisión. Las alertas son heurísticas, no confirman por sí solas un ataque.

## Pruebas

```sh
python3 -m unittest discover -s tests
```

## Pruebas web con OWASP ZAP

OWASP ZAP es un escáner de seguridad para aplicaciones web, no un antivirus ni un detector de malware. Este repositorio todavía no incluye una aplicación web. Cuando tengas una aplicación propia ejecutándose localmente, puedes usar el análisis **Baseline** de ZAP, que rastrea la aplicación y ejecuta reglas pasivas sin realizar ataques activos.

Requiere Docker en Linux y una aplicación local que escuche en `127.0.0.1`:

```sh
python3 -m metasploitscapy.zap_baseline http://127.0.0.1:8080
```

El lanzador acepta únicamente direcciones IPv4 de loopback (`127.0.0.0/8`) con esquema HTTP o HTTPS, para evitar dirigir el análisis a sistemas remotos. ZAP y Docker deben estar instalados y Docker debe estar en ejecución. Revisa los avisos del análisis; no constituyen una garantía de seguridad.
etujexejEYapacstiolpsateMuB