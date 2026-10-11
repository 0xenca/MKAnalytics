# MKAnalytics

Visor y analizador de logs de **MikroTik RouterOS** autoalojado. El router envía
sus logs por syslog (UDP) a un servidor Linux y MKAnalytics los guarda, los
muestra en una web para buscarlos y filtrarlos, y saca estadísticas
(IPs, puertos, flujos, picos de tráfico…).

<img width="1923" height="917" alt="Captura de MKAnalytics" src="https://github.com/user-attachments/assets/ad17ed18-2ffc-468a-bfed-f0debaf1a29d" />

## Cómo funciona

```
MikroTik ──syslog UDP :4501──▶ app.py ──▶ data/logs/*.ndjson(.gz)
                                  │
                                  └──web :8080──▶ navegador (Logs · Analítica · Reglas · Ajustes)
```

1. **Recepción.** `app.py` escucha en UDP (por defecto **4501**). Cada línea que
   llega se interpreta: topics, nivel, y en los logs de firewall cadena,
   interfaces, protocolo, IPs/puertos de origen y destino, MAC, estado de
   conexión, NAT y longitud. La hora guardada es la de recepción (el formato
   por defecto de RouterOS no lleva fecha). También acepta syslog BSD
   (`<PRI>Mmm dd hh:mm:ss host …`).
2. **Reglas al recibir.** Antes de guardar se aplican tus reglas: *descartar*
   (no se guarda), *ocultar* (se guarda pero no se ve por defecto) o *resaltar*
   (se colorea en la tabla).
3. **Almacenamiento.** Los logs se escriben en `data/logs/current.ndjson`
   (una línea JSON por log) y se vuelcan a disco cada pocos segundos. Al
   llegar al tamaño o la antigüedad de rotación (32 MB / 24 h por defecto), el
   segmento se cierra, se renombra `seg-<desde>-<hasta>-<último id>-<nº>.ndjson`
   y se comprime con gzip. No hay tope de logs: el límite es el disco, con una
   protección configurable (% libre mínimo → borrar los segmentos más antiguos o
   pausar la captura) y retención opcional por días.
4. **Consulta.** La web pide a la API solo lo que necesita: la tabla abre los
   segmentos de la página que miras y la analítica reutiliza lo ya calculado
   por segmento, así que funciona con millones de logs.

La configuración (ajustes, reglas, búsquedas guardadas) vive en
`data/config.json`.

## Tutorial

### 1. Instalar en el servidor

Requisitos: Linux con Python 3.9+.

```bash
git clone https://github.com/0xenca/MKAnalytics.git /opt/mkanalytics
sudo python3 -m pip install -r /opt/mkanalytics/requirements.txt
sudo python3 -m pip install orjson          # opcional: lectura del histórico ~2× más rápida

# servicio systemd
sudo cp /opt/mkanalytics/deploy/mkanalytics.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now mkanalytics
```

Para probar sin instalar: `python3 app.py` (UDP 4501, web en
`http://IP_DEL_SERVIDOR:8080`).

Opciones (`app.py --help`): `--syslog-port`, `--web-port`, `--web-host`,
`--syslog-host`, `--data-dir`, o las variables `SYSLOG_PORT`, `WEB_PORT`,
`WEB_HOST`, `SYSLOG_HOST`, `DATA_DIR`.

**Seguridad.** Si la web va a ser accesible desde la red, activa la
autenticación definiendo `LOGVIEW_USER` y `LOGVIEW_PASS` en el servicio
(`Environment=…` en la unidad systemd), o escucha solo en local
(`--web-host 127.0.0.1`) detrás de un proxy inverso con HTTPS.

Firewall del servidor: abre **UDP 4501** solo desde la IP del router y el
puerto web solo a quien deba verlo.

### 2. Configurar el MikroTik

```
/system logging action
add name=logviewer target=remote remote=IP_DEL_SERVIDOR remote-port=4501

/system logging
add topics=firewall action=logviewer
# opcional: más topics
add topics=system,error,warning action=logviewer
```

Las reglas de firewall solo generan log si tienen `log=yes` (recomendable
`log-prefix=` para distinguirlas luego):

```
/ip firewall filter set [find comment="drop wan"] log=yes log-prefix=DROP-WAN
```

En la cabecera de la web, la píldora **UDP :4501 escuchando** y el contador de
logs/s confirman que llegan datos.

### 3. Usar la web

- **Logs**: tabla en vivo. Clic en una IP, puerto o interfaz → filtra por ese
  valor; Mayús + clic → lo excluye. Clic en una fila → detalle y botón para
  crear una regla a partir de los campos marcados. Vista tabla o texto crudo.
- **Búsqueda**: los términos se combinan con Y.

  | Ejemplo | Significado |
  |---|---|
  | `192.168.0.10` | texto en cualquier parte del mensaje |
  | `"TCP (SYN)"` | frase exacta |
  | `-udp` | excluir |
  | `src:10.0.0.0/8` | IP o red de origen (`dst:`, `ip:` = cualquiera) |
  | `dport:53,443` | lista de valores (`sport:`, `port:`) |
  | `len:>100` | comparación numérica |
  | `in=bridge state!=new` | igualdad exacta / distinto |
  | `/SYN.*ACK/` | expresión regular |

  Las expresiones regulares usan RE2 (sin distinguir mayúsculas): siempre
  tardan un tiempo proporcional al texto, así que un patrón malicioso no puede
  colgar el servidor. No admiten referencias hacia atrás (`\1`) ni
  lookahead/lookbehind.

  Las búsquedas se pueden guardar. El panel **Avanzado** permite construir
  condiciones sin escribir la sintaxis.
- **Analítica**: línea temporal (clic en una barra para acotar), actividad por
  hora, picos, tops de IPs, puertos, flujos, protocolos, interfaces… Todo
  respeta el filtro y el rango de tiempo activos.
- **Reglas**: resaltar, ocultar o descartar logs según condiciones, con
  prueba sobre las últimas 24 h antes de guardar.
- **Ajustes**: estado del disco y previsión de llenado, rotación, compresión,
  retención, exportar/importar (JSON/CSV), borrados, lista de segmentos
  (descargar, borrar, **compactar**).

## Actualizar

```bash
cd /opt/mkanalytics && sudo git pull
sudo systemctl restart mkanalytics
```

`data/` no está en el repositorio: actualizar no toca tus logs ni tu
configuración.

## Tests

```bash
pip install -r requirements-dev.txt
python -m playwright install chromium   # solo para la prueba en navegador
python -m pytest                        # o --ignore=tests/test_e2e.py para saltarla
```

Cubren el parser, el lenguaje de búsqueda y las reglas, el almacén (captura,
rotación, compresión, borrados, importación, retención, guard de disco), el
motor de consultas y la analítica (comparados con una implementación de
referencia), la compactación (incluido un corte a mitad), la API HTTP, el
receptor UDP y una prueba completa en Chromium. GitHub Actions los ejecuta en
cada push y PR con Python 3.9–3.13.

## Cambios entre versiones

Resumen; el detalle de cada versión está en
[Releases](https://github.com/0xenca/MKAnalytics/releases).

**Actual**
- Seguridad: las regex de búsquedas y reglas se evalúan con RE2 (tiempo
  lineal), corrigiendo la alerta de CodeQL «Regular expression injection»
  (ReDoS). Nueva dependencia: `google-re2`.
- Rendimiento con millones de logs: la tabla y la analítica ya no recorren
  todo el histórico en cada refresco. Las búsquedas largas muestran
  resultados en ≤ 3 s («≥ N coincidencias · contando…») y terminan solas;
  la analítica avanza por tandas y después se refresca en décimas. En rangos
  grandes, las IP distintas son una estimación (≈).
- Botón **Compactar segmentos** (Ajustes → Segmentos): fusiona segmentos
  pequeños hasta el tamaño/antigüedad de rotación, en segundo plano y seguro
  ante cortes.

**Anteriores**
- Puerto syslog por defecto **4501** (antes 4500, que choca con IPsec NAT-T):
  actualiza `remote-port` en el router y el `ExecStart` del servicio.
- Avisos de «Cargando…», borrar segmentos individuales, contador de búfer,
  refresco automático configurable (10 s / 30 s / 1 min / off), pestaña
  Guardado renombrada a Ajustes.
