# MKAnalytics — paquete de despliegue

<img width="1923" height="917" alt="image" src="https://github.com/user-attachments/assets/ad17ed18-2ffc-468a-bfed-f0debaf1a29d" />


Contiene solo el código de la app (`app.py`, `static/`) y la unidad systemd de
referencia. **No incluye `data/`**: si ya tienes una instalación en marcha,
descomprimir este zip encima no toca tus logs ni tu configuración.

## Instalar / actualizar en el servidor

```bash
# 1) copiar el código (crea /opt/mkanalytics si no existe)
sudo mkdir -p /opt/mkanalytics
sudo unzip -o mkanalytics.zip -d /tmp/mkanalytics-new
sudo rsync -a --exclude 'deploy' --exclude 'README.md' \
    /tmp/mkanalytics-new/mkanalytics/ /opt/mkanalytics/

# 2) dependencias (solo la primera vez, o si cambian)
sudo python3 -m pip install -r /opt/mkanalytics/requirements.txt

# 3) unidad systemd (solo la primera vez; si ya la tenías, revisa el puerto)
sudo cp /opt/mkanalytics/deploy/mkanalytics.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now mkanalytics

# actualizaciones posteriores: repite el paso 1 y luego
sudo systemctl restart mkanalytics
```

## Puerto syslog: 4501

El receptor UDP escucha ahora en **4501** por defecto (antes 4500, que
coincide con IPsec NAT-T). Si vienes de una instalación anterior:

- Actualiza la regla del MikroTik: `remote-port=4501` en
  `/system logging action`.
- Si ya tenías `/etc/systemd/system/mkanalytics.service` con `--syslog-port
  4500`, sustitúyelo por el de este paquete (`deploy/mkanalytics.service`)
  o edita el `ExecStart` a mano.
- El firewall del servidor debe permitir UDP 4501 entrante desde el router
  (y ya no hace falta abrir el 4500, salvo que también uses IPsec ahí).

## Novedades de esta versión

- **Avisos de carga**: la tabla de logs, la analítica, las reglas y Ajustes
  muestran un "Cargando…" con spinner cuando una petición tarda más de
  300 ms (búsquedas grandes, históricos, etc.).
- **Borrar segmentos individuales** desde Ajustes → Segmentos (con
  confirmación; es irreversible, no hay backups).
- **Contador de búfer**: la píldora de cabecera y Ajustes → Estado muestran
  cuántos logs están escritos pero aún sin volcar a disco.
- **Refresco automático configurable**: el indicador «En vivo» de la
  cabecera ahora es un desplegable con 4 opciones — cada 10 s, cada 30 s,
  cada 1 min, o desactivado. Se recuerda entre sesiones (localStorage del
  navegador). Al desactivarlo, la tabla y la analítica solo se actualizan
  al cambiar de página/pestaña o pulsar «Actualizar»; el contador de
  cabecera y el resto de píldoras se siguen actualizando cada 2 s aparte.
- Pestaña **Guardado** renombrada a **Ajustes**.

## Estructura del zip

```
mkanalytics/
├── app.py
├── requirements.txt
├── static/
│   ├── index.html
│   ├── app.js
│   └── style.css
├── deploy/
│   └── mkanalytics.service      # copiar a /etc/systemd/system/
└── README.md
```
