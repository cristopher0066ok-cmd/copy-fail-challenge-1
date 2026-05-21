# Reporte Técnico: CVE-2026-31431 (Copy Fail)

## Resumen
Vulnerabilidad lógica en el subsistema criptográfico del kernel Linux que permite a un usuario sin privilegios escribir 4 bytes controlados en el page cache de cualquier archivo legible, incluyendo binarios setuid-root.

## Causa Raíz
`algif_aead.c` realizaba operaciones in-place encadenando el TX SGL con el RX SGL via `sg_chain()`. El algoritmo `authencesn` usa el buffer de destino como scratch space para reorganizar bytes ESN, escribiendo en `dst[assoclen + cryptlen]` — fuera del área legítima de salida. Cuando páginas del page cache son introducidas via `splice()`, esta escritura modifica directamente la caché del kernel.

## Conceptos de Bajo Nivel

### Page Cache
El kernel mantiene una caché en RAM de los contenidos de archivos. `execve()` carga binarios desde esta caché. Si se corrompe, el archivo en disco permanece intacto pero el binario ejecutado en memoria está modificado.

### Bit Setuid
Binarios con el bit setuid (`-rwsr-xr-x`) se ejecutan con los privilegios del propietario (root). Al corromper `/usr/bin/su` en el page cache, el shellcode inyectado corre como UID 0.

### Inodos y Permisos
La escritura via `authencesn` no pasa por el VFS write path, por lo que el inodo no se marca dirty. Herramientas de integridad que comparan checksums en disco no detectan la modificación.

## El Parche
Cambiar `rsgl_src` por `areq->tsgl` en `aead_request_set_crypt()` separa los scatterlists de origen y destino, eliminando la posibilidad de que páginas del page cache queden en el scatterlist de escritura.

## Lección
La optimización in-place de 2017 (commit 72548b093ee3) introdujo el bug al combinar una decisión razonable de performance con un comportamiento no documentado de `authencesn`. Cada cambio era correcto en aislamiento; la vulnerabilidad existe en su intersección.
