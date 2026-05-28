# Reporte Técnico — CVE-2026-31431 "Copy Fail"
**Autor:** Cristopher Quisilema  
**Fecha:** 28 de mayo de 2026

## 1. Bug raíz y ubicación

El bug está en `crypto/algif_aead.c`, función `_aead_recvmsg()`, línea 282.
En 2017 se introdujo una optimización que usaba `areq->tsgl` (TX scatterlist)
como fuente en `aead_request_set_crypt()`, haciendo que `req->src == req->dst`.
Esto significa que el kernel escribe el resultado cifrado sobre las mismas
páginas de memoria que contienen el input, que pueden pertenecer al page cache.

## 2. Por qué el write a dst es peligroso

Cuando `req->src` apunta a páginas del page cache de un archivo setuid (como
`/usr/bin/su`), y `req->dst` es el mismo puntero, la operación criptográfica
escribe directamente en esas páginas en memoria. El resultado: el binario en
memoria queda corrompido/modificado sin tocar el disco. El kernel ejecuta la
versión corrompida en memoria cuando el proceso llama a `execve()`.

## 3. Por qué el exploit es "stealthy"

El exploit no modifica ningún archivo en disco. Solo corrompe el page cache
en RAM. Un `sha256sum /usr/bin/su` desde disco devuelve el hash original.
No hay escrituras en el filesystem, no hay logs de modificación, no hay
alertas de integridad de archivos. El ataque es completamente invisible para
herramientas como `aide`, `tripwire` o `inotifywait`.

## 4. Conexión con conceptos de clase

- **Page cache:** el kernel mantiene en RAM copias de archivos para acelerar
  accesos. Estas páginas son compartidas entre procesos. Escribir en ellas
  afecta a todos los procesos que lean ese archivo.
- **setuid y chmod:** `/usr/bin/su` tiene el bit setuid (`chmod 4755`), lo que
  significa que se ejecuta con los privilegios del dueño (root), no del usuario
  que lo llama. Si su código en memoria es reemplazado, el atacante controla
  código que corre como root.
- **Inodos:** el inodo registra metadatos del archivo en disco, pero el page
  cache es independiente. Modificar el page cache no cambia el inodo ni el
  mtime del archivo.

## 5. Lección aprendida

El bug surgió de combinar tres cambios "razonables":
1. Una optimización de rendimiento (in-place crypto, 2017)
2. El diseño de AF_ALG que expone operaciones crypto al userspace
3. El hecho de que splice() puede apuntar a páginas del page cache

Ninguno de estos cambios es obviamente peligroso por sí solo. La
vulnerabilidad emerge de su interacción. Esto ilustra que la seguridad
del kernel requiere analizar no solo cada cambio individualmente sino
sus interacciones con el resto del sistema.
