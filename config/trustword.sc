;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;                                       ;;
;; Archivo de configuración de trustword ;;
;;                                       ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; database     : Es el nombre de la base de datos SQLite.
;                Recuerde que si no existe, se creará.
;
; default_user : Es el nombre del usuario predeterminado,
;                invocado implícitamente cuando no se
;                ajusta usando el parámetro '--from' o
;                '--user'.
;
; sql_file     : El archivo SQL inicial que es invocado,
;                para crear las tablas principales, y
;                entre otras cosas.
;
; block_size   : El tamaño del bloque a usar en la lectura
;                de un flujo de archivos en algunas operaciones
;                como lo son, el cifrado, descifrar, la firma y
;                la lectura/escritura de datos general.
;

database       :  files/trustword.db
default_user   :  default
sql_file       :  config/trustword.sql
block_size     :  65536
