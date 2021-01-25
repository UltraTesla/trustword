# Historial de cambios

## version 1.1.0 (2021-01-25)

### Agregado

* Parámetro '--hash' obligatorio para poder verificar las claves a importar
* Integración con cmake
* El parser para leer la configuración dinámicamente ahora tiene la posibilidad de interpretar variables de entorno

### Arreglado

* La huella dictilar de una clave se mostraba incompleta
* La clave pública y la clave de verificación tenían la misma longitud lo cual podía causar importaciones erradas sin consentimiento del usuario
* Si el archivo de configuración no existía, se paraba la ejecución
* En caso de detectar que no se ha definido una variable en el archivo de configuación, se ajustaba, pero si había otra más, no lo hacía y podía generar un fallo de ejecución
* Cuando el tamaño del bloque de datos es menor o igual a cero el programa leía infinitamente

### Seguridad

* Era posible modificar el nombre de usuario sin verificar antes si la clave había cambiado
* No era obligatorio ver la huella dactilar de la clave a importar
