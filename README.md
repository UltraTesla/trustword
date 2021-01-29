## trustword
**Trustword** es un programa muy simple para la firma, el cifrado y el mantenimiento de claves para facilitar y fortalecer una comunicación segura. Usa internamente (gracias a [libsodium](https://github.com/jedisct1/libsodium)) para el cifrado XSalsa20, y en el caso de la criptografía asimétrica, se complementa con el intercambio de claves X25519. Y para la firma digital Ed25519ph con SHA512.

## Dependencias
* gcc (recomendado) o clang (no probado)
* cmake
* openssl
* libsodium
* argon2
* sqlite3

## Instalación

```bash
git clone https://github.com/UltraTesla/trustword.git
cd trustword
chmod +x dependences.sh
sudo ./dependences.sh
sudo chown <Tu nombre de usuario>:<Tu grupo> ~/.trustword
trustword --help
```

## Ejemplos
**Nota**: *También se puede ejecutar para ver los ejemplos en pantalla*:

```bash
./trustword --examples
```

### Administración de usuarios:
**Crear un usuario**:
```bash
./trustword -g --user [Nombre de usuario] --pasword [Contraseña]
```

**Eliminar un usuario**:
```bash
./trustword --delete --user [Nombre de usuario]
```

### Importación/exportación de claves:
**Exportar una clave pública**:
```bash
./trustword -e --user [Nombre de usuario]
```

**Importar una clave pública (sin registro)**:
```bash
./trustword -i [Ruta de la clave] --hash [Huella dactilar]
```

**Importar una clave pública (con registro)**:
```bash
./trustword -i [Ruta de la clave] --password [Contraseña] --hash [Huella dactilar]
```

**Exportar una clave secreta**:
```bash
./trustword -E --user [Nombre de usuario]
```

**Exportar una clave de verificación**:
```bash
./trustword -z --user [Nombre de usuario]
```

**Exportar una clave para firmar**:
```bash
./trustword -Z --user [Nombre de usuario]
```

**Notas**:

* En el caso de querer importar una clave de verificación con registro, se debe hacer el mismo procedimiento que en la importación de la clave pública; cosa inválida para la importación de alguna clave privada (secreta o para firmar).
* En caso de querer importar una clave privada sin antes haber importando el par público, ocasionará un error. Y si se agregó una clave pública sin registro, entonces obtendrá un error.

### Cifrar/Descifrar
**Cifrar simétricamente**:
```bash
./trustword -k [Nombre del archivo a cifrar] --password [Contraseña]
```

**Descifrar simétricamente**:
```bash
./trustword -K [Nombre del archivo a descifrar] --password [Contraseña]
```

**Cifrar usando el par de claves**:
```bash
./trustword -C [Nombre del archivo a cifrar] --from [Nombre de usuario - origen] --to [Nombre de usuario - destino] --password [Contraseña de la clave secreta del usuario de origen]
```

**Descifrar usando el par de claves**:
```bash
./trustword -D [Nombre del archivo a descifrar --from [Nombre de usuario - origen] --to [Nombre de usuario - destino] --password [Contraseña de la clave secreta del usuario de destino]
```

### Firmar/Verificar
**Firmar**:
```bash
./trustword -s [Nombre del archivo a firmar] --user [Nombre de usuario] --password [Contraseña del usuario de la clave para firmar]
```

**Verificar**:
```bash
./trustword -v [Nombre del archivo original] -V [Nombre del archivo de la firma] --user [Nombre de usuario de la clave de verificación]
```

### Listar los usuarios
**Listar todos los usuarios**:
```bash
./trustword --list
```

**Listar a un usuario específico**:
```bash
./trustword --list --user [Nombre de usuario]
```

~ DtxdF
