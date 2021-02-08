#include <stdio.h>
#include "config.h"

void show_error() {
	puts("Pruebe 'trustword --help' para más información.");

}

void show_version(void) {
	printf("%s-%s (Parte del proyecto Ultra Tesla) - DtxdF\n", PROJECT_NAME, PROJECT_VER);

}

void show_examples(void) {
	puts("     Administración de usuarios:");
	puts("         *- Crear un usuario         : ./trustword -g --user [Nombre de usuario] --pasword [Contraseña]");
	puts("         *- Eliminar un usuario      : ./trustword --delete --user [Nombre de usuario]");
	puts("         *- Actualizar la contraseña : ./trustword -E --user [Nombre de usuario] | ./trustword -I - --hash [Huella dactilar] -p [Contraseña] -N [Nueva contraseña] --overwrite");
	puts("     Importación/Exportación de claves:");
	puts("         *- Exportar una clave pública                : ./trustword -e --user [Nombre de usuario]");
	puts("         *- Importar una clave pública (sin registro) : ./trustword -i [Ruta de la clave] --hash [Huella dactilar]");
	puts("         *- Importar una clave pública (con registro) : ./trustword -i [Ruta de la clave] --password [Contraseña] --hash [Huella dactilar]");
	puts("         *- Exportar una clave secreta                : ./trustword -E --user [Nombre de usuario]");
	puts("         *- Exportar una clave de verificación        : ./trustword -z --user [Nombre de usuario]");
	puts("         *- Exportar una clave para firmar            : ./trustword -Z --user [Nombre de usuario]");
	puts("");
	puts("         Notas:");
	puts("             *- Nota #1: En el caso de querer importar una clave de verificación con registro, se debe ");
	puts("                         hacer el mismo procedimiento que en la importación de la clave pública; cosa ");
	puts("                         inválida para la importación de alguna clave privada (secreta o para firmar).");
	puts("             *- Nota #2: En caso de querer importar una clave privada sin antes haber importando el par ");
	puts("                         público, ocasionará un error. Y si se agregó una clave pública sin registro, ");
	puts("                         entonces obtendrá un error.");
	puts("");
	puts("     Cifrar/Descifrar:");
	puts("         *- Cifrar simétricamente             : ./trustword -k [Nombre del archivo a cifrar] --password [Contraseña]");
	puts("         *- Descifrar simétricamente          : ./trustword -K [Nombre del archivo a descifrar] --password [Contraseña]");
	puts("         *- Cifrar usando el par de claves    : ./trustword -C [Nombre del archivo a cifrar] --from [Nombre de usuario - origen] --to [Nombre de usuario - destino] --password [Contraseña de la clave secreta del usuario de origen]");
	puts("         *- Descifrar usando el par de claves : ./trustword -D [Nombre del archivo a descifrar --from [Nombre de usuario - origen] --to [Nombre de usuario - destino] --password [Contraseña de la clave secreta del usuario de destino]");
	puts("");
	puts("     Firmar/Verificar:");
	puts("         *- Firmar    : ./trustword -s [Nombre del archivo a firmar] --user [Nombre de usuario] --password [Contraseña del usuario de la clave para firmar]");
	puts("         *- Verificar : ./trustword -v [Nombre del archivo original] -V [Nombre del archivo de la firma] --user [Nombre de usuario de la clave de verificación]");
	puts("");
	puts("     Listar los usuarios:");
	puts("         *- Listar todos los usuarios      : ./trustword --list");
	puts("         *- Listar a un usuario específico : ./trustword --list --user [Nombre de usuario]");

}

void show_help(void) {
	show_version();

	puts("Modo de empleo: trustword [OPCIONES]");
	puts("        o bien: trustword --help");
	puts("");
	puts("Facilita la comunicación y la compartición de datos de forma confiable y segura, creando una");
	puts("infraestructura para la administración de las claves para la firma y para el cifrado tanto");
	puts("simétrico y de clave pública.");
	puts("");
	puts("Algunas operaciones que requieren archivos pueden leer la entrada estándar si se usa '-'.");
	puts("");
	puts("Operaciones como la importación o exportación se comportan ligeramente diferente cuando la opción ");
	puts("'-h' está presente, indicando que lo que se leerá está en hexadecimal y se deberá descodificar.");
	puts("");
	puts("Si el parámetro '--from' o '--user' no se definen, se usará el usuario por defecto del archivo de ");
	puts("configuración.");
	puts("");
	puts("     Resumen de los comandos:");
	puts("         -t, --to USUARIO                   el nombre de usuario del destinatario");
	puts("         -f, --from USUARIO                 el nombre de usuario del remitente");
	puts("         -c, --configuration FICHERO        usar un archivo de configuración arbitrario");
	puts("         -g, --generate-keypair             generar el par de claves");
	puts("         -d, --delete                       borrar el usuario");
	puts("         -o, --output FICHERO               redirigir la salida de algunas operaciones ");
	puts("                                            hacia un fichero");
	puts("         -e, --export                       exportar una clave pública");
	puts("         -E, --export-secret-key            exportar una clave secreta");
	puts("         -z, --export-verify-key            exportar la clave de verificación");
	puts("         -Z, --export-sign-key              exportar la clave para la firmar");
	puts("         -i, --import FICHERO               importar una clave pública");
	puts("         -I, --import-secret-key FICHERO    importar una clave secreta");
	puts("         -u, --import-verify-key FICHERO    importar una clave de verificación");
	puts("         -U, --import-sign-key FICHERO      importar una clave para firmar");
	puts("             --user USUARIO                 lo mismo que '--from'");
	puts("         -l, --list                         listar la lista de claves junto con sus identificadores");
	puts("         -s, --sign FICHERO                 firmar el archivo de destino");
	puts("         -C, --encrypt FICHERO              cifrar el archivo de destino");
	puts("         -D, --decrypt FICHERO              descifrar el archivo de destino");
	puts("         -v, --verify FICHERO               verificar el contenido firmado");
	puts("         -V, --to-verify FICHERO            la firma a verificar");
	puts("         -k, --symmetric FICHERO            usar el cifrado simétrico para cifrar un archivo");
	puts("         -K, --symmetric-decrypt FICHERO    usar el cifrado simétrico para descifrar un archivo");
	puts("         -p, --password CONTRASEÑA          la contraseña usada por algunas operaciones");
	puts("         -N, --new-password CONTRASEÑA      la nueva contraseña, en caso de cambiarla");
	puts("         -h, --human                        muestra, en hexadecimal, los resultados de algunas operaciones");
	puts("             --hash                         la suma de comprobación de la clave");
	puts("             --examples                     muestra algunos ejemplos para empezar con el pie derecho");
	puts("             --overwrite                    sobrescribe una clave de un usuario existente");
	puts("             --version                      informe sobre la versión");
	puts("             --help                         mostrar este mensaje");

}
