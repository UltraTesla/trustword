cmake_minimum_required(VERSION 3.10)
project(trustword VERSION "1.1.0")
include(GNUInstallDirs)
# Los prefijos usado por las variables predeterminadas
set(prefix ${CMAKE_INSTALL_PREFIX})
set(WORKSPACE $ENV{HOME}/.trustword)
set(WORKSPACE_GLOB ${prefix}/${CMAKE_INSTALL_SYSCONFDIR}/trustword)
# Las variables de configuración
set(CONFIG_FILE ${WORKSPACE_GLOB}/${PROJECT_NAME}.sc)
set(DEFAULT_DATABASE ${WORKSPACE}/${PROJECT_NAME}.db)
set(DEFAULT_USER $ENV{USER})
set(DEFAULT_SQL_FILE ${WORKSPACE_GLOB}/${PROJECT_NAME}.sql)
set(DEFAULT_MAX_SQL_SIZE 1024)
set(DEFAULT_BLOCK_SIZE 65535)
# Las variables de configuración de Argon2
set(DEFAULT_ARGON2_HASHLEN 16)
set(DEFAULT_ARGON2_SALTLEN 16)
set(DEFAULT_ARGON2_T_COST 2)
set(DEFAULT_ARGON2_M_COST 102400)
set(DEFAULT_ARGON2_PARALLELISM 8)
set(DEFAULT_ARGON2_ENCODED_LEN 128)
# Los archivos que le proveen información a trustword, y,
# lo configuran.
configure_file(config.h.in ${PROJECT_SOURCE_DIR}/config.h)
# Agregamos el proyecto
set(
	SRC_LIST 
	main.c box.c trim.c sp_parser.c  read_all.c
	version.c hash.c strupper.c argon2_custom.c
	multiple_free.c

)
add_executable(${PROJECT_NAME} ${SRC_LIST} config/trustword.sc config/trustword.sql)
target_compile_options(${PROJECT_NAME} PUBLIC -Wno-discarded-qualifiers -pipe -O2 -ggdb)

# Hacemos una búsqueda
find_library(LibArgon2  argon2  REQUIRED)
find_library(LibSQLite3 sqlite3 REQUIRED)
find_library(LibSodium  sodium  REQUIRED)
find_package(OpenSSL            REQUIRED)

# Las librerías requeridas
target_link_libraries(${PROJECT_NAME} OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(${PROJECT_NAME} sqlite3)
target_link_libraries(${PROJECT_NAME} argon2)
target_link_libraries(${PROJECT_NAME} sodium)

# Instalamos el proyecto
install(
	TARGETS ${PROJECT_NAME}
	DESTINATION ${prefix}/${CMAKE_INSTALL_BINDIR}
	COMPONENT binaries

)
# Ahora los archivos necesarios para iniciar el programa
install(FILES config/trustword.sc  DESTINATION ${WORKSPACE_GLOB} COMPONENT config)
install(FILES config/trustword.sql DESTINATION ${WORKSPACE_GLOB} COMPONENT config)
install(
        DIRECTORY DESTINATION ${WORKSPACE}
        DIRECTORY_PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE
                              GROUP_READ GROUP_EXECUTE
                              WORLD_READ WORLD_EXECUTE
)
