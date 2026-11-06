project(acme-libunbound C)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBUNBOUND REQUIRED IMPORTED_TARGET libunbound)
add_library(pki_acme_unbound SHARED src/main/native/libunbound_jni.c)
add_dependencies(java pki_acme_unbound)
target_include_directories(pki_acme_unbound PRIVATE ${JNI_INCLUDE_DIRS})
target_link_libraries(pki_acme_unbound PRIVATE PkgConfig::LIBUNBOUND)
target_compile_features(pki_acme_unbound PRIVATE c_std_11)
target_compile_options(pki_acme_unbound PRIVATE -Wall -Wextra -Werror)
install(TARGETS pki_acme_unbound LIBRARY DESTINATION ${LIB_INSTALL_DIR})

javac(pki-acme-libunbound-classes
    SOURCES src/main/java/*.java
    CLASSPATH ${PKI_ACME_JAR}
    OUTPUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/classes
    DEPENDS pki-acme-jar
)
add_dependencies(java pki-acme-libunbound-classes)

set(PKI_ACME_LIBUNBOUND_JAR ${CMAKE_BINARY_DIR}/dist/pki-acme-libunbound.jar
    CACHE INTERNAL "pki-acme-libunbound.jar"
)
jar(pki-acme-libunbound-jar
    CREATE ${PKI_ACME_LIBUNBOUND_JAR}
    INPUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/classes
    DEPENDS pki-acme-libunbound-classes
)
add_dependencies(java pki-acme-libunbound-jar)

add_custom_target(pki-acme-libunbound-links ALL
    COMMENT "Creating links for the optional ACME DNS adapter")
add_custom_command(
    TARGET pki-acme-libunbound-links POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory webapp/lib
    COMMAND ln -sf ../../../../../../../..${JAVA_JAR_INSTALL_DIR}/pki/pki-acme-libunbound.jar webapp/lib/pki-acme-libunbound.jar
)

if(WITH_JAVA)
    install(FILES ${PKI_ACME_LIBUNBOUND_JAR} DESTINATION ${JAVA_JAR_INSTALL_DIR}/pki)
endif()
install(
    DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/
    DESTINATION ${DATA_INSTALL_DIR}/acme/webapps/acme/WEB-INF/lib
)
