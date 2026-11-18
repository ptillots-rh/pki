project(acme-dnsjava NONE)

# Keep dependency resolution inside the optional module so default builds
# do not require dnsjava.
# Preserve an explicit/cached DNSJAVA_JAR override. Otherwise prefer the
# packaged Maven artifact over an unrelated JAR with the same filename.
if(NOT DNSJAVA_JAR AND XMVN_RESOLVE)
    execute_process(
        COMMAND ${XMVN_RESOLVE} dnsjava:dnsjava
        OUTPUT_VARIABLE resolved_dnsjava
        OUTPUT_STRIP_TRAILING_WHITESPACE
        RESULT_VARIABLE dnsjava_resolve_status
    )
    if(dnsjava_resolve_status EQUAL 0 AND IS_ABSOLUTE "${resolved_dnsjava}"
            AND EXISTS "${resolved_dnsjava}")
        set(DNSJAVA_JAR "${resolved_dnsjava}" CACHE FILEPATH "dnsjava JAR" FORCE)
    endif()
endif()
if(NOT DNSJAVA_JAR)
    find_file(DNSJAVA_JAR
        NAMES dnsjava.jar
        PATHS /usr/share/java /usr/share/java/dnsjava
    )
endif()
# RPM BuildRequires enforces the minimum version. For manual builds, the
# caller must supply dnsjava 3.7.1 or newer; filename lookup cannot verify it.
if(NOT IS_ABSOLUTE "${DNSJAVA_JAR}" OR NOT EXISTS "${DNSJAVA_JAR}")
    message(FATAL_ERROR "The ACME dnsjava adapter requires dnsjava 3.7.1 or newer; set DNSJAVA_JAR to an absolute JAR path")
endif()

javac(pki-acme-dnsjava-classes
    SOURCES src/main/java/*.java
    CLASSPATH ${PKI_ACME_JAR} ${DNSJAVA_JAR} ${SLF4J_API_JAR}
    OUTPUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/classes
    DEPENDS pki-acme-jar
)
add_dependencies(java pki-acme-dnsjava-classes)

set(PKI_ACME_DNSJAVA_JAR ${CMAKE_BINARY_DIR}/dist/pki-acme-dnsjava.jar
    CACHE INTERNAL "pki-acme-dnsjava.jar"
)
jar(pki-acme-dnsjava-jar
    CREATE ${PKI_ACME_DNSJAVA_JAR}
    INPUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/classes
    DEPENDS pki-acme-dnsjava-classes
)
add_dependencies(java pki-acme-dnsjava-jar)

add_custom_target(pki-acme-dnsjava-links ALL
    COMMENT "Creating links for the optional ACME DNS adapter")
add_custom_command(
    TARGET pki-acme-dnsjava-links POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory webapp/lib
    COMMAND ln -sf ../../../../../../../..${JAVA_JAR_INSTALL_DIR}/pki/pki-acme-dnsjava.jar webapp/lib/pki-acme-dnsjava.jar
    COMMAND ln -sf ../../../../../../../..${DNSJAVA_JAR} webapp/lib/dnsjava.jar
)

if(WITH_JAVA)
    install(FILES ${PKI_ACME_DNSJAVA_JAR} DESTINATION ${JAVA_JAR_INSTALL_DIR}/pki)
endif()
install(
    DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/
    DESTINATION ${DATA_INSTALL_DIR}/acme/webapps/acme/WEB-INF/lib
)
