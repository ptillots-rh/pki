# Select optional adapters independently; default builds resolve no DNS toolkit.
if(WITH_ACME_DNSJAVA)
    add_subdirectory(dnsjava)
endif()
if(WITH_ACME_LIBUNBOUND)
    add_subdirectory(libunbound)
endif()
