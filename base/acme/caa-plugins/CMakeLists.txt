# The DNS library is resolved only when the optional adapter is selected.
if(WITH_ACME_DNSJAVA)
    add_subdirectory(dnsjava)
endif()
