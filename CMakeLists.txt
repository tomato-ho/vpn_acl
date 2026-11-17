cmake_minimum_required(VERSION 3.16)

project(vpn_acl VERSION 0.3.4 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(VPN_WITH_DB "Build MariaDB-backed components" ON)
option(VPN_WITH_SPDLOG "Use spdlog for vpn-policyd logging" ON)
option(VPN_WITH_ADMIN "Build the vpn-admin web service" OFF)

find_package(OpenSSL REQUIRED)

set(VPnCORE_SOURCES
    libvpncore/src/accounting.cpp
    libvpncore/src/cidr.cpp
    libvpncore/src/config.cpp
    libvpncore/src/ipc.cpp
    libvpncore/src/nft.cpp
    libvpncore/src/parse.cpp
    libvpncore/src/password.cpp
    libvpncore/src/radius.cpp
    libvpncore/src/retention.cpp
    libvpncore/src/session_marker.cpp
    libvpncore/src/session_recovery.cpp
    libvpncore/src/util.cpp
    libvpncore/src/validation.cpp
)

if(VPN_WITH_DB)
    list(APPEND VPnCORE_SOURCES
        libvpncore/src/db.cpp
        libvpncore/src/db_config.cpp
        libvpncore/src/policy_store.cpp
    )
endif()

if(VPN_WITH_DB)
    find_package(PkgConfig REQUIRED)
endif()

if(VPN_WITH_DB)
    pkg_check_modules(MARIADB QUIET mariadb)
    if(NOT MARIADB_FOUND)
        pkg_check_modules(MARIADB QUIET libmariadb)
    endif()
    if(NOT MARIADB_FOUND)
        message(FATAL_ERROR "MariaDB Connector/C development package was not found")
    endif()
endif()

add_library(vpncore ${VPnCORE_SOURCES})

target_include_directories(vpncore
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/libvpncore/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/third_party
)

if(VPN_WITH_DB)
    target_include_directories(vpncore PUBLIC ${MARIADB_INCLUDE_DIRS})
    target_link_directories(vpncore PUBLIC ${MARIADB_LIBRARY_DIRS})
    target_link_libraries(vpncore PUBLIC ${MARIADB_LIBRARIES})
endif()

target_link_libraries(vpncore PUBLIC OpenSSL::Crypto)

if(VPN_WITH_DB)
    add_library(vpnservice STATIC
        libvpnservice/src/admin_read.cpp
        libvpnservice/src/access_log.cpp
        libvpnservice/src/group_write.cpp
        libvpnservice/src/limits.cpp
        libvpnservice/src/metrics_read.cpp
        libvpnservice/src/openvpn_status.cpp
        libvpnservice/src/service_write.cpp
        libvpnservice/src/session_history.cpp
        libvpnservice/src/settings_write.cpp
        libvpnservice/src/user_write.cpp
    )
    target_include_directories(vpnservice
        PUBLIC
            ${CMAKE_CURRENT_SOURCE_DIR}/libvpnservice/include
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/third_party
    )
    target_link_libraries(vpnservice PUBLIC vpncore)
endif()

if(VPN_WITH_DB)
    add_executable(vpn-policyctl vpn-policyctl/main.cpp)
    target_link_libraries(vpn-policyctl PRIVATE vpncore vpnservice)

    add_executable(vpn-client-connect vpn-client-connect/main.cpp)
    target_link_libraries(vpn-client-connect PRIVATE vpncore)

    add_executable(vpn-client-disconnect vpn-client-disconnect/main.cpp)
    target_link_libraries(vpn-client-disconnect PRIVATE vpncore)

    add_executable(vpn-auth-check vpn-auth-check/main.cpp)
    target_link_libraries(vpn-auth-check PRIVATE vpncore)
endif()

if(VPN_WITH_DB AND VPN_WITH_ADMIN)
    find_package(Threads REQUIRED)

    add_executable(vpn-admin
        vpn-admin/admin_config.cpp
        vpn-admin/auth.cpp
        vpn-admin/db_pool.cpp
        vpn-admin/http_server.cpp
        vpn-admin/main.cpp
        vpn-admin/metrics.cpp
    )
    target_include_directories(vpn-admin
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/third_party
    )
    target_link_libraries(vpn-admin PRIVATE vpnservice vpncore Threads::Threads)
endif()

if(VPN_WITH_DB)
    find_package(Threads REQUIRED)
    if(VPN_WITH_SPDLOG)
        find_package(spdlog REQUIRED)
    endif()

    add_executable(vpn-policyd
        vpn-policyd/accounting_worker.cpp
        vpn-policyd/logging.cpp
        vpn-policyd/main.cpp
        vpn-policyd/nft_batch.cpp
        vpn-policyd/nft_manager.cpp
        vpn-policyd/status.cpp
    )
    target_include_directories(vpn-policyd
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/vpn-policyd
            ${CMAKE_CURRENT_SOURCE_DIR}/third_party
    )
    target_link_libraries(vpn-policyd PRIVATE vpncore Threads::Threads)

    if(VPN_WITH_SPDLOG)
        target_compile_definitions(vpn-policyd PRIVATE VPN_USE_SPDLOG)
        target_link_libraries(vpn-policyd PRIVATE spdlog::spdlog)
    endif()
endif()

enable_testing()
add_executable(vpncore_tests tests/test_core.cpp)
target_link_libraries(vpncore_tests PRIVATE vpncore)
add_test(NAME vpncore_tests COMMAND vpncore_tests)

add_executable(vpn_status_tests
    tests/test_status.cpp
    vpn-policyd/status.cpp
)
target_include_directories(vpn_status_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/vpn-policyd)
target_link_libraries(vpn_status_tests PRIVATE vpncore)
add_test(NAME vpn_status_tests COMMAND vpn_status_tests)

add_executable(vpn_nft_batch_tests
    tests/test_nft_batch.cpp
    vpn-policyd/nft_batch.cpp
)
target_include_directories(vpn_nft_batch_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/vpn-policyd)
target_link_libraries(vpn_nft_batch_tests PRIVATE vpncore)
add_test(NAME vpn_nft_batch_tests COMMAND vpn_nft_batch_tests)

add_executable(vpn_retention_tests tests/test_retention.cpp)
target_link_libraries(vpn_retention_tests PRIVATE vpncore)
add_test(NAME vpn_retention_tests COMMAND vpn_retention_tests)

add_executable(vpn_nft_flow_tests tests/test_nft_flow.cpp)
target_link_libraries(vpn_nft_flow_tests PRIVATE vpncore)
add_test(NAME vpn_nft_flow_tests COMMAND vpn_nft_flow_tests)

add_executable(vpn_session_marker_tests tests/test_session_marker.cpp)
target_link_libraries(vpn_session_marker_tests PRIVATE vpncore)
add_test(NAME vpn_session_marker_tests COMMAND vpn_session_marker_tests)

add_executable(vpn_session_recovery_tests tests/test_session_recovery.cpp)
target_link_libraries(vpn_session_recovery_tests PRIVATE vpncore)
add_test(NAME vpn_session_recovery_tests COMMAND vpn_session_recovery_tests)

add_executable(vpn_radius_tests tests/test_radius.cpp)
target_link_libraries(vpn_radius_tests PRIVATE vpncore)
add_test(NAME vpn_radius_tests COMMAND vpn_radius_tests)

find_package(Threads REQUIRED)
add_executable(vpn_ipc_tests tests/test_ipc.cpp)
target_link_libraries(vpn_ipc_tests PRIVATE vpncore Threads::Threads)
add_test(NAME vpn_ipc_tests COMMAND vpn_ipc_tests)

if(VPN_WITH_DB)
    add_executable(vpn_service_status_tests tests/test_service_status.cpp)
    target_link_libraries(vpn_service_status_tests PRIVATE vpnservice)
    add_test(NAME vpn_service_status_tests COMMAND vpn_service_status_tests)
endif()