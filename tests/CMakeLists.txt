cmake_minimum_required(VERSION 3.28)

# Helper function to register Unity test targets and wire them into CTest
function(add_urtp_test test_target_name)
    add_executable(${test_target_name} ${ARGN})
    target_link_libraries(${test_target_name}
        PRIVATE
            urtp_control
            urtp_net
            urtp_media
            urtp_ring
            urtp_crypto
            urtp_core
            PkgConfig::LIBURING
            unity::framework
    )
    add_test(NAME ${test_target_name} COMMAND ${test_target_name})
endfunction()

add_urtp_test(test_string_view test_string_view.c)
add_urtp_test(test_hash test_hash.c)
add_urtp_test(test_memory test_memory.c)
add_urtp_test(test_ring test_ring.c)
add_urtp_test(test_net test_net.c)
add_urtp_test(test_control test_control.c)
add_urtp_test(test_bencode test_bencode.c)
add_urtp_test(test_sdp test_sdp.c)
add_urtp_test(test_ng test_ng.c)
add_urtp_test(test_base64 test_base64.c)
add_urtp_test(test_sdes test_sdes.c)
add_urtp_test(test_srtp test_srtp.c)
add_urtp_test(test_stun test_stun.c)
add_urtp_test(test_dtls test_dtls.c)
add_urtp_test(test_pcap test_pcap.c ../src/server.c)
add_urtp_test(test_transcode test_transcode.c ../src/server.c)
add_urtp_test(test_server test_server.c ../src/server.c)
add_urtp_test(test_bg_tasks test_bg_tasks.c ../src/server.c)
add_urtp_test(test_jitter test_jitter.c)
add_urtp_test(test_log test_log.c)


