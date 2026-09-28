# One executable per subject area, so a failure names the area it broke.

add_executable(mira_core_tests test_core.cpp)
add_executable(mira_event_loop_tests test_event_loop.cpp)

add_executable(mira_task_scope_tests test_task_scope.cpp)
add_executable(mira_runtime_tests test_runtime.cpp)
target_link_libraries(mira_runtime_tests PRIVATE Mira::core Mira::warnings)
target_include_directories(mira_runtime_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
add_test(NAME runtime COMMAND mira_runtime_tests)
set_tests_properties(runtime PROPERTIES TIMEOUT 60)

foreach(target mira_core_tests mira_event_loop_tests mira_task_scope_tests)
    target_link_libraries(${target} PRIVATE
        Mira::core
        Mira::warnings
    )
    target_include_directories(${target} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
endforeach()

add_test(NAME core COMMAND mira_core_tests)
add_test(NAME event_loop COMMAND mira_event_loop_tests)
add_test(NAME task_scope COMMAND mira_task_scope_tests)
set_tests_properties(task_scope PROPERTIES TIMEOUT 60)

# Contract violations must terminate, and only a separate process can assert
# that. `check_terminates.cmake` demands the exact exit code the binary's
# terminate handler installs, so an ordinary crash does not pass as fail-fast.
function(mira_add_terminate_tests prefix target)
    foreach(mode ${ARGN})
        add_test(NAME ${prefix}_${mode} COMMAND ${CMAKE_COMMAND}
            -DPROGRAM=$<TARGET_FILE:${target}> -DMODE=${mode}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/check_terminates.cmake)
        set_tests_properties(${prefix}_${mode} PROPERTIES TIMEOUT 15)
    endforeach()
endfunction()

mira_add_terminate_tests(runtime mira_runtime_tests self-destruction)

mira_add_terminate_tests(task_scope mira_task_scope_tests
    pending-destruction unobserved-failure abandoned-join unstarted-join)

mira_add_terminate_tests(task_contract mira_core_tests
    sync-get-suspended abandoned-awaiter)

mira_add_terminate_tests(event_loop mira_event_loop_tests
    destroy-during-dispatch reentrant-run-once root-task-deadlock)

# POSIX-only: detach synchronously resumes readiness waiters; IOCP
# cancellation drains through completions instead.
if(NOT WIN32)
    mira_add_terminate_tests(event_loop mira_event_loop_tests
        destroy-during-detach reentrant-run-once-during-detach)
endif()

# An event-loop bug tends to hang rather than fail. A timeout turns that into
# a red test instead of a stuck CI job.
set_tests_properties(event_loop PROPERTIES TIMEOUT 60)

add_executable(mira_timer_allocation_tests test_timer_allocation.cpp)
target_link_libraries(mira_timer_allocation_tests PRIVATE Mira::core Mira::warnings)
add_test(NAME timer_allocation COMMAND mira_timer_allocation_tests)
set_tests_properties(timer_allocation PROPERTIES TIMEOUT 30)
