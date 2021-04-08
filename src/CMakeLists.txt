find_package(Sodium)

file(GLOB_RECURSE SRCS *.cpp)

add_executable(WVOPRF ${SRCS})

target_include_directories(WVOPRF PUBLIC "${PROJECT_BINARY_DIR}")
target_include_directories(WVOPRF PUBLIC ${SODIUM_INCLUDE_DIR})
target_link_libraries(WVOPRF ${sodium_LIBRARIES})