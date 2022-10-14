cmake_minimum_required(VERSION 3.0.2)

project("xorcbc")
add_library(${PROJECT_NAME} SHARED
    "src/xorcbc.c"
)

project("xorcbc-test")
add_executable(${PROJECT_NAME}
    "src/test/main.c"
)
target_include_directories(${PROJECT_NAME} PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
)
target_link_libraries(${PROJECT_NAME}
    "xorcbc"
)
