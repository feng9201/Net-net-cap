CMAKE_MINIMUM_REQUIRED(VERSION 3.8.0)
project(netCap LANGUAGES CXX)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

#msvc 添加管理员权限运行
if(MSVC)
#add_compile_options("$<$<C_COMPILER_ID:MSVC>:/utf-8>")
#add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/utf-8>")
SET( CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /level='requireAdministrator' /uiAccess='false' /SUBSYSTEM:WINDOWS /ENTRY:mainCRTStartup" )
endif()

find_package(unofficial-pcapplusplus CONFIG REQUIRED)

#Qt 设置
if(QT5_PATH)
message(${QT5_PATH})
else()
set(QT5_PATH "C:/Qt/Qt5.9.7/5.9.7/msvc2015/lib/cmake")
endif()
set(CMAKE_PREFIX_PATH ${QT5_PATH})
find_package(Qt5 COMPONENTS
        Core
        Gui
        Widgets
        REQUIRED)


#Qt自动moc rcc uic
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

#获取所有cpp文件
file(GLOB_RECURSE CPPSRC_DIR_LIST "*.cpp" )
#获取所有头文件
file(GLOB_RECURSE HEADERSRC_DIR_LIST "*.h" )
#获取所有UI文件
file(GLOB_RECURSE UISRC_DIR_LIST "*.ui" )
#获取所有qrc文件
file(GLOB_RECURSE QRCSRC_DIR_LIST "*.qrc" )

set(AllFile ${HEADERSRC_DIR_LIST} ${CPPSRC_DIR_LIST})
foreach(fileItem ${AllFile})       
    get_filename_component(PARENT_DIR "${fileItem}" DIRECTORY)
    string(REPLACE "${CMAKE_CURRENT_SOURCE_DIR}" "" GROUP "${PARENT_DIR}")
    # Make sure we are using windows slashes
    string(REPLACE "/" "\\" GROUP "${GROUP}")
    # Group into "Source Files" and "Header Files"
    set(GROUP "${GROUP}")
    source_group("${GROUP}" FILES "${fileItem}")
endforeach()

#设置自动生成UI文件夹
source_group("Ui" FILES ${UISRC_DIR_LIST} ${WRAP_FILES})
# 设置资源目录
set(RESOURCES_DIR ${CMAKE_CURRENT_SOURCE_DIR}/images)

set(WINRC_DIR_LIST "")
if(MSVC)
file(GLOB_RECURSE WINRC_DIR_LIST "*.rc")
endif()

#设置包含主目录
set(CMAKE_INCLUDE_CURRENT_DIR ON)
#生成exe
add_executable(${PROJECT_NAME} ${CPPSRC_DIR_LIST} ${QRCSRC_DIR_LIST} ${UISRC_DIR_LIST} ${WINRC_DIR_LIST} ${CCSRC_DIR_LIST})
#包含项目头文件
target_include_directories(${PROJECT_NAME} PRIVATE ${HEADERSRC_DIR_LIST})

target_link_libraries(${PROJECT_NAME}
	Qt5::Core
    Qt5::Gui
    Qt5::Widgets
    unofficial::pcapplusplus::pcappp 
	unofficial::pcapplusplus::commonpp 
	unofficial::pcapplusplus::packetpp
	) 
	



