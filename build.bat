echo in build
rd /s /Q .\bin\RelWithDebInfo
cmake -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo -G "Visual Studio 17 2022" -A "Win32" -DQT5_PATH=C:\Qt\Qt5.9.7\5.9.7\msvc2015\lib\cmake -DCMAKE_TOOLCHAIN_FILE=D:/vcpkg/scripts/buildsystems/vcpkg.cmake
cmake --build build --config RelWithDebInfo
