@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
"C:\Program Files\LLVM\bin\clang-tidy.exe" -p build-release src\model.cpp src\address.cpp src\analysis.cpp src\format.cpp src\cli.cpp src\acquire.cpp src\adapters.cpp src\dns_servers.cpp src\suffix.cpp src\registration.cpp src\main.cpp tests\tests.cpp tests\nonadmin.cpp tests\nonadmin_launch.cpp --checks=-*,clang-analyzer-*,bugprone-*,performance-* --warnings-as-errors=* > artifacts\clang-tidy.txt 2>&1
exit /b %errorlevel%


