@echo off
set IDF_PATH=C:\Espressif\frameworks\esp-idf-v5.3.1
set IDF_TOOLS_PATH=C:\Espressif
call "C:\Espressif\frameworks\esp-idf-v5.3.1\export.bat"
cd /d "C:\Users\hp\Desktop\WP3"
"C:\Espressif\python_env\idf5.3_py3.11_env\Scripts\python.exe" "C:\Espressif\frameworks\esp-idf-v5.3.1\tools\idf.py" build
