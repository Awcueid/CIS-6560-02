@echo off

:: ============================================================================
:: [USER CONFIGURATION] 
:: @CB: Please change the path below to match the project folder on your computer.
:: ============================================================================

cd /d "C:\Users\Costantinos\Desktop\CIS 6560 02 PROJECT"  

".venv\Scripts\python.exe" -m streamlit run app.py
pause