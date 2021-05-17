Welcome to the CryptCpp Library
===============================
CryptCpp is a C++ Cryptographic interface library that decouples application code from specific cryptographic library calls.

Overview
========
The CryptCpp library consists of of the following layers:

- **An interface layer**
This includes a set of header files present inside the **include/cryptcpp** dierctory. An application code only needs to use the interfaces declared by these header files without bothering about wchich cryptographic library is actually used to implement them.

- **An implementation layer**
This layer provides the actual implementation of the interfaces. The application code does not need to know about any source files or headers from this layer. The source code for an implementation using a cryptographic library, say 'x', can be found in the directory **src/impl/x** and its headers at **include/cryptcpp/impl/x**. Currently, the only implementation provided is through the OpenSSL crypto library. However, it should be easy to provide implementations using other libraries without changing the application code.

- **The factory**
The library is designed to support multiple different implementations using different cryptographic libraries. To ensure an application consistently uses implementations by a particular library, an abstract factory interface is provided.


Functionalities
===============
  - Encoding and decoding with Base-64 and Hex codecs
  - Message digest calculation
  - Digital signatures
  - Symmetric key encryption and decryption
  - Asymmetric key encryption and decryption

Compilation
===========
The library has been compiled and tested with GNU C++ and LLVM clang++ compilers on Linux. The implementation layer through OpenSSL depends on the OpenSSL headers to be present on include path and an application linking to this library also needs to link to -lcrypto and -lssl. 
Type "make" from the **src** directory to compile.
