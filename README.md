# File Packing System (Public Domain)

The **DMOD** file format facilitates flexible multi-file packing, featuring integrated compression, standard encryption, cryptographic signatures, and cryptographic checksum validation.

DMOD shares similarities with other packaging formats like TAR (GNU) and ZIP, but it stands out due to its lack of licensing restrictions on the format itself and its implementations.

## Development Status and Documentation

**DMOD** is undergoing active development and does not yet adhere to standardized specifications. As a result of its dynamic evolution, comprehensive documentation has not been provided, given that the format's specifics have been continuously tailored to fulfill diverse requirements across various projects.

## Security Considerations

A component of note within the **DMOD** system is the code located in the `pwcrack` directory. This particular code is dedicated to performing calculations on preimages related to the DMOD password checksum. It's important to emphasize that these actions do not compromise the security of the password hashing mechanism.

The underlying philosophy behind the approach involves utilizing a unique methodology for achieving *secure hashing*, instead of opting for computationally intensive operations that would inherently slow down computations, a distinctive strategy has been adopted. This strategy employs a relatively compact checksum, composed of only 24 bits. This small checksum's primary function is to serve as a preliminary validation of the password. However, by design, due to its limited size, it possesses a significantly high probability of encountering hash collisions.

For the security of the **DMOD** system, it's crucial to note that utilizing a cipher, specifically AES-256-CTR, introduces an additional layer of protection. Even if a valid checksum is obtained, it will not decrease the security of the encryption strength or the complexity of brute forcing the key. The actual encryption key is the second SHA2-256 hash of the password.

In summary, the 24-bit checksum's role is to provide an initial validation of a password prior to decryption, thus expediting the process. If the checksum validation is successful, the complete 256-bit SHA-256 hash is employed alongside the AES-256-CTR stream cipher to facilitate the decryption of the archive contents. It's worth highlighting that the 24-bit checksum is inherently unsuitable for password brute force attacks due to its susceptibility to collision attacks.

Please be aware that due to the evolving nature of the **DMOD** format, these details are subject to change as the system matures and undergoes further development.

If this is confusing, read the code in source/dmod.cpp, `dmod_verify_key` and `dmod_hash`.
