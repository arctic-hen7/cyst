# Cyst

This is a simple, work-in-progress CLI that allows encrypting and decrypting files using multiple encryption methods and factors. For example, you could define that you want to be able to decrypt a file using either a passphrase or a keyfile. Or you could define that you want to be able to decrypt a file using either a passphrase *and* a keyfile, or a different, larger keyfile. This combination of "OR"s and "AND"s makes for practically limitless expressiveness in how you encrypt.

Right now, the core system is working and I'm in the process of adding additional factor types.

## License

See [`LICENSE`](./LICENSE).
