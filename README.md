# ctf-notes

Personal study notes from solving public CTF challenges and reverse-engineering exercises.

This repository is a learning log. The write-ups are reconstructed from notes I took while working through publicly available CTF problems — they are intended as a record of my own learning process and as a technical reference I can come back to.

## Disclaimer

Everything documented here concerns challenges from publicly hosted CTF events and training platforms (BUUCTF, SCTF, GUET-CTF, WMCTF, and so on). Every binary or service analyzed has been distributed by the organizers for educational purposes. Nothing in this repository is intended to be applied to real systems, third-party services, or production software, and the techniques described are general reverse-engineering and cryptanalysis methodology that has been publicly documented for years.

## Layout

```
en/   English write-ups
```

I plan to add Chinese versions (`zh/`) later.

## Index

- [WMCTF 2020 — easy_re: unpacking a PerlApp binary](en/01-wmctf2020-easy_re.md)
- [GUET-CTF 2019 — encrypt: RC4 plus a shifted Base64 alphabet](en/02-guetctf2019-encrypt.md)
- [SCTF 2019 — creakme: AES-CBC, Base64, and an SEH self-decrypting section](en/03-sctf2019-creakme.md)

## License

[MIT](LICENSE)
