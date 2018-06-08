int	 oath(unsigned char *, size_t keylen, uint64_t, uint8_t, uint16_t);
int	 oath_totp(unsigned char *, size_t, time_t, time_t, uint8_t, uint16_t);
int	 oath_hotp(unsigned char *, size_t, uint64_t, uint8_t);
size_t	 oath_decode_key(char *, unsigned char *, size_t);
int	 oath_generate_key(size_t);
