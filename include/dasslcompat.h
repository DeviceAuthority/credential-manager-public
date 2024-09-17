#ifndef __DASSLCOMPAT_H__
#define __DASSLCOMPAT_H__

// BIO_s_file and BIO_s_file_internal
// in 0.9.8 #define BIO_s_file          BIO_s_file_internal, uses both
// in 1.0.0 #define BIO_s_file_internal BIO_s_file, uses both
// in 1.0.1 #define BIO_s_file_internal BIO_s_file, uses both
// in 1.0.1 #define BIO_s_file_internal BIO_s_file, uses both
// in 1.1 no BIO_s_file_internal
#if (OPENSSL_VERSION_NUMBER >= 0x1010007fL)
#define BIO_s_file_internal BIO_s_file
#define SSL_CTX_default_passwd_callback(c) SSL_CTX_get_default_passwd_cb(c)
#define SSL_CTX_default_passwd_callback_userdata(c) SSL_CTX_get_default_passwd_cb_userdata(c)
#define BIO_num_write(b) BIO_number_written(b)
#else
#define SSL_CTX_default_passwd_callback(c) c->default_passwd_callback
#define SSL_CTX_default_passwd_callback_userdata(c) c->default_passwd_callback_userdata
#define BIO_num_write(b) b->num_write
#endif // #if (OPENSSL_VERSION_NUMBER >= 0x1010007fL)

#endif // #ifndef __DASSLCOMPAT_H__
