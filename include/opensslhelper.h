#ifndef OPENSSLHELPER_H
#define OPENSSLHELPER_H

#ifdef __cplusplus

bool openssl_load_provider(const std::string &provider);

extern "C" {
#endif // #ifdef __cplusplus

void openssl_init_locks(void);
void openssl_kill_locks(void);
void openssl_cleanup(void);


#ifdef __cplusplus
}
#endif // #ifdef __cplusplus

#endif // #ifndef OPENSSLHELPER_H
